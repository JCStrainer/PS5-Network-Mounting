#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <pthread.h>
#include <cstdio>
#include <map>

#include "json.hpp"
#include "mount_backend.hpp"
#include "web_assets.hpp"

extern "C" {
int sceNetInit(void);
int sceNetPoolCreate(const char* name, int size, int flags);
int sceNetPoolDestroy(int pool_id);

struct NotifyRequest {
    char reserved[45];
    char message[3075];
};
int sceKernelSendNotificationRequest(int, NotifyRequest*, unsigned long, int) __attribute__((weak));
int sceNotificationSend(int user_id, bool is_logged_in, const char* payload) __attribute__((weak));
int sceSystemServiceLaunchWebBrowser(const char* uri, void* reserved) __attribute__((weak));
int sceUserServiceInitialize(void*) __attribute__((weak));
int sceUserServiceTerminate(void) __attribute__((weak));
}

namespace {

#ifdef SYS_sendsyslog
#define PS5_SYS_SENDSYSLOG SYS_sendsyslog
#else
#define PS5_SYS_SENDSYSLOG 0x259
#endif

void LogKlog(const std::string &line) {
    std::string trimmed = line.size() > 400 ? line.substr(0, 400) + "..." : line;
    std::string msg = "<118>[PS5NM] " + trimmed + "\n";
#if defined(__FreeBSD__) || defined(__ORBIS__) || defined(_ORBIS_)
    (void)syscall(PS5_SYS_SENDSYSLOG, 7, msg.c_str(), 0);
#endif
    std::fprintf(stdout, "[PS5NM] %s\n", trimmed.c_str());
    std::fflush(stdout);
}

std::string LocalIp() {
    std::string ip = "127.0.0.1";
    ifaddrs *list = nullptr;
    if (getifaddrs(&list) != 0 || !list) return ip;

    for (ifaddrs *ifa = list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (std::strncmp(ifa->ifa_name, "lo", 2) == 0) continue;

        char buf[INET_ADDRSTRLEN];
        auto *addr = reinterpret_cast<sockaddr_in *>(ifa->ifa_addr);
        if (inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf))) {
            ip = buf;
            break;
        }
    }

    freeifaddrs(list);
    return ip;
}

bool InitUserService() {
    typedef int (*UserServiceInitFn)(void*);
    static UserServiceInitFn fn = nullptr;
    static bool resolved = false;
    static bool succeeded = false;
    if (succeeded) return true;
    if (!resolved) {
        resolved = true;
        if (sceUserServiceInitialize) {
            fn = sceUserServiceInitialize;
        } else {
            fn = reinterpret_cast<UserServiceInitFn>(dlsym(RTLD_DEFAULT, "sceUserServiceInitialize"));
            if (!fn) {
                void* handle = dlopen("libSceUserService.sprx", RTLD_LAZY);
                if (handle) {
                    fn = reinterpret_cast<UserServiceInitFn>(dlsym(handle, "sceUserServiceInitialize"));
                }
            }
        }
    }
    if (fn) {
        int rc = fn(nullptr);
        char buf[128];
        std::snprintf(buf, sizeof(buf), "sceUserServiceInitialize rc=0x%08x (%d)", static_cast<unsigned>(rc), rc);
        LogKlog(buf);
        succeeded = (rc == 0 || rc == static_cast<int>(0x80550001));
        return succeeded;
    }
    LogKlog("sceUserServiceInitialize symbol not found (continuing)");
    return false;
}

bool SendPlainToastDirect(const std::string &message) {
    NotifyRequest req{};
    std::snprintf(req.message, sizeof(req.message), "%s", message.c_str());
    typedef int (*PlainNotifyFn)(int, NotifyRequest*, unsigned long, int);
    static PlainNotifyFn fn = nullptr;
    static bool resolved = false;
    if (!resolved) {
        resolved = true;
        if (sceKernelSendNotificationRequest) {
            fn = sceKernelSendNotificationRequest;
        } else {
            fn = reinterpret_cast<PlainNotifyFn>(dlsym(RTLD_DEFAULT, "sceKernelSendNotificationRequest"));
        }
    }
    if (fn) {
        int rc = fn(0, &req, sizeof(req), 0);
        char buf[128];
        std::snprintf(buf, sizeof(buf), "[notify] sceKernelSendNotificationRequest rc=0x%08x (%d)",
                      static_cast<unsigned>(rc), rc);
        LogKlog(buf);
        return rc >= 0;
    }
    return false;
}

std::string JsonEscape(const std::string& value);

bool SendRichToastDirect(const std::string &message) {
    typedef int (*RichNotifyFn)(int, bool, const char*);
    static RichNotifyFn fn = nullptr;
    static bool resolved = false;
    if (!resolved) {
        resolved = true;
        if (sceNotificationSend) {
            fn = sceNotificationSend;
        } else {
            fn = reinterpret_cast<RichNotifyFn>(dlsym(RTLD_DEFAULT, "sceNotificationSend"));
            if (!fn) {
                void* handle = dlopen("libSceNotification.sprx", RTLD_LAZY);
                if (handle) {
                    fn = reinterpret_cast<RichNotifyFn>(dlsym(handle, "sceNotificationSend"));
                }
            }
        }
    }
    if (!fn) return false;

    std::string payload =
        "{\"rawData\":{\"viewTemplateType\":\"InteractiveToastTemplateB\","
        "\"channelType\":\"ServiceFeedback\",\"bundleName\":\"PS5 Network Mounting\","
        "\"useCaseId\":\"IDC\",\"toastOverwriteType\":\"InQueue\",\"isImmediate\":true,\"priority\":100,"
        "\"viewData\":{\"message\":{\"body\":\"" + JsonEscape(message) + "\"}}}}";
    constexpr int kSystemUserId = 0xFE;
    int rc = fn(kSystemUserId, true, payload.c_str());
    char buf[128];
    std::snprintf(buf, sizeof(buf), "[notify] sceNotificationSend rc=0x%08x (%d)",
                  static_cast<unsigned>(rc), rc);
    LogKlog(buf);
    return rc == 0;
}

bool SendToastWithRetries(const std::string &message, int max_attempts = 5, int delay_ms = 500) {
    if (message.empty()) return false;
    for (int attempt = 1; attempt <= max_attempts; ++attempt) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "[notify] Attempt %d/%d sending toast: %s",
                      attempt, max_attempts, message.c_str());
        LogKlog(buf);

        if (SendPlainToastDirect(message)) {
            LogKlog("[notify] Toast delivered via sceKernelSendNotificationRequest");
            return true;
        }
        if (SendRichToastDirect(message)) {
            LogKlog("[notify] Toast delivered via sceNotificationSend");
            return true;
        }

        if (attempt < max_attempts) {
            usleep(delay_ms * 1000);
        }
    }
    LogKlog("[notify] All toast notification attempts exhausted");
    return false;
}

bool LaunchBrowserWithRetries(const std::string &url, int max_attempts = 5, int delay_ms = 1000) {
    if (url.empty()) return false;
    InitUserService();

    typedef int (*LaunchBrowserFn)(const char *uri, void *reserved);
    static LaunchBrowserFn fn = nullptr;
    static bool resolved = false;
    if (!resolved) {
        resolved = true;
        if (sceSystemServiceLaunchWebBrowser) {
            fn = sceSystemServiceLaunchWebBrowser;
        } else {
            fn = reinterpret_cast<LaunchBrowserFn>(dlsym(RTLD_DEFAULT, "sceSystemServiceLaunchWebBrowser"));
            if (!fn) {
                void *handle = dlopen("libSceSystemService.sprx", RTLD_LAZY);
                if (handle) {
                    fn = reinterpret_cast<LaunchBrowserFn>(dlsym(handle, "sceSystemServiceLaunchWebBrowser"));
                }
            }
        }
    }

    if (!fn) {
        LogKlog("[browser] sceSystemServiceLaunchWebBrowser symbol not found");
        return false;
    }

    for (int attempt = 1; attempt <= max_attempts; ++attempt) {
        char buf[256];
        int rc = fn(url.c_str(), nullptr);
        std::snprintf(buf, sizeof(buf), "[browser] Attempt %d/%d: sceSystemServiceLaunchWebBrowser(\"%s\") rc=0x%08x (%d)",
                      attempt, max_attempts, url.c_str(), static_cast<unsigned>(rc), rc);
        LogKlog(buf);

        if (rc >= 0) {
            LogKlog("[browser] WebKit browser launched successfully");
            return true;
        }

        if (attempt < max_attempts) {
            usleep(delay_ms * 1000);
        }
    }

    LogKlog("[browser] All WebKit launch attempts exhausted");
    return false;
}

constexpr unsigned int kDefaultPort = 18080;
constexpr int kNetHeapSize = 5 * 1024 * 1024;
constexpr size_t kMaxBody = 64 * 1024;
constexpr size_t kMaxHeader = 16 * 1024;
constexpr int kMaxConcurrentClients = 32;

ps5nm::MountBackend g_mount;
pthread_mutex_t g_mount_api_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_client_count_lock = PTHREAD_MUTEX_INITIALIZER;
int g_active_clients = 0;

struct HttpResponse {
    unsigned int status = 200;
    std::string content_type = "application/json; charset=utf-8";
    std::string body;
    std::string extra_headers;
};

std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char c : value) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: if (c >= 0x20) out += static_cast<char>(c);
        }
    }
    return out;
}

std::string Quote(const std::string& s) { return "\"" + JsonEscape(s) + "\""; }

std::string StatusJson() {
    pthread_mutex_lock(&g_mount_api_lock);
    const auto s = g_mount.Status();
    pthread_mutex_unlock(&g_mount_api_lock);
    return "{\"state\":\"ready\",\"mounted\":" +
        std::string(s.mounted ? "true" : "false") + ",\"can_disconnect\":" +
        std::string(s.can_disconnect ? "true" : "false") + ",\"protocol\":" +
        (s.protocol.empty() ? "null" : Quote(s.protocol)) + ",\"endpoint\":" +
        (s.endpoint.empty() ? "null" : Quote(s.endpoint)) + ",\"mountpoint\":" +
        Quote(s.mountpoint) + ",\"last_result\":" + Quote(s.last_result) +
        ",\"last_error\":" + (s.last_error.empty() ? "null" : Quote(s.last_error)) + "}";
}

HttpResponse ApiError(unsigned int status, const char* code, const std::string& message) {
    return {status, "application/json; charset=utf-8",
            "{\"ok\":false,\"error\":" + Quote(code) + ",\"message\":" + Quote(message) + "}", ""};
}

HttpResponse HandleRequest(const std::string& method, const std::string& raw_path,
                           const std::map<std::string, std::string>& headers,
                           const std::string& body) {
    std::string path = raw_path;
    const auto query = path.find('?');
    if (query != std::string::npos) path.resize(query);

    // CORS preflight support
    if (method == "OPTIONS") {
        return {204, "text/plain", "",
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type, X-Requested-With\r\n"
                "Access-Control-Max-Age: 86400"};
    }

    if (method == "GET" && (path == "/" || path == "/index.html"))
        return {200, "text/html; charset=utf-8", std::string(ps5nm::kIndexHtml), ""};

    if (method == "GET" && path == "/api/v1/status")
        return {200, "application/json; charset=utf-8", StatusJson(), "Access-Control-Allow-Origin: *"};

    // Security / CSRF check for state-mutating POST requests:
    // If an Origin header is present from a foreign origin and no custom header is set, reject.
    if (method == "POST") {
        auto origin_it = headers.find("origin");
        auto requested_with_it = headers.find("x-requested-with");
        if (origin_it != headers.end() && !origin_it->second.empty()) {
            // If cross-origin request without our custom token header, block
            auto host_it = headers.find("host");
            std::string origin = origin_it->second;
            // Strip protocol from origin
            size_t pos = origin.find("://");
            if (pos != std::string::npos) origin = origin.substr(pos + 3);
            if (host_it != headers.end() && origin != host_it->second) {
                if (requested_with_it == headers.end() || requested_with_it->second != "PS5NM") {
                    return ApiError(403, "forbidden_origin", "Cross-origin request rejected without authorization header.");
                }
            }
        }
    }

    if (method == "POST" && path == "/api/v1/mount") {
        ps5nm::JsonValue req;
        std::string json_err;
        if (!ps5nm::JsonValue::Parse(body, req, &json_err) || !req.IsObject()) {
            return ApiError(400, "invalid_json", "Malformed JSON body: " + json_err);
        }

        std::string protocol = req.GetString("protocol");
        std::string host = req.GetString("host");
        std::string remote = req.GetString("remote_path");
        std::string mountpoint = req.GetString("mountpoint");
        std::string username = req.GetString("username");
        std::string password = req.GetString("password");
        int port = req.Has("port") ? req.GetInt("port", 0) : (protocol == "smb" ? 445 : 2049);

        if (protocol.empty() || host.empty() || remote.empty() || mountpoint.empty()) {
            return ApiError(400, "invalid_request",
                            "Required fields are missing or malformed: protocol, host, remote_path, mountpoint.");
        }

        if (protocol != "nfs" && protocol != "smb")
            return ApiError(400, "unsupported_protocol", "Choose NFS or SMB.");

        if (port < 1 || port > 65535)
            return ApiError(400, "invalid_port", "Port must be an integer from 1 to 65535.");

        if (host.size() > 253 || host.find_first_of(" /\\\r\n\t") != std::string::npos)
            return ApiError(400, "invalid_host", "Enter a hostname or IPv4 address only.");
        if (remote.size() > 1024 ||
            remote.find("..") != std::string::npos ||
            remote.find_first_of("\r\n?#") != std::string::npos)
            return ApiError(400, "invalid_remote_path", "Remote path is empty, too long, or contains unsafe characters.");
        if (protocol == "nfs" && remote.front() != '/')
            return ApiError(400, "invalid_remote_path", "NFS requires an absolute export path, for example /mnt/dataPool/games.");
        if (protocol == "smb" && remote.front() == '/')
            return ApiError(400, "invalid_remote_path", "SMB path must be ShareName or ShareName/subfolder without a leading slash.");
        if (mountpoint != "/hostapp")
            return ApiError(400, "unsafe_mountpoint", "For safety, the only allowed mountpoint is /hostapp.");

        std::string error;
        pthread_mutex_lock(&g_mount_api_lock);
        const bool mounted = g_mount.Mount(protocol, host, port, remote, mountpoint,
                                           username, password, &error);
        pthread_mutex_unlock(&g_mount_api_lock);
        if (!mounted) return ApiError(500, "mount_failed", error);
        return {200, "application/json; charset=utf-8", StatusJson(), "Access-Control-Allow-Origin: *"};
    }

    if (method == "POST" && path == "/api/v1/browser") {
        ps5nm::JsonValue req;
        std::string url;
        if (ps5nm::JsonValue::Parse(body, req) && req.IsObject() && req.Has("url")) {
            url = req.GetString("url");
        }
        if (url.empty()) {
            const std::string local_ip = LocalIp();
            url = "http://" + local_ip + ":" + std::to_string(kDefaultPort);
        }
        const bool launched = LaunchBrowserWithRetries(url, 3, 500);
        return {200, "application/json; charset=utf-8",
                std::string("{\"ok\":") + (launched ? "true" : "false") + ",\"url\":" + Quote(url) + "}", "Access-Control-Allow-Origin: *"};
    }

    if (method == "POST" && path == "/api/v1/notify") {
        ps5nm::JsonValue req;
        std::string msg = "PS5 Network Mounting";
        if (ps5nm::JsonValue::Parse(body, req) && req.IsObject() && req.Has("message")) {
            msg = req.GetString("message");
        }
        const bool sent = SendToastWithRetries(msg, 3, 300);
        return {200, "application/json; charset=utf-8",
                std::string("{\"ok\":") + (sent ? "true" : "false") + ",\"message\":" + Quote(msg) + "}", "Access-Control-Allow-Origin: *"};
    }

    if (method == "POST" && path == "/api/v1/unmount") {
        ps5nm::JsonValue req;
        std::string json_err;
        if (!ps5nm::JsonValue::Parse(body, req, &json_err) || !req.IsObject()) {
            return ApiError(400, "invalid_json", "Malformed JSON body: " + json_err);
        }
        std::string mountpoint = req.GetString("mountpoint");
        if (mountpoint.empty())
            return ApiError(400, "invalid_request", "mountpoint is required.");
        std::string error;
        pthread_mutex_lock(&g_mount_api_lock);
        const bool unmounted = g_mount.Unmount(mountpoint, &error);
        pthread_mutex_unlock(&g_mount_api_lock);
        if (!unmounted) return ApiError(409, "unmount_failed", error);
        return {200, "application/json; charset=utf-8", StatusJson(), "Access-Control-Allow-Origin: *"};
    }

    return ApiError(404, "not_found", "Unknown page or API endpoint.");
}

const char* Reason(unsigned int status) {
    switch (status) {
    case 200: return "OK";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default: return "Internal Server Error";
    }
}

bool SendAll(int fd, const char* data, size_t size) {
    size_t sent = 0;
    while (sent < size) {
        const ssize_t n = send(fd, data + sent, size - sent, 0);
        if (n > 0) { sent += static_cast<size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

void SendResponse(int fd, const HttpResponse& response) {
    std::string header = std::string("HTTP/1.1 ") + std::to_string(response.status) +
        " " + Reason(response.status) + "\r\nContent-Type: " + response.content_type +
        "\r\nContent-Length: " + std::to_string(response.body.size()) +
        "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n";
    if (!response.extra_headers.empty()) {
        header += response.extra_headers;
        if (header.back() != '\n') header += "\r\n";
    }
    header += "\r\n";
    (void)SendAll(fd, header.data(), header.size());
    if (!response.body.empty()) {
        (void)SendAll(fd, response.body.data(), response.body.size());
    }
}

std::string Lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

void HandleClient(int fd) {
    timeval timeout{10, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    std::string data;
    char buffer[4096];
    size_t split = std::string::npos;
    while ((split = data.find("\r\n\r\n")) == std::string::npos) {
        if (data.size() >= kMaxHeader) {
            SendResponse(fd, ApiError(431, "headers_too_large", "HTTP headers exceed the 16 KiB limit."));
            return;
        }
        const ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
        if (n <= 0) return;
        data.append(buffer, static_cast<size_t>(n));
    }
    if (split > kMaxHeader) {
        SendResponse(fd, ApiError(431, "headers_too_large", "HTTP headers exceed the 16 KiB limit."));
        return;
    }

    const std::string header = data.substr(0, split);
    std::string body = data.substr(split + 4);
    const auto line_end = header.find("\r\n");
    const std::string request_line = header.substr(0, line_end);
    const auto sp1 = request_line.find(' ');
    const auto sp2 = sp1 == std::string::npos ? sp1 : request_line.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) {
        SendResponse(fd, ApiError(400, "bad_request", "Malformed HTTP request line."));
        return;
    }
    const std::string method = request_line.substr(0, sp1);
    const std::string path = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
    const std::string version = request_line.substr(sp2 + 1);
    if (version != "HTTP/1.1" && version != "HTTP/1.0") {
        SendResponse(fd, ApiError(400, "bad_version", "Only HTTP/1.0 and HTTP/1.1 are supported."));
        return;
    }

    std::map<std::string, std::string> parsed_headers;
    size_t content_length = 0;
    bool has_content_length = false;
    size_t pos = line_end == std::string::npos ? header.size() : line_end + 2;
    while (pos < header.size()) {
        const auto end = header.find("\r\n", pos);
        const std::string line = header.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            SendResponse(fd, ApiError(400, "bad_header", "Malformed HTTP header."));
            return;
        }
        const std::string key = Lower(line.substr(0, colon));
        std::string value = line.substr(colon + 1);
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
        parsed_headers[key] = value;

        if (key == "content-length") {
            if (has_content_length) {
                SendResponse(fd, ApiError(400, "duplicate_length", "Duplicate Content-Length headers are not accepted."));
                return;
            }
            char* tail = nullptr;
            const unsigned long parsed = std::strtoul(value.c_str(), &tail, 10);
            if (tail == value.c_str() || *tail != '\0') {
                SendResponse(fd, ApiError(400, "bad_length", "Invalid Content-Length header."));
                return;
            }
            content_length = static_cast<size_t>(parsed);
            has_content_length = true;
        } else if (key == "transfer-encoding" && Lower(value) != "identity") {
            SendResponse(fd, ApiError(400, "unsupported_encoding", "Chunked request bodies are not supported."));
            return;
        }
        if (end == std::string::npos) break;
        pos = end + 2;
    }

    if (content_length > kMaxBody) {
        SendResponse(fd, ApiError(413, "body_too_large", "Request body exceeds the 64 KiB limit."));
        return;
    }
    if (body.size() > content_length) body.resize(content_length);
    while (body.size() < content_length) {
        const size_t want = content_length - body.size() < sizeof(buffer) ?
            content_length - body.size() : sizeof(buffer);
        const ssize_t n = recv(fd, buffer, want, 0);
        if (n <= 0) {
            SendResponse(fd, ApiError(400, "incomplete_body", "Request body ended before Content-Length bytes arrived."));
            return;
        }
        body.append(buffer, static_cast<size_t>(n));
    }

    SendResponse(fd, HandleRequest(method, path, parsed_headers, body));
}

void* ClientWorker(void* arg) {
    int fd = *static_cast<int*>(arg);
    delete static_cast<int*>(arg);
    HandleClient(fd);
    close(fd);

    pthread_mutex_lock(&g_client_count_lock);
    --g_active_clients;
    pthread_mutex_unlock(&g_client_count_lock);
    return nullptr;
}
}

struct StartupWorkerArgs {
    std::string web_url;
    std::string toast_message;
};

void* StartupWorker(void* arg) {
    auto* args = reinterpret_cast<StartupWorkerArgs*>(arg);
    LogKlog("[startup] Background startup worker began; waiting 300ms for system services to settle");
    usleep(300 * 1000);

    LogKlog("[startup] Sending startup notification toast");
    SendToastWithRetries(args->toast_message, 5, 500);

    LogKlog("[startup] Launching WebKit browser pointing to " + args->web_url);
    LaunchBrowserWithRetries(args->web_url, 5, 1000);

    delete args;
    return nullptr;
}

int main() {
    LogKlog("Initializing PS5 Network Mounting payload");

    int net_init_rc = sceNetInit();
    if (net_init_rc != 0) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "sceNetInit returned %d (non-fatal, continuing)", net_init_rc);
        LogKlog(buf);
    }
    const int net_pool = sceNetPoolCreate("ps5-network-mounting", kNetHeapSize, 0);
    if (net_pool < 0) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "sceNetPoolCreate returned %d (non-fatal, continuing)", net_pool);
        LogKlog(buf);
    }

    InitUserService();

    unsigned int port = kDefaultPort;
    if (const char* env = std::getenv("PS5NM_PORT")) {
        char* end = nullptr;
        const long value = std::strtol(env, &end, 10);
        if (end != env && *end == '\0' && value >= 1024 && value <= 65535)
            port = static_cast<unsigned int>(value);
    }

    // Default to 0.0.0.0 (all interfaces) so the UI is accessible via PS5 web browser
    // and from any PC/phone on the LAN using the PS5 IP address.
    const char* bind_ip = std::getenv("PS5NM_BIND");
    if (!bind_ip || !*bind_ip) bind_ip = "0.0.0.0";

    (void)signal(SIGPIPE, SIG_IGN);
    const int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "socket creation failed (errno %d: %s)", errno, std::strerror(errno));
        LogKlog(buf);
        (void)sceNetPoolDestroy(net_pool);
        return 2;
    }
    int reuse = 1;
    (void)setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    (void)setsockopt(server, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
#ifdef SO_NOSIGPIPE
    (void)setsockopt(server, SOL_SOCKET, SO_NOSIGPIPE, &reuse, sizeof(reuse));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
        LogKlog("inet_pton failed for bind_ip=" + std::string(bind_ip));
        close(server);
        (void)sceNetPoolDestroy(net_pool);
        return 3;
    }

    bool bound = false;
    constexpr int kMaxBindAttempts = 10;
    for (int attempt = 1; attempt <= kMaxBindAttempts; ++attempt) {
        if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
            listen(server, 16) == 0) {
            bound = true;
            break;
        }

        int bind_err = errno;
        char buf[192];
        std::snprintf(buf, sizeof(buf), "bind/listen attempt %d/%d on %s:%u failed (errno %d: %s)",
                      attempt, kMaxBindAttempts, bind_ip, port, bind_err, std::strerror(bind_err));
        LogKlog(buf);

        if (attempt < kMaxBindAttempts) {
            usleep(500 * 1000);
        }
    }

    const std::string local_ip = LocalIp();
    const std::string web_url = "http://" + local_ip + ":" + std::to_string(port);

    if (!bound) {
        LogKlog("bind/listen failed permanently on " + std::string(bind_ip) + ":" + std::to_string(port));
        close(server);

        // Check if port is already active (another instance running)
        int probe = socket(AF_INET, SOCK_STREAM, 0);
        bool already_running = false;
        if (probe >= 0) {
            sockaddr_in probe_addr{};
            probe_addr.sin_family = AF_INET;
            probe_addr.sin_port = htons(static_cast<uint16_t>(port));
            inet_pton(AF_INET, "127.0.0.1", &probe_addr.sin_addr);
            if (connect(probe, reinterpret_cast<sockaddr*>(&probe_addr), sizeof(probe_addr)) == 0) {
                already_running = true;
            }
            close(probe);
        }

        if (already_running) {
            LogKlog("Detected active server already running on port " + std::to_string(port) +
                    ". Relaunching WebKit and sending notification.");
            SendToastWithRetries("PS5 Network Mounting v1.1.1\nAlready active: " + web_url, 3, 500);
            LaunchBrowserWithRetries(web_url, 5, 1000);
            (void)sceNetPoolDestroy(net_pool);
            return 0; // Clean exit without error
        }

        SendToastWithRetries("PS5 Network Mounting Error:\nPort " + std::to_string(port) + " in use!", 3, 500);
        (void)sceNetPoolDestroy(net_pool);
        return 3;
    }

    LogKlog("Listening on " + std::string(bind_ip) + ":" + std::to_string(port) + " (URL: " + web_url + ")");

    // Spawn background startup worker to dispatch toast & browser without delaying the accept loop
    auto* startup_args = new StartupWorkerArgs{web_url, "PS5 Network Mounting v1.1.1\nListening on: " + web_url};
    pthread_t startup_tid;
    if (pthread_create(&startup_tid, nullptr, StartupWorker, startup_args) == 0) {
        pthread_detach(startup_tid);
    } else {
        StartupWorker(startup_args);
    }

    for (;;) {
        sockaddr_in peer{};
        socklen_t peer_size = sizeof(peer);
        const int client = accept(server, reinterpret_cast<sockaddr*>(&peer), &peer_size);
        if (client < 0) {
            if (errno == EINTR) continue;
            continue;
        }

        pthread_mutex_lock(&g_client_count_lock);
        if (g_active_clients >= kMaxConcurrentClients) {
            pthread_mutex_unlock(&g_client_count_lock);
            HttpResponse busy = ApiError(503, "busy", "Too many concurrent connections.");
            SendResponse(client, busy);
            close(client);
            continue;
        }
        ++g_active_clients;
        pthread_mutex_unlock(&g_client_count_lock);

        int* arg = new int(client);
        pthread_t th;
        if (pthread_create(&th, nullptr, ClientWorker, arg) == 0) {
            pthread_detach(th);
        } else {
            // Fallback to synchronous if thread creation fails
            delete arg;
            HandleClient(client);
            close(client);
            pthread_mutex_lock(&g_client_count_lock);
            --g_active_clients;
            pthread_mutex_unlock(&g_client_count_lock);
        }
    }

    close(server);
    (void)sceNetPoolDestroy(net_pool);
    return 0;
}
