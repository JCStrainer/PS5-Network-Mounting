#pragma once

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ps5nm {

enum class JsonType { Null, Bool, Number, String, Array, Object };

class JsonValue {
public:
    JsonType type = JsonType::Null;
    bool bool_val = false;
    double num_val = 0.0;
    int64_t int_val = 0;
    std::string str_val;
    std::vector<JsonValue> arr_val;
    std::map<std::string, JsonValue> obj_val;

    JsonValue() = default;

    bool IsNull() const { return type == JsonType::Null; }
    bool IsBool() const { return type == JsonType::Bool; }
    bool IsNumber() const { return type == JsonType::Number; }
    bool IsString() const { return type == JsonType::String; }
    bool IsArray() const { return type == JsonType::Array; }
    bool IsObject() const { return type == JsonType::Object; }

    bool Has(const std::string& key) const {
        return type == JsonType::Object && obj_val.find(key) != obj_val.end();
    }

    const JsonValue& operator[](const std::string& key) const {
        static const JsonValue kNull{};
        if (type != JsonType::Object) return kNull;
        auto it = obj_val.find(key);
        return it != obj_val.end() ? it->second : kNull;
    }

    std::string GetString(const std::string& key, const std::string& def = "") const {
        if (type != JsonType::Object) return def;
        auto it = obj_val.find(key);
        if (it != obj_val.end() && it->second.type == JsonType::String) {
            return it->second.str_val;
        }
        return def;
    }

    int GetInt(const std::string& key, int def = 0) const {
        if (type != JsonType::Object) return def;
        auto it = obj_val.find(key);
        if (it != obj_val.end() && it->second.type == JsonType::Number) {
            return static_cast<int>(it->second.int_val);
        }
        return def;
    }

    bool GetBool(const std::string& key, bool def = false) const {
        if (type != JsonType::Object) return def;
        auto it = obj_val.find(key);
        if (it != obj_val.end() && it->second.type == JsonType::Bool) {
            return it->second.bool_val;
        }
        return def;
    }

    static bool Parse(const std::string& src, JsonValue& root, std::string* err = nullptr) {
        size_t idx = 0;
        SkipWs(src, idx);
        if (!ParseValue(src, idx, root, err)) return false;
        SkipWs(src, idx);
        if (idx < src.size()) {
            if (err) *err = "Unexpected trailing characters after JSON document at position " + std::to_string(idx);
            return false;
        }
        return true;
    }

private:
    static void SkipWs(const std::string& s, size_t& i) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) {
            ++i;
        }
    }

    static bool ParseValue(const std::string& s, size_t& i, JsonValue& val, std::string* err) {
        SkipWs(s, i);
        if (i >= s.size()) {
            if (err) *err = "Unexpected end of input";
            return false;
        }
        char c = s[i];
        if (c == '{') return ParseObject(s, i, val, err);
        if (c == '[') return ParseArray(s, i, val, err);
        if (c == '"') return ParseString(s, i, val.str_val, err) ? (val.type = JsonType::String, true) : false;
        if (c == 't' || c == 'f') return ParseBool(s, i, val, err);
        if (c == 'n') return ParseNull(s, i, val, err);
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return ParseNumber(s, i, val, err);

        if (err) *err = std::string("Unexpected character '") + c + "' at position " + std::to_string(i);
        return false;
    }

    static bool ParseString(const std::string& s, size_t& i, std::string& out, std::string* err) {
        if (i >= s.size() || s[i] != '"') {
            if (err) *err = "Expected '\"'";
            return false;
        }
        ++i;
        out.clear();
        out.reserve(32);
        while (i < s.size()) {
            char c = s[i++];
            if (c == '"') return true;
            if (c == '\\') {
                if (i >= s.size()) {
                    if (err) *err = "Unterminated escape sequence in string";
                    return false;
                }
                char esc = s[i++];
                switch (esc) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    if (i + 4 > s.size()) {
                        if (err) *err = "Invalid unicode escape sequence";
                        return false;
                    }
                    unsigned int cp = 0;
                    for (int k = 0; k < 4; ++k) {
                        char h = s[i++];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= (h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= (h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= (h - 'A' + 10);
                        else {
                            if (err) *err = "Invalid hex in unicode escape sequence";
                            return false;
                        }
                    }
                    if (cp < 0x80) {
                        out += static_cast<char>(cp);
                    } else if (cp < 0x800) {
                        out += static_cast<char>(0xC0 | (cp >> 6));
                        out += static_cast<char>(0x80 | (cp & 0x3F));
                    } else {
                        out += static_cast<char>(0xE0 | (cp >> 12));
                        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                        out += static_cast<char>(0x80 | (cp & 0x3F));
                    }
                    break;
                }
                default:
                    if (err) *err = std::string("Unknown escape sequence '\\") + esc + "'";
                    return false;
                }
            } else {
                if (static_cast<unsigned char>(c) < 0x20) {
                    if (err) *err = "Unescaped control character in string";
                    return false;
                }
                out += c;
            }
        }
        if (err) *err = "Unterminated string literal";
        return false;
    }

    static bool ParseNumber(const std::string& s, size_t& i, JsonValue& val, std::string* err) {
        size_t start = i;
        if (s[i] == '-') ++i;
        if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) {
            if (err) *err = "Invalid number format";
            return false;
        }
        if (s[i] == '0' && i + 1 < s.size() && std::isdigit(static_cast<unsigned char>(s[i + 1]))) {
            if (err) *err = "Numbers cannot have leading zeroes";
            return false;
        }
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
        bool is_float = false;
        if (i < s.size() && s[i] == '.') {
            is_float = true;
            ++i;
            if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) {
                if (err) *err = "Invalid fraction in number";
                return false;
            }
            while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
        }
        if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
            is_float = true;
            ++i;
            if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
            if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) {
                if (err) *err = "Invalid exponent in number";
                return false;
            }
            while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
        }
        std::string num_str = s.substr(start, i - start);
        val.type = JsonType::Number;
        char* end = nullptr;
        if (is_float) {
            val.num_val = std::strtod(num_str.c_str(), &end);
            val.int_val = static_cast<int64_t>(val.num_val);
        } else {
            val.int_val = std::strtoll(num_str.c_str(), &end, 10);
            val.num_val = static_cast<double>(val.int_val);
        }
        return true;
    }

    static bool ParseBool(const std::string& s, size_t& i, JsonValue& val, std::string* err) {
        if (s.compare(i, 4, "true") == 0) {
            val.type = JsonType::Bool;
            val.bool_val = true;
            i += 4;
            return true;
        }
        if (s.compare(i, 5, "false") == 0) {
            val.type = JsonType::Bool;
            val.bool_val = false;
            i += 5;
            return true;
        }
        if (err) *err = "Expected boolean true or false";
        return false;
    }

    static bool ParseNull(const std::string& s, size_t& i, JsonValue& val, std::string* err) {
        if (s.compare(i, 4, "null") == 0) {
            val.type = JsonType::Null;
            i += 4;
            return true;
        }
        if (err) *err = "Expected null";
        return false;
    }

    static bool ParseObject(const std::string& s, size_t& i, JsonValue& val, std::string* err) {
        ++i; // skip '{'
        val.type = JsonType::Object;
        val.obj_val.clear();
        for (;;) {
            SkipWs(s, i);
            if (i >= s.size()) {
                if (err) *err = "Unclosed object literal";
                return false;
            }
            if (s[i] == '}') {
                ++i;
                return true;
            }
            if (!val.obj_val.empty()) {
                if (s[i] != ',') {
                    if (err) *err = "Expected ',' or '}' in object literal";
                    return false;
                }
                ++i;
                SkipWs(s, i);
                if (i >= s.size()) {
                    if (err) *err = "Unexpected end in object literal after comma";
                    return false;
                }
            }
            std::string key;
            if (!ParseString(s, i, key, err)) return false;
            SkipWs(s, i);
            if (i >= s.size() || s[i] != ':') {
                if (err) *err = "Expected ':' after property name in object literal";
                return false;
            }
            ++i; // skip ':'
            JsonValue elem;
            if (!ParseValue(s, i, elem, err)) return false;
            val.obj_val[std::move(key)] = std::move(elem);
        }
    }

    static bool ParseArray(const std::string& s, size_t& i, JsonValue& val, std::string* err) {
        ++i; // skip '['
        val.type = JsonType::Array;
        val.arr_val.clear();
        for (;;) {
            SkipWs(s, i);
            if (i >= s.size()) {
                if (err) *err = "Unclosed array literal";
                return false;
            }
            if (s[i] == ']') {
                ++i;
                return true;
            }
            if (!val.arr_val.empty()) {
                if (s[i] != ',') {
                    if (err) *err = "Expected ',' or ']' in array literal";
                    return false;
                }
                ++i;
                SkipWs(s, i);
                if (i >= s.size()) {
                    if (err) *err = "Unexpected end in array literal after comma";
                    return false;
                }
            }
            JsonValue elem;
            if (!ParseValue(s, i, elem, err)) return false;
            val.arr_val.push_back(std::move(elem));
        }
    }
};

} // namespace ps5nm
