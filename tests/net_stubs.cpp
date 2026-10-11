extern "C" {
int sceNetInit(void) { return 0; }
int sceNetPoolCreate(const char*, int, int) { return 1; }
int sceNetPoolDestroy(int) { return 0; }
int sceKernelSendNotificationRequest(int, void*, unsigned long, int) { return 0; }
int sceSystemServiceLaunchWebBrowser(const char*, void*) { return 0; }
}
