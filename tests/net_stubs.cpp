extern "C" {
int sceNetInit(void) { return 0; }
int sceNetPoolCreate(const char*, int, int) { return 1; }
int sceNetPoolDestroy(int) { return 0; }
int sceKernelSendNotificationRequest(int, void*, unsigned long, int) { return 0; }
int sceNotificationSend(int, bool, const char*) { return 0; }
int sceSystemServiceLaunchWebBrowser(const char*, void*) { return 0; }
int sceUserServiceInitialize(void*) { return 0; }
int sceUserServiceTerminate(void) { return 0; }
}
