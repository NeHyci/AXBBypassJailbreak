#import <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dlfcn.h>

static bool isJailbreakFile(const char *path) {
    if (path) {
        if (!strcmp(path, "/Applications/Cydia.app")
        || !strcmp(path, "/var/lib/cydia")
        || !strcmp(path, "/var/mobile/Library/Cydia")
        || !strcmp(path, "/usr/libexec/cydia")
        || !strcmp(path, "/var/cache/apt")
        || !strcmp(path, "/var/lib/apt")
        || !strcmp(path, "/Library/MobileSubstrate/MobileSubstrate.dylib")
        || !strcmp(path, "/bin/bash")
        || !strcmp(path, "/bin/sh")
        || !strcmp(path, "/usr/sbin/sshd")
        || !strcmp(path, "/usr/libexec/ssh-keysign")
        || !strcmp(path, "/etc/apt")
        || !strcmp(path, "/etc/ssh/sshd_config")
        || !strcmp(path, "/Library/MobileSubstrate/DynamicLibraries/xCon.plist")
        || !strcmp(path, "/Library/MobileSubstrate/DynamicLibraries/xCon.dylib")
        || !strcmp(path, "/usr/bin/cycript")
        || !strcmp(path, "/usr/sbin/frida-server")) {
            return true;
        }
    }
    return false;
}

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (isJailbreakFile(path.UTF8String)) {
        return NO;
    }
    return %orig;
}
- (id)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if ([path isEqualToString:@"/var/containers/Bundle/Application"]
    || [path isEqualToString:@"/var/mobile/Applications"]
    || [path isEqualToString:@"/var/mobile/Containers/Bundle/Application"]
    || [path isEqualToString:@"/Applications"]) {
        return %orig(@"/Bypass", error);
    }
    return %orig;
}
%end
%hookf(int, stat, const char *path, struct stat *st) {
    if (isJailbreakFile(path)) {
        return -1;
    }
    return %orig;
}
%hookf(int, dladdr, const void *addr, Dl_info *info) {
    if (addr == &stat
    || addr == &lstat) {
        info->dli_fname = "/usr/lib/system/libsystem_kernel.dylib";
    }
    return %orig;
}
%hookf(char *, getenv, const char *name) {
    if (!strcmp(name, "DYLD_INSERT_LIBRARIES")) {
        return NULL;
    }
    return %orig;
}
%hookf(int, lstat, const char *path, struct stat *st) {
    if (!%orig) {
        if (st) {
            if ((st->st_mode & S_IFLNK) == S_IFLNK) {
                st->st_mode = S_IFDIR;
            }
        }
    }
    return %orig;
}

%hookf(const char *, _dyld_get_image_name, unsigned int image_index) {
    if (!strcmp(%orig, "/Library/MobileSubstrate/MobileSubstrate.dylib")
    || strstr(%orig, "SubstrateLoader.dylib")
    || strstr(%orig, "SubstrateInserter.dylib")
    || strstr(%orig, "libcycript.dylib")) {
        return "";
    }
    return %orig;
}

%hook BCEMain
- (void)onlineEntry {
    return;
}
- (void)offlineEntry {
    return;
}
%end
%hook BCESMain
- (void)onlineEntry {
    return;
}
- (void)offlineEntry {
    return;
}
%end
