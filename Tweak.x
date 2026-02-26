/**
 * PokerStars v3.90.1 (Build 80957) — iOS Tweak
 * SSL Pinning Bypass + Anti-Detection
 * Bundle: ro.pokerstarsmobile.www
 *
 * 7 SSL Layers + OpenSSL 3.3.2 (CommLib2a) + 5 Anti-Detection
 * Total: 65+ hooks
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>

// substrate
extern void MSHookFunction(void *symbol, void *replace, void **result);

// Block types
typedef void (^ChallengeCompletion)(NSURLSessionAuthChallengeDisposition, NSURLCredential *);
typedef void (^DeprecatedTLSCompletion)(BOOL);

// ============================================================
// Shared: Jailbreak paths
// ============================================================
static NSSet *gJBPathSet = nil;

static void initJBPaths(void) {
    gJBPathSet = [NSSet setWithArray:@[
        @"/Applications/Cydia.app",
        @"/Applications/FakeCarrier.app",
        @"/Applications/Icy.app",
        @"/Applications/IntelliScreen.app",
        @"/Applications/MxTube.app",
        @"/Applications/RockApp.app",
        @"/Applications/SBSettings.app",
        @"/Applications/WinterBoard.app",
        @"/Applications/blackra1n.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        @"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        @"/Library/MobileSubstrate/DynamicLibraries",
        @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        @"/bin/bash",
        @"/bin/sh",
        @"/etc/apt",
        @"/private/jailbreak.txt",
        @"/private/var/lib/apt",
        @"/private/var/lib/apt/",
        @"/private/var/lib/cydia",
        @"/private/var/mobile/Library/SBSettings/Themes",
        @"/private/var/stash",
        @"/private/var/tmp/cydia.log",
        @"/usr/bin/sshd",
        @"/usr/sbin/sshd",
        @"/usr/lib/substitute-inserter.dylib",
        @"/usr/libexec/ssh-keysign"
    ]];
}

static BOOL isJBPath(const char *path) {
    if (!path || !gJBPathSet) return NO;
    NSString *p = @(path);
    if ([gJBPathSet containsObject:p]) return YES;
    for (NSString *jbPath in gJBPathSet) {
        if ([p hasPrefix:jbPath]) return YES;
    }
    return NO;
}

// Helper: accept any SSL challenge
static inline void acceptSSLChallenge(NSURLAuthenticationChallenge *challenge, ChallengeCompletion completion) {
    NSURLProtectionSpace *ps = challenge.protectionSpace;
    if ([ps.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        SecTrustRef trust = ps.serverTrust;
        NSURLCredential *cred = [NSURLCredential credentialForTrust:trust];
        completion(NSURLSessionAuthChallengeUseCredential, cred);
    } else {
        completion(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

// ============================================================
// LAYER 1: iOS Security.framework — SecTrust
// ============================================================

%hookf(bool, SecTrustEvaluateWithError, SecTrustRef trust, CFErrorRef *error) {
    if (error) *error = NULL;
    return true;
}

%hookf(OSStatus, SecTrustEvaluate, SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultUnspecified;
    return errSecSuccess;
}

%hookf(OSStatus, SecTrustGetTrustResult, SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultUnspecified;
    return errSecSuccess;
}

// ============================================================
// LAYER 2: AFNetworking 4.0.1
// ============================================================

%hook AFSecurityPolicy
- (BOOL)evaluateServerTrust:(id)trust forDomain:(NSString *)domain { return YES; }
- (void)setSSLPinningMode:(NSInteger)mode { %orig(0); }
- (void)setAllowInvalidCertificates:(BOOL)allow { %orig(YES); }
- (void)setValidatesDomainName:(BOOL)validate { %orig(NO); }
- (BOOL)allowInvalidCertificates { return YES; }
- (BOOL)validatesDomainName { return NO; }
- (NSInteger)SSLPinningMode { return 0; }
%end

%hook AFURLSessionManager
- (NSError *)serverTrustErrorForServerTrust:(id)trust url:(id)url { return nil; }
%end

// ============================================================
// LAYER 5: LivePerson LPMessagingSDK 6.22.0
// ============================================================

%hook LPSRSecurityPolicy
- (BOOL)evaluateServerTrust:(id)trust forDomain:(NSString *)domain { return YES; }
%end

%hook LPSRPinningSecurityPolicy
- (BOOL)evaluateServerTrust:(id)trust forDomain:(NSString *)domain { return YES; }
%end

%hook LPSRWebSocket
- (BOOL)allowsUntrustedSSLCertificates { return YES; }
- (void)setAllowsUntrustedSSLCertificates:(BOOL)allow { %orig(YES); }
%end

%hook NSURLRequest
- (NSArray *)SR_SSLPinnedCertificates { return nil; }
%end

// ============================================================
// LAYER 6: GeoComply SDK 2.15.0 — SSL + Anti-Bypass
// ============================================================

%hook GCHttpTask
- (BOOL)shouldTrustProtectionSpace:(id)ps { return YES; }
- (void)updateSSLChallengeInfo { /* TRUE NOP — prevents SSL bypass detection */ }
- (void)logCertificateInfo:(id)info { /* NOP */ }
- (void)parseCertificatesForProtectionSpace:(id)ps { /* NOP */ }
%end

%hook GCAuthChallengeDetector
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(ChallengeCompletion)completion {
    acceptSSLChallenge(challenge, completion);
}
%end

// ============================================================
// LAYER 7: NSURLSession + WKWebView Delegates
// ============================================================

%hook GULNetworkURLSession
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(ChallengeCompletion)completion {
    acceptSSLChallenge(challenge, completion);
}
%end

%hook PYRBaseWebViewController
- (void)webView:(WKWebView *)webView didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(ChallengeCompletion)completion {
    acceptSSLChallenge(challenge, completion);
}
- (void)webView:(WKWebView *)webView authenticationChallenge:(NSURLAuthenticationChallenge *)challenge shouldAllowDeprecatedTLS:(DeprecatedTLSCompletion)completion {
    completion(YES);
}
%end

%hook PYRBaseWebViewControllerPrivate
- (void)webView:(WKWebView *)webView didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(ChallengeCompletion)completion {
    acceptSSLChallenge(challenge, completion);
}
- (void)webView:(WKWebView *)webView authenticationChallenge:(NSURLAuthenticationChallenge *)challenge shouldAllowDeprecatedTLS:(DeprecatedTLSCompletion)completion {
    completion(YES);
}
%end

%hook PYRStarsWebViewController
- (void)webView:(WKWebView *)webView didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(ChallengeCompletion)completion {
    acceptSSLChallenge(challenge, completion);
}
- (void)webView:(WKWebView *)webView authenticationChallenge:(NSURLAuthenticationChallenge *)challenge shouldAllowDeprecatedTLS:(DeprecatedTLSCompletion)completion {
    completion(YES);
}
%end

%hook NSURLSessionDelegateBypassingSSLErrors
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(ChallengeCompletion)completion {
    acceptSSLChallenge(challenge, completion);
}
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(ChallengeCompletion)completion {
    acceptSSLChallenge(challenge, completion);
}
%end

// ============================================================
// ANTI-DETECTION 1: Jailbreak
// ============================================================

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    static NSArray *schemes;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        schemes = @[@"cydia://", @"sileo://", @"zbra://", @"filza://", @"activator://", @"undecimus://"];
    });
    NSString *s = url.absoluteString;
    for (NSString *scheme in schemes) {
        if ([s hasPrefix:scheme]) return NO;
    }
    return %orig;
}
%end

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (!path) return %orig;
    if ([gJBPathSet containsObject:path]) return NO;
    for (NSString *jbPath in gJBPathSet) {
        if ([path hasPrefix:jbPath]) return NO;
    }
    return %orig;
}
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir {
    if (!path) return %orig;
    if ([gJBPathSet containsObject:path]) return NO;
    for (NSString *jbPath in gJBPathSet) {
        if ([path hasPrefix:jbPath]) return NO;
    }
    return %orig;
}
%end

%hookf(pid_t, fork) { return -1; }
%hookf(pid_t, getppid) { return 1; }

// ============================================================
// ANTI-DETECTION 3: GeoComply RASP
// ============================================================

%hook GCDebuggerDetectionOperation
- (void)start { /* NOP — don't start debugger detection */ }
%end

%hook GCReverseEngineeringDetectionOperation
- (id)checkDYLDForLibs:(id)libs { return nil; }
- (id)checkOpenedPort:(id)port shouldImprove:(BOOL)improve { return nil; }
- (BOOL)canOpenPort:(id)port { return NO; }
%end

// ============================================================
// C function hook originals & replacements
// ============================================================

// --- access / stat / lstat ---
static int (*orig_access)(const char *, int);
static int hook_access(const char *path, int mode) {
    if (isJBPath(path)) return -1;
    return orig_access(path, mode);
}

static int (*orig_stat)(const char *restrict, struct stat *restrict);
static int hook_stat(const char *restrict path, struct stat *restrict buf) {
    if (isJBPath(path)) return -1;
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *restrict, struct stat *restrict);
static int hook_lstat(const char *restrict path, struct stat *restrict buf) {
    if (isJBPath(path)) return -1;
    return orig_lstat(path, buf);
}

// --- ptrace ---
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int hook_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31) return 0; // PT_DENY_ATTACH
    return orig_ptrace(request, pid, addr, data);
}

// --- sysctl (clear P_TRACED) ---
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (namelen == 4 && name[0] == 1 && name[1] == 14 && oldp) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~0x00000800; // P_TRACED
    }
    return ret;
}

// --- _dyld_get_image_name (hide Frida/Substrate) ---
static const char *(*orig_dyld_get_image_name)(uint32_t);
static const char *hook_dyld_get_image_name(uint32_t idx) {
    const char *name = orig_dyld_get_image_name(idx);
    if (name) {
        static const char *hidden[] = {
            "frida", "FridaGadget", "substrate", "substitute", "cycript",
            "SSLKillSwitch", "MobileSubstrate", "libreveal", "Shadow",
            "TweakInject", "ellekit", NULL
        };
        for (int i = 0; hidden[i]; i++) {
            if (strcasestr(name, hidden[i]))
                return "/usr/lib/libSystem.B.dylib";
        }
    }
    return name;
}

// --- OpenSSL (statically linked via CommLib2a) ---
static int (*orig_X509_verify_cert)(void *);
static int hook_X509_verify_cert(void *ctx) { return 1; }

static int (*orig_X509_check_host)(void *, const char *, size_t, unsigned int, char **);
static int hook_X509_check_host(void *cert, const char *name, size_t namelen, unsigned int flags, char **peername) { return 1; }

static int (*orig_X509_STORE_CTX_init)(void *, void *, void *, void *);
static int hook_X509_STORE_CTX_init(void *ctx, void *store, void *x509, void *chain) {
    int ret = orig_X509_STORE_CTX_init(ctx, store, x509, chain);
    return ret > 0 ? ret : 1;
}

static long (*orig_ssl_get_verify_result)(void *);
static long hook_ssl_get_verify_result(void *ssl) { return 0; /* X509_V_OK */ }

// ============================================================
// Runtime ObjC hooks (pattern-matched classes)
// ============================================================

static void hookRuntimePatterns(void) {
    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);

    for (unsigned int i = 0; i < classCount; i++) {
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(classes[i], &methodCount);
        if (!methods) continue;

        for (unsigned int j = 0; j < methodCount; j++) {
            NSString *sel = NSStringFromSelector(method_getName(methods[j]));

            // LPMessagingSDK cert pinning
            if ([sel containsString:@"handleCertPinningFailed"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^(id s){ }));
            }
            else if ([sel isEqualToString:@"getCertPinningPublicKeyList"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^NSArray *(id s){ return @[]; }));
            }
            else if ([sel isEqualToString:@"evaluateCertPinningCertificate"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^BOOL(id s){ return YES; }));
            }
            else if ([sel isEqualToString:@"certPinningPublicKeys"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^id(id s){ return nil; }));
            }
            // AppsFlyer
            else if ([sel containsString:@"isJailbroken"] || [sel containsString:@"isJailBroken"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^BOOL(id s){ return NO; }));
            }
            else if ([sel containsString:@"promptJailbrokenWarning"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^(id s){ }));
            }
            else if ([sel isEqualToString:@"skipAdvancedJailbreakValidation"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^BOOL(id s){ return YES; }));
            }
            // Integrity checks
            else if ([sel containsString:@"dataIntegrityCheck"] || [sel containsString:@"integrityViolation"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^BOOL(id s){ return YES; }));
            }
        }
        free(methods);
    }
    free(classes);
}

// ============================================================
// Constructor
// ============================================================

%ctor {
    @autoreleasepool {
        NSLog(@"[PokerStarsSSLBypass] Loading — 7 SSL layers + anti-detection...");

        initJBPaths();

        // Logos hooks (%hook + %hookf)
        %init;

        // C function hooks
        MSHookFunction((void *)access, (void *)hook_access, (void **)&orig_access);
        MSHookFunction((void *)stat, (void *)hook_stat, (void **)&orig_stat);
        MSHookFunction((void *)lstat, (void *)hook_lstat, (void **)&orig_lstat);
        MSHookFunction((void *)sysctl, (void *)hook_sysctl, (void **)&orig_sysctl);
        MSHookFunction((void *)_dyld_get_image_name, (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);

        void *ptrace_ptr = dlsym(RTLD_DEFAULT, "ptrace");
        if (ptrace_ptr) MSHookFunction(ptrace_ptr, (void *)hook_ptrace, (void **)&orig_ptrace);

        // OpenSSL hooks (statically linked in main binary)
        void *fn;
        fn = dlsym(RTLD_DEFAULT, "X509_verify_cert");
        if (fn) { MSHookFunction(fn, (void *)hook_X509_verify_cert, (void **)&orig_X509_verify_cert); NSLog(@"[PokerStarsSSLBypass] X509_verify_cert hooked"); }

        fn = dlsym(RTLD_DEFAULT, "X509_check_host");
        if (fn) { MSHookFunction(fn, (void *)hook_X509_check_host, (void **)&orig_X509_check_host); NSLog(@"[PokerStarsSSLBypass] X509_check_host hooked"); }

        fn = dlsym(RTLD_DEFAULT, "X509_STORE_CTX_init");
        if (fn) { MSHookFunction(fn, (void *)hook_X509_STORE_CTX_init, (void **)&orig_X509_STORE_CTX_init); NSLog(@"[PokerStarsSSLBypass] X509_STORE_CTX_init hooked"); }

        // SSL_get_verify_result / SSL_CTX_set_verify (may not be exported)
        fn = dlsym(RTLD_DEFAULT, "SSL_get_verify_result");
        if (fn) {
            MSHookFunction(fn, (void *)hook_ssl_get_verify_result, (void **)&orig_ssl_get_verify_result);
        }

        // Runtime pattern hooks (delayed to ensure all frameworks loaded)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            hookRuntimePatterns();
            NSLog(@"[PokerStarsSSLBypass] Runtime pattern hooks installed!");
        });

        NSLog(@"[PokerStarsSSLBypass] All core hooks installed!");
    }
}
