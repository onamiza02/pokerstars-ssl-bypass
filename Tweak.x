/**
 * PokerStars v3.90.1 (Build 80957) — iOS Tweak
 * SSL Pinning Bypass + Anti-Detection + FULL Traffic Logger
 * Bundle: ro.pokerstarsmobile.www
 *
 * Captures 100% of all traffic:
 *   - SSL_read/SSL_write  → CommLib2a plaintext (game protocol, login, guards)
 *   - Auth layer           → credentials, tokens, IDP OAuth2
 *   - HTTP layer           → AFNetworking REST API calls
 *   - WebSocket            → GraphQL subscriptions, STOMP
 *   - WebView bridge       → JS ↔ Native messages
 *
 * Log output: /var/tmp/ps_traffic.log + NSLog (syslog)
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

// ╔════════════════════════════════════════════════════════════╗
// ║  MSHookFunction — runtime resolved via dlsym              ║
// ║  No link-time dependency on CydiaSubstrate/substrate      ║
// ╚════════════════════════════════════════════════════════════╝
typedef void (*MSHookFunction_t)(void *, void *, void **);
static MSHookFunction_t _MSHookFn = NULL;

static void MSHookFunction(void *symbol, void *replace, void **result) {
    if (_MSHookFn) _MSHookFn(symbol, replace, result);
}

static void initHookAPI(void) {
    _MSHookFn = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (_MSHookFn) return;
    const char *libs[] = {
        "/usr/lib/libellekit.dylib",
        "/var/jb/usr/lib/libellekit.dylib",
        "/usr/lib/libsubstrate.dylib",
        "/var/jb/usr/lib/libsubstrate.dylib",
        NULL
    };
    for (int i = 0; libs[i]; i++) {
        void *h = dlopen(libs[i], RTLD_LAZY);
        if (h) { _MSHookFn = (MSHookFunction_t)dlsym(h, "MSHookFunction"); if (_MSHookFn) return; }
    }
}

typedef void (^ChallengeCompletion)(NSURLSessionAuthChallengeDisposition, NSURLCredential *);
typedef void (^DeprecatedTLSCompletion)(BOOL);

// ╔════════════════════════════════════════════════════════════╗
// ║  SECTION 1: LOG INFRASTRUCTURE                            ║
// ╚════════════════════════════════════════════════════════════╝

#define HEXDUMP_MAX 2048

static NSFileHandle *gLogHandle = nil;
static dispatch_queue_t gLogQueue = nil;

static void initLogger(void) {
    gLogQueue = dispatch_queue_create("com.ps.traffic.log", DISPATCH_QUEUE_SERIAL);
    NSString *logPath = @"/var/tmp/ps_traffic.log";

    // Rotate if > 50MB
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:logPath]) {
        NSDictionary *attr = [fm attributesOfItemAtPath:logPath error:nil];
        if ([attr fileSize] > 50 * 1024 * 1024) {
            [fm removeItemAtPath:[logPath stringByAppendingString:@".old"] error:nil];
            [fm moveItemAtPath:logPath toPath:[logPath stringByAppendingString:@".old"] error:nil];
        }
    }

    [fm createFileAtPath:logPath contents:nil attributes:nil];
    gLogHandle = [NSFileHandle fileHandleForWritingAtPath:logPath];
    [gLogHandle seekToEndOfFile];

    NSString *hdr = [NSString stringWithFormat:
        @"\n══════════ PokerStars Traffic Logger Started: %@ ══════════\n\n",
        [NSDate date]];
    [gLogHandle writeData:[hdr dataUsingEncoding:NSUTF8StringEncoding]];
}

static void psLog(NSString *tag, NSString *format, ...) __attribute__((format(__NSString__, 2, 3)));
static void psLog(NSString *tag, NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSLog(@"[PS][%@] %@", tag, msg);

    if (gLogHandle && gLogQueue) {
        NSTimeInterval ts = [[NSDate date] timeIntervalSince1970];
        unsigned ms = (unsigned)(ts * 1000) % 1000;
        NSString *line = [NSString stringWithFormat:@"[%.0f.%03u][%@] %@\n", ts, ms, tag, msg];
        NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
        dispatch_async(gLogQueue, ^{
            [gLogHandle writeData:data];
        });
    }
}

static NSString *hexDump(const void *data, int len) {
    if (!data || len <= 0) return @"(empty)";
    int cap = len > HEXDUMP_MAX ? HEXDUMP_MAX : len;
    const unsigned char *p = (const unsigned char *)data;
    NSMutableString *s = [NSMutableString stringWithCapacity:cap * 5];

    for (int i = 0; i < cap; i += 16) {
        [s appendFormat:@"  %04x: ", i];
        for (int j = 0; j < 16; j++) {
            if (i + j < cap) [s appendFormat:@"%02x ", p[i + j]];
            else [s appendString:@"   "];
        }
        [s appendString:@" |"];
        for (int j = 0; j < 16 && (i + j) < cap; j++) {
            unsigned char c = p[i + j];
            [s appendFormat:@"%c", (c >= 0x20 && c < 0x7f) ? c : '.'];
        }
        [s appendString:@"|\n"];
    }
    if (len > HEXDUMP_MAX)
        [s appendFormat:@"  ... (%d more bytes)\n", len - HEXDUMP_MAX];
    return s;
}

static void logToFile(NSString *content) {
    if (gLogHandle && gLogQueue) {
        NSData *data = [content dataUsingEncoding:NSUTF8StringEncoding];
        dispatch_async(gLogQueue, ^{
            [gLogHandle writeData:data];
        });
    }
}

// ╔════════════════════════════════════════════════════════════╗
// ║  SECTION 2: SSL PINNING BYPASS (7 Layers + OpenSSL)       ║
// ╚════════════════════════════════════════════════════════════╝

// --- LAYER 1: SecTrust ---
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

// --- LAYER 2: AFNetworking 4.0.1 ---
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

// --- LAYER 5: LivePerson ---
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

// --- LAYER 6: GeoComply ---
%hook GCHttpTask
- (BOOL)shouldTrustProtectionSpace:(id)ps { return YES; }
- (void)updateSSLChallengeInfo {}
- (void)logCertificateInfo:(id)info {}
- (void)parseCertificatesForProtectionSpace:(id)ps {}
%end

%hook GCAuthChallengeDetector
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(ChallengeCompletion)completion {
    NSURLProtectionSpace *ps = challenge.protectionSpace;
    if ([ps.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completion(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:ps.serverTrust]);
    } else {
        completion(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}
%end

// --- LAYER 7: NSURLSession + WKWebView delegates ---
static inline void bypassSSL(NSURLAuthenticationChallenge *challenge, ChallengeCompletion completion) {
    NSURLProtectionSpace *ps = challenge.protectionSpace;
    if ([ps.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completion(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:ps.serverTrust]);
    } else {
        completion(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

%hook GULNetworkURLSession
- (void)URLSession:(NSURLSession *)s task:(NSURLSessionTask *)t didReceiveChallenge:(NSURLAuthenticationChallenge *)c completionHandler:(ChallengeCompletion)h { bypassSSL(c, h); }
%end

%hook PYRBaseWebViewController
- (void)webView:(WKWebView *)w didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)c completionHandler:(ChallengeCompletion)h { bypassSSL(c, h); }
- (void)webView:(WKWebView *)w authenticationChallenge:(NSURLAuthenticationChallenge *)c shouldAllowDeprecatedTLS:(DeprecatedTLSCompletion)h { h(YES); }
%end
%hook PYRBaseWebViewControllerPrivate
- (void)webView:(WKWebView *)w didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)c completionHandler:(ChallengeCompletion)h { bypassSSL(c, h); }
- (void)webView:(WKWebView *)w authenticationChallenge:(NSURLAuthenticationChallenge *)c shouldAllowDeprecatedTLS:(DeprecatedTLSCompletion)h { h(YES); }
%end
%hook PYRStarsWebViewController
- (void)webView:(WKWebView *)w didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)c completionHandler:(ChallengeCompletion)h { bypassSSL(c, h); }
- (void)webView:(WKWebView *)w authenticationChallenge:(NSURLAuthenticationChallenge *)c shouldAllowDeprecatedTLS:(DeprecatedTLSCompletion)h { h(YES); }
%end
%hook NSURLSessionDelegateBypassingSSLErrors
- (void)URLSession:(NSURLSession *)s didReceiveChallenge:(NSURLAuthenticationChallenge *)c completionHandler:(ChallengeCompletion)h { bypassSSL(c, h); }
- (void)URLSession:(NSURLSession *)s task:(NSURLSessionTask *)t didReceiveChallenge:(NSURLAuthenticationChallenge *)c completionHandler:(ChallengeCompletion)h { bypassSSL(c, h); }
%end

// ╔════════════════════════════════════════════════════════════╗
// ║  SECTION 3: ANTI-DETECTION (JB + Debug + RASP)            ║
// ╚════════════════════════════════════════════════════════════╝

static NSSet *gJBPathSet = nil;
static void initJBPaths(void) {
    gJBPathSet = [NSSet setWithArray:@[
        @"/Applications/Cydia.app", @"/Applications/FakeCarrier.app",
        @"/Applications/Icy.app", @"/Applications/IntelliScreen.app",
        @"/Applications/MxTube.app", @"/Applications/RockApp.app",
        @"/Applications/SBSettings.app", @"/Applications/WinterBoard.app",
        @"/Applications/blackra1n.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        @"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        @"/Library/MobileSubstrate/DynamicLibraries",
        @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        @"/bin/bash", @"/bin/sh", @"/etc/apt",
        @"/private/jailbreak.txt", @"/private/var/lib/apt",
        @"/private/var/lib/apt/", @"/private/var/lib/cydia",
        @"/private/var/mobile/Library/SBSettings/Themes",
        @"/private/var/stash", @"/private/var/tmp/cydia.log",
        @"/usr/bin/sshd", @"/usr/sbin/sshd",
        @"/usr/lib/substitute-inserter.dylib", @"/usr/libexec/ssh-keysign"
    ]];
}
static BOOL isJBPath(const char *path) {
    if (!path || !gJBPathSet) return NO;
    NSString *p = @(path);
    if ([gJBPathSet containsObject:p]) return YES;
    for (NSString *jb in gJBPathSet) { if ([p hasPrefix:jb]) return YES; }
    return NO;
}

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    static NSArray *schemes;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ schemes = @[@"cydia://",@"sileo://",@"zbra://",@"filza://",@"activator://",@"undecimus://"]; });
    NSString *s = url.absoluteString;
    for (NSString *sc in schemes) { if ([s hasPrefix:sc]) return NO; }
    return %orig;
}
%end

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && (isJBPath(path.UTF8String))) return NO;
    return %orig;
}
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir {
    if (path && (isJBPath(path.UTF8String))) return NO;
    return %orig;
}
%end

%hookf(pid_t, fork) { return -1; }
%hookf(pid_t, getppid) { return 1; }

%hook GCDebuggerDetectionOperation
- (void)start {}
%end
%hook GCReverseEngineeringDetectionOperation
- (id)checkDYLDForLibs:(id)libs { return nil; }
- (id)checkOpenedPort:(id)port shouldImprove:(BOOL)improve { return nil; }
- (BOOL)canOpenPort:(id)port { return NO; }
%end

// C function hooks
static int (*orig_access)(const char *, int);
static int hook_access(const char *path, int mode) { return isJBPath(path) ? -1 : orig_access(path, mode); }
static int (*orig_stat)(const char *restrict, struct stat *restrict);
static int hook_stat(const char *restrict path, struct stat *restrict buf) { return isJBPath(path) ? -1 : orig_stat(path, buf); }
static int (*orig_lstat)(const char *restrict, struct stat *restrict);
static int hook_lstat(const char *restrict path, struct stat *restrict buf) { return isJBPath(path) ? -1 : orig_lstat(path, buf); }
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int hook_ptrace(int req, pid_t p, caddr_t a, int d) { return req == 31 ? 0 : orig_ptrace(req, p, a, d); }
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hook_sysctl(int *name, u_int nl, void *op, size_t *ol, void *np, size_t newl) {
    int ret = orig_sysctl(name, nl, op, ol, np, newl);
    if (nl == 4 && name[0] == 1 && name[1] == 14 && op) ((struct kinfo_proc *)op)->kp_proc.p_flag &= ~0x800;
    return ret;
}
static const char *(*orig_dyld_name)(uint32_t);
static const char *hook_dyld_name(uint32_t idx) {
    const char *n = orig_dyld_name(idx);
    if (n) {
        static const char *h[] = {"frida","FridaGadget","substrate","substitute","cycript","SSLKillSwitch","MobileSubstrate","libreveal","Shadow","TweakInject","ellekit",NULL};
        for (int i = 0; h[i]; i++) if (strcasestr(n, h[i])) return "/usr/lib/libSystem.B.dylib";
    }
    return n;
}

// OpenSSL bypass
static int (*orig_X509_verify_cert)(void *);
static int hook_X509_verify_cert(void *ctx) { return 1; }
static int (*orig_X509_check_host)(void *, const char *, size_t, unsigned int, char **);
static int hook_X509_check_host(void *c, const char *n, size_t l, unsigned int f, char **p) { return 1; }
static int (*orig_X509_STORE_CTX_init)(void *, void *, void *, void *);
static int hook_X509_STORE_CTX_init(void *a, void *b, void *c, void *d) { int r = orig_X509_STORE_CTX_init(a,b,c,d); return r > 0 ? r : 1; }
static long (*orig_ssl_get_verify)(void *);
static long hook_ssl_get_verify(void *ssl) { return 0; }

// ╔════════════════════════════════════════════════════════════╗
// ║  SECTION 4: TRAFFIC LOGGER — SSL_read / SSL_write         ║
// ║  (Captures ALL CommLib2a plaintext traffic)                ║
// ╚════════════════════════════════════════════════════════════╝

static int (*orig_SSL_read)(void *ssl, void *buf, int num);
static int hook_SSL_read(void *ssl, void *buf, int num) {
    int ret = orig_SSL_read(ssl, buf, num);
    if (ret > 0) {
        psLog(@"SSL_READ", @"ssl=%p len=%d", ssl, ret);
        logToFile([NSString stringWithFormat:@"[SSL_READ] ssl=%p len=%d\n%@\n", ssl, ret, hexDump(buf, ret)]);
    }
    return ret;
}

static int (*orig_SSL_write)(void *ssl, const void *buf, int num);
static int hook_SSL_write(void *ssl, const void *buf, int num) {
    if (num > 0) {
        psLog(@"SSL_WRITE", @"ssl=%p len=%d", ssl, num);
        logToFile([NSString stringWithFormat:@"[SSL_WRITE] ssl=%p len=%d\n%@\n", ssl, num, hexDump(buf, num)]);
    }
    return orig_SSL_write(ssl, buf, num);
}

// Track SSL connection lifecycle
static void *(*orig_SSL_new)(void *ctx);
static void *hook_SSL_new(void *ctx) {
    void *ssl = orig_SSL_new(ctx);
    psLog(@"SSL_NEW", @"ctx=%p → ssl=%p", ctx, ssl);
    return ssl;
}

static void (*orig_SSL_free)(void *ssl);
static void hook_SSL_free(void *ssl) {
    psLog(@"SSL_FREE", @"ssl=%p", ssl);
    orig_SSL_free(ssl);
}

// ╔════════════════════════════════════════════════════════════╗
// ║  SECTION 5: TRAFFIC LOGGER — AUTH LAYER                   ║
// ║  (Credentials, tokens, login events)                      ║
// ╚════════════════════════════════════════════════════════════╝

// PYRAuthenticationListenerImpl — login success/failure
%hook PYRAuthenticationListenerImpl
- (void)onLogin {
    psLog(@"AUTH", @"★ LOGIN SUCCESS ★");
    %orig;
}
- (void)onLoginError:(id)error loginAction:(id)action extAuthUrl:(id)url {
    psLog(@"AUTH", @"✗ LOGIN ERROR: error=%@ action=%@ url=%@", error, action, url);
    %orig;
}
- (void)onEventLimitedLoginMode {
    psLog(@"AUTH", @"⚠ LIMITED LOGIN MODE");
    %orig;
}
%end

// NSString AES encryption category — capture encrypted passwords
%hook NSString
- (id)toAES256EncryptWithKey:(id)key {
    psLog(@"CRYPTO", @"AES256 ENCRYPT: input=%@ key=%@", self, key);
    id result = %orig;
    psLog(@"CRYPTO", @"AES256 ENCRYPT result: %@", result);
    return result;
}
- (id)toAES256DecryptWithKey:(id)key {
    id result = %orig;
    psLog(@"CRYPTO", @"AES256 DECRYPT: key=%@ → result=%@", key, result);
    return result;
}
%end

// WKWebView script messages — JS bridge
%hook PYRWeakScriptMessageDelegate
- (void)userContentController:(id)controller didReceiveScriptMessage:(WKScriptMessage *)message {
    psLog(@"WEBVIEW", @"JS→Native: name=%@ body=%@", message.name, message.body);
    %orig;
}
%end

// WKWebView evaluateJavaScript — Native→JS
%hook WKWebView
- (void)evaluateJavaScript:(NSString *)js completionHandler:(void (^)(id, NSError *))handler {
    if (js.length > 0 && ([js containsString:@"updateAuth"] || [js containsString:@"starsweb"] || [js containsString:@"login"])) {
        psLog(@"WEBVIEW", @"Native→JS: %@", js.length > 500 ? [js substringToIndex:500] : js);
    }
    %orig;
}
%end

// ╔════════════════════════════════════════════════════════════╗
// ║  SECTION 6: TRAFFIC LOGGER — HTTP LAYER                   ║
// ║  (AFNetworking REST API calls + responses)                ║
// ╚════════════════════════════════════════════════════════════╝

%hook AFHTTPSessionManager
- (NSURLSessionDataTask *)dataTaskWithHTTPMethod:(NSString *)method
    URLString:(NSString *)URLString
    parameters:(id)parameters
    headers:(NSDictionary *)headers
    uploadProgress:(void (^)(NSProgress *))uploadProgress
    downloadProgress:(void (^)(NSProgress *))downloadProgress
    success:(void (^)(NSURLSessionDataTask *, id))success
    failure:(void (^)(NSURLSessionDataTask *, NSError *))failure {

    psLog(@"HTTP", @"→ %@ %@", method, URLString);
    if (parameters) psLog(@"HTTP", @"  params: %@", parameters);
    if (headers) psLog(@"HTTP", @"  headers: %@", headers);

    void (^wrappedSuccess)(NSURLSessionDataTask *, id) = ^(NSURLSessionDataTask *task, id resp) {
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)task.response;
        psLog(@"HTTP", @"← %@ %@ → %ld", method, URLString, (long)httpResp.statusCode);
        NSString *respStr = nil;
        if ([resp isKindOfClass:[NSDictionary class]] || [resp isKindOfClass:[NSArray class]]) {
            NSData *json = [NSJSONSerialization dataWithJSONObject:resp options:0 error:nil];
            respStr = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
        } else if ([resp isKindOfClass:[NSData class]]) {
            respStr = [[NSString alloc] initWithData:resp encoding:NSUTF8StringEncoding];
        }
        if (respStr) {
            if (respStr.length > 2000) respStr = [[respStr substringToIndex:2000] stringByAppendingString:@"..."];
            psLog(@"HTTP", @"  body: %@", respStr);
        }
        if (success) success(task, resp);
    };

    void (^wrappedFailure)(NSURLSessionDataTask *, NSError *) = ^(NSURLSessionDataTask *task, NSError *error) {
        psLog(@"HTTP", @"✗ %@ %@ → %@", method, URLString, error.localizedDescription);
        if (failure) failure(task, error);
    };

    return %orig(method, URLString, parameters, headers, uploadProgress, downloadProgress, wrappedSuccess, wrappedFailure);
}
%end

// ╔════════════════════════════════════════════════════════════╗
// ║  SECTION 7: TRAFFIC LOGGER — KEYCHAIN                     ║
// ║  (Token storage/retrieval)                                ║
// ╚════════════════════════════════════════════════════════════╝

// Hook SecItemAdd/SecItemCopyMatching to see token storage
%hookf(OSStatus, SecItemAdd, CFDictionaryRef attributes, CFTypeRef *result) {
    OSStatus ret = %orig;
    NSDictionary *dict = (__bridge NSDictionary *)attributes;
    NSString *svc = dict[(__bridge id)kSecAttrService];
    NSString *acct = dict[(__bridge id)kSecAttrAccount];
    if (svc || acct) {
        psLog(@"KEYCHAIN", @"ADD: service=%@ account=%@ → %d", svc, acct, (int)ret);
    }
    return ret;
}

%hookf(OSStatus, SecItemCopyMatching, CFDictionaryRef query, CFTypeRef *result) {
    OSStatus ret = %orig;
    NSDictionary *dict = (__bridge NSDictionary *)query;
    NSString *svc = dict[(__bridge id)kSecAttrService];
    NSString *acct = dict[(__bridge id)kSecAttrAccount];
    if (svc || acct) {
        psLog(@"KEYCHAIN", @"GET: service=%@ account=%@ → %d", svc, acct, (int)ret);
        if (ret == errSecSuccess && result && *result) {
            CFTypeRef val = *result;
            if (CFGetTypeID(val) == CFDataGetTypeID()) {
                NSData *d = (__bridge NSData *)val;
                NSString *str = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (str && str.length < 2000) {
                    psLog(@"KEYCHAIN", @"  value: %@", str);
                } else {
                    psLog(@"KEYCHAIN", @"  value: (%lu bytes)", (unsigned long)d.length);
                }
            }
        }
    }
    return ret;
}

// ╔════════════════════════════════════════════════════════════╗
// ║  SECTION 8: RUNTIME PATTERN HOOKS                         ║
// ║  (Bypass + Logging for dynamically discovered classes)     ║
// ╚════════════════════════════════════════════════════════════╝

static void hookRuntimePatterns(void) {
    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);

    for (unsigned int i = 0; i < classCount; i++) {
        NSString *className = NSStringFromClass(classes[i]);
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(classes[i], &methodCount);
        if (!methods) continue;

        for (unsigned int j = 0; j < methodCount; j++) {
            NSString *sel = NSStringFromSelector(method_getName(methods[j]));

            // === BYPASS: SSL/JB/Integrity ===
            if ([sel containsString:@"handleCertPinningFailed"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^(id s){}));
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
            else if ([sel containsString:@"isJailbroken"] || [sel containsString:@"isJailBroken"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^BOOL(id s){ return NO; }));
            }
            else if ([sel containsString:@"promptJailbrokenWarning"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^(id s){}));
            }
            else if ([sel isEqualToString:@"skipAdvancedJailbreakValidation"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^BOOL(id s){ return YES; }));
            }
            else if ([sel containsString:@"dataIntegrityCheck"] || [sel containsString:@"integrityViolation"]) {
                method_setImplementation(methods[j], imp_implementationWithBlock(^BOOL(id s){ return YES; }));
            }

            // === LOGGING: Auth selectors on Swift classes ===
            // MfLoginWithCredentialsViewController — catch login action
            if ([className containsString:@"LoginWithCredentials"] && [sel containsString:@"onPerformLogin"]) {
                psLog(@"INIT", @"Found login method: %@.%@", className, sel);
                // Can't easily swizzle with block due to unknown args, but logged for identification
            }

            // MfAuthenticator — catch login methods
            if ([className containsString:@"MfAuthenticator"]) {
                if ([sel containsString:@"loginWith"] || [sel containsString:@"login:password"] ||
                    [sel containsString:@"fetchIDPToken"] || [sel containsString:@"onIDPTokenChanged"]) {
                    psLog(@"INIT", @"Found auth method: %@.%@", className, sel);
                }
            }

            // MfIDPClient — catch token methods
            if ([className containsString:@"IDPClient"]) {
                if ([sel containsString:@"updateIDPToken"] || [sel containsString:@"Token"]) {
                    psLog(@"INIT", @"Found IDP method: %@.%@", className, sel);
                }
            }

            // GraphQL service logging
            if ([className containsString:@"GraphQL"] && [sel containsString:@"websocket"]) {
                psLog(@"INIT", @"Found GraphQL WS: %@.%@", className, sel);
            }

            // STOMP logging
            if ([className containsString:@"STOMP"] && ([sel containsString:@"send"] || [sel containsString:@"subscribe"])) {
                psLog(@"INIT", @"Found STOMP: %@.%@", className, sel);
            }
        }
        free(methods);
    }
    free(classes);
}

// Hook Swift auth classes via ObjC runtime names
static void hookSwiftAuthClasses(void) {
    // MfAuthenticator (_TtC12MfAppLibrary15MfAuthenticator)
    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);

    for (unsigned int i = 0; i < classCount; i++) {
        NSString *name = NSStringFromClass(classes[i]);

        // Hook MfAuthenticator login methods
        if ([name containsString:@"MfAuthenticator"]) {
            psLog(@"INIT", @"Hooking MfAuthenticator: %@", name);
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(classes[i], &mc);
            for (unsigned int j = 0; j < mc; j++) {
                SEL sel = method_getName(methods[j]);
                NSString *selStr = NSStringFromSelector(sel);

                // Hook loginWith:password: variants
                if ([selStr hasPrefix:@"loginWith"] && [selStr containsString:@"password"]) {
                    Method m = methods[j];
                    IMP origIMP = method_getImplementation(m);
                    NSUInteger argCount = [[selStr componentsSeparatedByString:@":"] count] - 1;

                    IMP newIMP = nil;
                    if (argCount == 2) {
                        newIMP = imp_implementationWithBlock(^(id self, id arg1, id arg2) {
                            psLog(@"AUTH", @"★ MfAuth.%@ arg1=%@ arg2=%@", selStr, arg1, arg2);
                            ((void(*)(id, SEL, id, id))origIMP)(self, sel, arg1, arg2);
                        });
                    } else if (argCount == 3) {
                        newIMP = imp_implementationWithBlock(^(id self, id arg1, id arg2, id arg3) {
                            psLog(@"AUTH", @"★ MfAuth.%@ arg1=%@ arg2=%@ arg3=%@", selStr, arg1, arg2, arg3);
                            ((void(*)(id, SEL, id, id, id))origIMP)(self, sel, arg1, arg2, arg3);
                        });
                    }
                    if (newIMP) {
                        method_setImplementation(m, newIMP);
                        psLog(@"INIT", @"Hooked(%lu): %@.%@", (unsigned long)argCount, name, selStr);
                    } else {
                        psLog(@"INIT", @"Skip(%lu): %@.%@", (unsigned long)argCount, name, selStr);
                    }
                }

                // Hook fetchIDPToken
                if ([selStr containsString:@"fetchIDPToken"]) {
                    psLog(@"INIT", @"Found fetchIDPToken: %@.%@", name, selStr);
                }
            }
            if (methods) free(methods);
        }

        // Hook MfIDPClient token updates
        if ([name containsString:@"IDPClient"]) {
            psLog(@"INIT", @"Hooking IDPClient: %@", name);
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(classes[i], &mc);
            for (unsigned int j = 0; j < mc; j++) {
                SEL sel = method_getName(methods[j]);
                NSString *selStr = NSStringFromSelector(sel);

                if ([selStr containsString:@"updateIDPToken"]) {
                    Method m = methods[j];
                    IMP origIMP = method_getImplementation(m);
                    NSUInteger argCount = [[selStr componentsSeparatedByString:@":"] count] - 1;

                    IMP newIMP = nil;
                    if (argCount == 1) {
                        newIMP = imp_implementationWithBlock(^(id self, id arg1) {
                            psLog(@"AUTH", @"★ IDP: %@ arg1=%@", selStr, arg1);
                            ((void(*)(id, SEL, id))origIMP)(self, sel, arg1);
                        });
                    } else if (argCount == 2) {
                        newIMP = imp_implementationWithBlock(^(id self, id arg1, id arg2) {
                            psLog(@"AUTH", @"★ IDP: %@ arg1=%@ arg2=%@", selStr, arg1, arg2);
                            ((void(*)(id, SEL, id, id))origIMP)(self, sel, arg1, arg2);
                        });
                    } else if (argCount == 3) {
                        newIMP = imp_implementationWithBlock(^(id self, id arg1, id arg2, id arg3) {
                            psLog(@"AUTH", @"★ IDP: %@ arg1=%@ arg2=%@ arg3=%@", selStr, arg1, arg2, arg3);
                            ((void(*)(id, SEL, id, id, id))origIMP)(self, sel, arg1, arg2, arg3);
                        });
                    }
                    if (newIMP) {
                        method_setImplementation(m, newIMP);
                        psLog(@"INIT", @"Hooked(%lu): %@.%@", (unsigned long)argCount, name, selStr);
                    } else {
                        psLog(@"INIT", @"Skip(%lu): %@.%@", (unsigned long)argCount, name, selStr);
                    }
                }
            }
            if (methods) free(methods);
        }

        // Hook MfLoginWithCredentialsViewController
        if ([name containsString:@"LoginWithCredentials"]) {
            psLog(@"INIT", @"Hooking LoginVC: %@", name);
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(classes[i], &mc);
            for (unsigned int j = 0; j < mc; j++) {
                SEL sel = method_getName(methods[j]);
                NSString *selStr = NSStringFromSelector(sel);

                if ([selStr containsString:@"onPerformLogin"] || [selStr containsString:@"performLogin"]) {
                    psLog(@"INIT", @"Found login action: %@.%@", name, selStr);
                }
            }
            if (methods) free(methods);
        }

        // Hook MfGraphQLService — log GraphQL operations
        if ([name containsString:@"GraphQLService"] && ![name containsString:@"Protocol"]) {
            psLog(@"INIT", @"Found GraphQLService: %@", name);
        }

        // Hook MfSTOMPClient — log STOMP frames
        if ([name containsString:@"STOMPClient"]) {
            psLog(@"INIT", @"Found STOMPClient: %@", name);
        }
    }
    free(classes);
}

// ╔════════════════════════════════════════════════════════════╗
// ║  SECTION 9: CONSTRUCTOR                                   ║
// ╚════════════════════════════════════════════════════════════╝

%ctor {
    @autoreleasepool {
        // Resolve MSHookFunction via dlsym BEFORE anything else
        initHookAPI();

        // Init logger
        initLogger();
        psLog(@"INIT", @"PokerStars Traffic Logger v2.1 loading...");
        psLog(@"INIT", @"Bundle: %@", [[NSBundle mainBundle] bundleIdentifier]);
        psLog(@"INIT", @"MSHookFunction: %s", _MSHookFn ? "RESOLVED" : "NOT FOUND");

        initJBPaths();
        %init;

        // C function hooks — anti-detection
        MSHookFunction((void *)access, (void *)hook_access, (void **)&orig_access);
        MSHookFunction((void *)stat, (void *)hook_stat, (void **)&orig_stat);
        MSHookFunction((void *)lstat, (void *)hook_lstat, (void **)&orig_lstat);
        MSHookFunction((void *)sysctl, (void *)hook_sysctl, (void **)&orig_sysctl);
        MSHookFunction((void *)_dyld_get_image_name, (void *)hook_dyld_name, (void **)&orig_dyld_name);
        void *ptrace_ptr = dlsym(RTLD_DEFAULT, "ptrace");
        if (ptrace_ptr) MSHookFunction(ptrace_ptr, (void *)hook_ptrace, (void **)&orig_ptrace);

        // OpenSSL bypass hooks
        void *fn;
        fn = dlsym(RTLD_DEFAULT, "X509_verify_cert");
        if (fn) { MSHookFunction(fn, (void *)hook_X509_verify_cert, (void **)&orig_X509_verify_cert); psLog(@"INIT", @"✓ X509_verify_cert"); }
        fn = dlsym(RTLD_DEFAULT, "X509_check_host");
        if (fn) { MSHookFunction(fn, (void *)hook_X509_check_host, (void **)&orig_X509_check_host); psLog(@"INIT", @"✓ X509_check_host"); }
        fn = dlsym(RTLD_DEFAULT, "X509_STORE_CTX_init");
        if (fn) { MSHookFunction(fn, (void *)hook_X509_STORE_CTX_init, (void **)&orig_X509_STORE_CTX_init); psLog(@"INIT", @"✓ X509_STORE_CTX_init"); }
        fn = dlsym(RTLD_DEFAULT, "SSL_get_verify_result");
        if (fn) { MSHookFunction(fn, (void *)hook_ssl_get_verify, (void **)&orig_ssl_get_verify); psLog(@"INIT", @"✓ SSL_get_verify_result"); }

        // ★ CRITICAL: SSL_read / SSL_write — captures ALL CommLib2a plaintext
        fn = dlsym(RTLD_DEFAULT, "SSL_read");
        if (fn) { MSHookFunction(fn, (void *)hook_SSL_read, (void **)&orig_SSL_read); psLog(@"INIT", @"★ SSL_read hooked — CommLib2a traffic capture active"); }
        fn = dlsym(RTLD_DEFAULT, "SSL_write");
        if (fn) { MSHookFunction(fn, (void *)hook_SSL_write, (void **)&orig_SSL_write); psLog(@"INIT", @"★ SSL_write hooked — CommLib2a traffic capture active"); }
        fn = dlsym(RTLD_DEFAULT, "SSL_new");
        if (fn) { MSHookFunction(fn, (void *)hook_SSL_new, (void **)&orig_SSL_new); psLog(@"INIT", @"✓ SSL_new"); }
        fn = dlsym(RTLD_DEFAULT, "SSL_free");
        if (fn) { MSHookFunction(fn, (void *)hook_SSL_free, (void **)&orig_SSL_free); psLog(@"INIT", @"✓ SSL_free"); }

        // Runtime hooks — DISABLED for crash bisect
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            // hookRuntimePatterns();
            // hookSwiftAuthClasses();
            psLog(@"INIT", @"Runtime hooks DISABLED (bisect mode)");
            psLog(@"INIT", @"═══ CORE HOOKS ACTIVE — Logging to /var/tmp/ps_traffic.log ═══");
        });

        psLog(@"INIT", @"Core hooks installed! Waiting for runtime hooks...");
    }
}
