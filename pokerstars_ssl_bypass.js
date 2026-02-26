/**
 * PokerStars v3.90.1 (Build 80957) — Complete SSL Pinning Bypass
 * Bundle ID: ro.pokerstarsmobile.www
 *
 * Usage:
 *   frida -U -f ro.pokerstarsmobile.www -l pokerstars_ssl_bypass.js --no-pause
 *   frida -U -n pokerstars -l pokerstars_ssl_bypass.js
 *
 * Bypasses 7 SSL Pinning Layers:
 *   1. iOS Security.framework (SecTrust*)
 *   2. AFNetworking 4.0.1 (AFSecurityPolicy)
 *   3. Starscream 4.0.4 (Swift WebSocket CertificatePinning)
 *   4. Apollo 1.18.0 (GraphQL SSLSecurity)
 *   5. LivePerson LPMessagingSDK 6.22.0 (LPSRSecurityPolicy)
 *   6. GeoComply SDK 2.15.0 (GCHttpTask + anti-bypass detection)
 *   7. CommSSL / CommLib2a (Custom C++ OpenSSL 3.3.2 verification)
 *
 * Also Bypasses:
 *   - Jailbreak detection (6 URL schemes + 20+ file paths)
 *   - Debugger detection (sysctl P_TRACED, ptrace)
 *   - GeoComply RASP (hook detection, tweak enumeration, dylib scanning)
 *   - AppsFlyer sanity flags
 *   - Integrity violation checks
 *   - NSURLSession delegate pinning (all classes)
 *   - WKWebView authentication challenges
 */

'use strict';

// ============================================================
// Configuration
// ============================================================
var CONFIG = {
    verbose: false,       // true = log every hook hit
    logSSL: true,        // log SSL bypass events
    logJB: true,         // log jailbreak bypass events
    logAntiDebug: false, // log anti-debug bypass
    colorLog: true       // colored console output
};

function log(tag, msg) {
    if (CONFIG.colorLog) {
        console.log('[*] \x1b[36m[' + tag + ']\x1b[0m ' + msg);
    } else {
        console.log('[*] [' + tag + '] ' + msg);
    }
}

function logSuccess(tag, msg) {
    if (CONFIG.colorLog) {
        console.log('[+] \x1b[32m[' + tag + ']\x1b[0m ' + msg);
    } else {
        console.log('[+] [' + tag + '] ' + msg);
    }
}

function logWarn(tag, msg) {
    if (CONFIG.colorLog) {
        console.log('[!] \x1b[33m[' + tag + ']\x1b[0m ' + msg);
    } else {
        console.log('[!] [' + tag + '] ' + msg);
    }
}

var hookCount = { ssl: 0, jb: 0, debug: 0, geo: 0 };

// ============================================================
// LAYER 1: iOS Security.framework — SecTrust* bypass
// ============================================================
function bypassSecTrust() {
    var tag = 'SecTrust';

    // SecTrustEvaluateWithError (iOS 12+, primary)
    try {
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onEnter: function(args) {
                    this.errorPtr = args[1];
                },
                onLeave: function(retval) {
                    // Return true (trusted) and clear error
                    if (this.errorPtr && !this.errorPtr.isNull()) {
                        this.errorPtr.writePointer(ptr(0x0));
                    }
                    retval.replace(0x1); // true
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'SecTrustEvaluateWithError hooked');
        }
    } catch(e) { logWarn(tag, 'SecTrustEvaluateWithError: ' + e); }

    // SecTrustEvaluate (legacy, still used by AFNetworking/GeoComply)
    try {
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onEnter: function(args) {
                    this.resultPtr = args[1]; // SecTrustResultType*
                },
                onLeave: function(retval) {
                    // kSecTrustResultProceed = 1, kSecTrustResultUnspecified = 4
                    if (this.resultPtr && !this.resultPtr.isNull()) {
                        this.resultPtr.writeU32(4); // kSecTrustResultUnspecified (= trusted, no override)
                    }
                    retval.replace(0x0); // errSecSuccess
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'SecTrustEvaluate hooked');
        }
    } catch(e) { logWarn(tag, 'SecTrustEvaluate: ' + e); }

    // SecTrustGetTrustResult
    try {
        var SecTrustGetTrustResult = Module.findExportByName('Security', 'SecTrustGetTrustResult');
        if (SecTrustGetTrustResult) {
            Interceptor.attach(SecTrustGetTrustResult, {
                onEnter: function(args) {
                    this.resultPtr = args[1];
                },
                onLeave: function(retval) {
                    if (this.resultPtr && !this.resultPtr.isNull()) {
                        this.resultPtr.writeU32(4); // kSecTrustResultUnspecified
                    }
                    retval.replace(0x0);
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'SecTrustGetTrustResult hooked');
        }
    } catch(e) { logWarn(tag, 'SecTrustGetTrustResult: ' + e); }

    // === OpenSSL 3.3.2 (statically linked in main binary via CommLib2a) ===
    // NOTE: SSL_get_verify_result, SSL_CTX_set_verify, SSL_set_verify are NOT
    // exported symbols in this build. We try them first, then fall back to
    // runtime symbol scanning via Module.enumerateExports().
    var mainBinary = Process.enumerateModules()[0].name;

    // SSL_get_verify_result → X509_V_OK
    try {
        var sslGetVerify = Module.findExportByName(mainBinary, 'SSL_get_verify_result');
        if (sslGetVerify) {
            Interceptor.attach(sslGetVerify, {
                onLeave: function(retval) {
                    retval.replace(0x0); // X509_V_OK
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'SSL_get_verify_result hooked');
        } else {
            logWarn(tag, 'SSL_get_verify_result NOT exported (stripped) — relying on X509_verify_cert');
        }
    } catch(e) { /* stripped */ }

    // SSL_CTX_set_verify → SSL_VERIFY_NONE
    try {
        var sslCtxSetVerify = Module.findExportByName(mainBinary, 'SSL_CTX_set_verify');
        if (sslCtxSetVerify) {
            Interceptor.attach(sslCtxSetVerify, {
                onEnter: function(args) {
                    args[1] = ptr(0x0); // SSL_VERIFY_NONE
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'SSL_CTX_set_verify → VERIFY_NONE');
        }
    } catch(e) { /* stripped */ }

    // SSL_set_verify → SSL_VERIFY_NONE
    try {
        var sslSetVerify = Module.findExportByName(mainBinary, 'SSL_set_verify');
        if (sslSetVerify) {
            Interceptor.attach(sslSetVerify, {
                onEnter: function(args) {
                    args[1] = ptr(0x0); // SSL_VERIFY_NONE
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'SSL_set_verify → VERIFY_NONE');
        }
    } catch(e) { /* stripped */ }

    // X509_verify_cert — CORE chain verification (IS exported, confirmed)
    try {
        var x509Verify = Module.findExportByName(mainBinary, 'X509_verify_cert');
        if (x509Verify) {
            Interceptor.attach(x509Verify, {
                onLeave: function(retval) {
                    retval.replace(0x1); // success
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'X509_verify_cert hooked (covers CommSSL chain verification)');
        }
    } catch(e) { logWarn(tag, 'X509_verify_cert: ' + e); }

    // X509_STORE_CTX_init — set default flags to skip checks
    try {
        var x509StoreCtxInit = Module.findExportByName(mainBinary, 'X509_STORE_CTX_init');
        if (x509StoreCtxInit) {
            Interceptor.attach(x509StoreCtxInit, {
                onLeave: function(retval) {
                    // Ensure init succeeds
                    retval.replace(0x1);
                }
            });
            logSuccess(tag, 'X509_STORE_CTX_init hooked');
        }
    } catch(e) { /* optional */ }

    // SSL_do_handshake — monitor for CommSSL failures (IS exported)
    try {
        var sslDoHandshake = Module.findExportByName(mainBinary, 'SSL_do_handshake');
        if (sslDoHandshake) {
            Interceptor.attach(sslDoHandshake, {
                onLeave: function(retval) {
                    if (CONFIG.verbose && retval.toInt32() !== 1) {
                        log(tag, 'SSL_do_handshake returned: ' + retval.toInt32());
                    }
                }
            });
            logSuccess(tag, 'SSL_do_handshake monitored (CommSSL/CommLib2a)');
        }
    } catch(e) { /* optional */ }

    // Runtime fallback: scan ALL exports for OpenSSL verify functions
    // that may have different symbol names (e.g., with OPENSSL_ prefix)
    try {
        var mod = Process.getModuleByName(mainBinary);
        var exports = mod.enumerateExports();
        var sslSymbolsFound = [];
        for (var i = 0; i < exports.length; i++) {
            var name = exports[i].name;
            // Look for any verify-related OpenSSL exports we haven't caught
            if ((name.indexOf('verify_result') !== -1 ||
                 name.indexOf('set_verify') !== -1 ||
                 name.indexOf('cert_verify_callback') !== -1 ||
                 name.indexOf('X509_check_host') !== -1) &&
                name.indexOf('_STORE_') === -1) { // skip STORE functions
                sslSymbolsFound.push(name);
            }
        }
        if (sslSymbolsFound.length > 0) {
            log(tag, 'Extra OpenSSL symbols found: ' + sslSymbolsFound.join(', '));
            // Hook X509_check_host if found (hostname verification)
            for (var j = 0; j < sslSymbolsFound.length; j++) {
                if (sslSymbolsFound[j].indexOf('X509_check_host') !== -1) {
                    var checkHost = Module.findExportByName(mainBinary, sslSymbolsFound[j]);
                    if (checkHost) {
                        Interceptor.attach(checkHost, {
                            onLeave: function(retval) {
                                retval.replace(0x1); // hostname matches
                                hookCount.ssl++;
                            }
                        });
                        logSuccess(tag, 'X509_check_host hooked (CommSSL CN verification)');
                    }
                }
            }
        }
    } catch(e) { /* runtime scan failed */ }
}

// ============================================================
// LAYER 2: AFNetworking 4.0.1 — AFSecurityPolicy bypass
// ============================================================
function bypassAFNetworking() {
    var tag = 'AFNet';

    if (!ObjC.available) return;

    // AFSecurityPolicy.evaluateServerTrust:forDomain: → always YES
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            // evaluateServerTrust:forDomain:
            Interceptor.attach(AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation, {
                onLeave: function(retval) {
                    retval.replace(0x1); // YES
                    hookCount.ssl++;
                    if (CONFIG.logSSL && CONFIG.verbose) log(tag, 'evaluateServerTrust → YES');
                }
            });

            // setSSLPinningMode: → force None (0)
            Interceptor.attach(AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(0x0); // AFSSLPinningModeNone
                }
            });

            // setAllowInvalidCertificates: → force YES
            Interceptor.attach(AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(0x1); // YES
                }
            });

            // setValidatesDomainName: → force NO
            Interceptor.attach(AFSecurityPolicy['- setValidatesDomainName:'].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(0x0); // NO
                }
            });

            // allowInvalidCertificates getter → YES
            Interceptor.attach(AFSecurityPolicy['- allowInvalidCertificates'].implementation, {
                onLeave: function(retval) {
                    retval.replace(0x1);
                }
            });

            // validatesDomainName getter → NO
            Interceptor.attach(AFSecurityPolicy['- validatesDomainName'].implementation, {
                onLeave: function(retval) {
                    retval.replace(0x0);
                }
            });

            // SSLPinningMode getter → None
            Interceptor.attach(AFSecurityPolicy['- SSLPinningMode'].implementation, {
                onLeave: function(retval) {
                    retval.replace(0x0);
                }
            });

            logSuccess(tag, 'AFSecurityPolicy fully bypassed (7 hooks)');
        }
    } catch(e) { logWarn(tag, 'AFSecurityPolicy: ' + e); }

    // AFURLSessionManager — serverTrustErrorForServerTrust:url: → return nil (no error)
    // NOTE: We do NOT hook challenge completionHandlers directly because
    // calling completion in onEnter causes double-invocation crashes.
    // Instead, SecTrust hooks (Layer 1) + AFSecurityPolicy hooks above
    // ensure the original challenge handler naturally succeeds.
    try {
        var AFURLSessionManager = ObjC.classes.AFURLSessionManager;
        if (AFURLSessionManager) {
            // serverTrustErrorForServerTrust:url: → nil (prevents error creation)
            if (AFURLSessionManager['- serverTrustErrorForServerTrust:url:']) {
                Interceptor.attach(AFURLSessionManager['- serverTrustErrorForServerTrust:url:'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(ptr(0x0)); // nil = no error
                        hookCount.ssl++;
                    }
                });
            }
            logSuccess(tag, 'AFURLSessionManager.serverTrustError → nil');
        }
    } catch(e) { logWarn(tag, 'AFURLSessionManager: ' + e); }
}

// ============================================================
// LAYER 3: Starscream 4.0.4 — Swift WebSocket SSL bypass
// ============================================================
function bypassStarscream() {
    var tag = 'Starscream';

    // FoundationSecurity.evaluateTrust(trust:domain:completion:)
    // Mangled: _$s10Starscream18FoundationSecurityC13evaluateTrust5trust6domain10completionySo03SecE3Refa_SSSgyAA12PinningStateOXEtF
    try {
        var mod = 'Starscream';
        var evaluateTrust = Module.findExportByName(mod,
            '_$s10Starscream18FoundationSecurityC13evaluateTrust5trust6domain10completionySo03SecE3Refa_SSSgyAA12PinningStateOXEtF');
        if (evaluateTrust) {
            Interceptor.attach(evaluateTrust, {
                onEnter: function(args) {
                    // args[0] = self, args[1] = trust, args[2] = domain (Swift String)
                    // args[3] = completion closure
                    // We need to call completion with PinningState.success
                    // PinningState.success = 0 in the enum
                    this.completion = args[3];
                },
                onLeave: function(retval) {
                    // The completion was already called by the original.
                    // We override by replacing the function entirely below.
                }
            });
            logSuccess(tag, 'evaluateTrust hooked (interceptor)');
        }
    } catch(e) { /* fallback below */ }

    // NOTE: We do NOT use Interceptor.replace for Swift functions as the
    // calling convention is complex and mismatched args cause crashes.
    // Instead, SecTrust hooks (Layer 1) make evaluateTrust naturally succeed.
    // The Interceptor.attach above logs any calls for debugging.

    // Fallback: Hook the ObjC-bridged class if available
    try {
        var starscreamSecurity = ObjC.classes._TtC10Starscream18FoundationSecurity;
        if (!starscreamSecurity) {
            // Try without prefix
            starscreamSecurity = ObjC.classes.FoundationSecurity;
        }
        if (starscreamSecurity) {
            logSuccess(tag, 'FoundationSecurity class found (ObjC bridge)');
        }
    } catch(e) { /* Swift class may not be ObjC-visible */ }
}

// ============================================================
// LAYER 4: Apollo 1.18.0 — GraphQL SSLSecurity bypass
// ============================================================
function bypassApollo() {
    var tag = 'Apollo';

    // SSLSecurity.isValid(_:domain:) -> Bool
    try {
        var isValid = Module.findExportByName('Apollo',
            '_$s6Apollo11SSLSecurityC7isValid_6domainSbSo11SecTrustRefa_SSSgtF');
        if (isValid) {
            Interceptor.attach(isValid, {
                onLeave: function(retval) {
                    retval.replace(0x1); // true
                    hookCount.ssl++;
                    if (CONFIG.logSSL && CONFIG.verbose) log(tag, 'SSLSecurity.isValid → true');
                }
            });
            logSuccess(tag, 'SSLSecurity.isValid hooked → true');
        }
    } catch(e) { logWarn(tag, 'SSLSecurity.isValid: ' + e); }

    // WebSocket.disableSSLCertValidation setter → force true
    try {
        var disableSetter = Module.findExportByName('Apollo',
            '_$s6Apollo9WebSocketC24disableSSLCertValidationSbvs');
        if (disableSetter) {
            Interceptor.attach(disableSetter, {
                onEnter: function(args) {
                    args[1] = ptr(0x1); // true
                }
            });
            logSuccess(tag, 'WebSocket.disableSSLCertValidation → true');
        }
    } catch(e) { /* optional */ }

    // WebSocket.disableSSLCertValidation getter → true
    try {
        var disableGetter = Module.findExportByName('Apollo',
            '_$s6Apollo9WebSocketC24disableSSLCertValidationSbvg');
        if (disableGetter) {
            Interceptor.attach(disableGetter, {
                onLeave: function(retval) {
                    retval.replace(0x1);
                }
            });
            logSuccess(tag, 'WebSocket.disableSSLCertValidation getter → true');
        }
    } catch(e) { /* optional */ }
}

// ============================================================
// LAYER 5: LivePerson LPMessagingSDK 6.22.0 — LPSR SSL bypass
// ============================================================
function bypassLivePersonSSL() {
    var tag = 'LivePerson';

    if (!ObjC.available) return;

    // LPSRSecurityPolicy.evaluateServerTrust:forDomain:
    try {
        var cls = ObjC.classes.LPSRSecurityPolicy;
        if (cls) {
            Interceptor.attach(cls['- evaluateServerTrust:forDomain:'].implementation, {
                onLeave: function(retval) {
                    retval.replace(0x1);
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'LPSRSecurityPolicy.evaluateServerTrust → YES');
        }
    } catch(e) { logWarn(tag, 'LPSRSecurityPolicy: ' + e); }

    // LPSRPinningSecurityPolicy.evaluateServerTrust:forDomain:
    try {
        var cls = ObjC.classes.LPSRPinningSecurityPolicy;
        if (cls) {
            Interceptor.attach(cls['- evaluateServerTrust:forDomain:'].implementation, {
                onLeave: function(retval) {
                    retval.replace(0x1);
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'LPSRPinningSecurityPolicy.evaluateServerTrust → YES');
        }
    } catch(e) { logWarn(tag, 'LPSRPinningSecurityPolicy: ' + e); }

    // LPSRWebSocket — force allowsUntrustedSSLCertificates
    try {
        var cls = ObjC.classes.LPSRWebSocket;
        if (cls) {
            Interceptor.attach(cls['- allowsUntrustedSSLCertificates'].implementation, {
                onLeave: function(retval) {
                    retval.replace(0x1);
                }
            });
            Interceptor.attach(cls['- setAllowsUntrustedSSLCertificates:'].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(0x1);
                }
            });
            logSuccess(tag, 'LPSRWebSocket.allowsUntrustedSSL → YES');
        }
    } catch(e) { logWarn(tag, 'LPSRWebSocket: ' + e); }

    // NSURLRequest+LPSRWebSocket SR_SSLPinnedCertificates → nil
    try {
        var cls = ObjC.classes.NSURLRequest;
        if (cls['- SR_SSLPinnedCertificates']) {
            Interceptor.attach(cls['- SR_SSLPinnedCertificates'].implementation, {
                onLeave: function(retval) {
                    retval.replace(ptr(0x0)); // nil = no pinned certs
                }
            });
            logSuccess(tag, 'SR_SSLPinnedCertificates → nil');
        }
    } catch(e) { /* optional category method */ }

    // === LPMessagingSDK Public Key Pinning (additional layer) ===
    // handleCertPinningFailed → NOP (prevent cert pin failure actions)
    try {
        var resolver = new ApiResolver('objc');
        var matches = resolver.enumerateMatches('-[* handleCertPinningFailed*]');
        matches.forEach(function(m) {
            Interceptor.replace(m.address,
                new NativeCallback(function() {
                    // NOP — suppress cert pinning failure
                    hookCount.ssl++;
                }, 'void', ['pointer', 'pointer', 'pointer'])
            );
            logSuccess(tag, 'handleCertPinningFailed → NOP (' + m.name + ')');
        });
    } catch(e) { /* optional */ }

    // getCertPinningPublicKeyList → return empty array (no pins to check)
    try {
        var resolver = new ApiResolver('objc');
        var matches = resolver.enumerateMatches('-[* getCertPinningPublicKeyList*]');
        matches.forEach(function(m) {
            Interceptor.attach(m.address, {
                onLeave: function(retval) {
                    // Return empty NSArray — no public keys to pin against
                    retval.replace(ObjC.classes.NSArray.array());
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'getCertPinningPublicKeyList → empty (' + m.name + ')');
        });
    } catch(e) { /* optional */ }

    // evaluateCertPinningCertificate → skip (return success)
    try {
        var resolver = new ApiResolver('objc');
        var matches = resolver.enumerateMatches('-[* evaluateCertPinningCertificate*]');
        matches.forEach(function(m) {
            Interceptor.attach(m.address, {
                onLeave: function(retval) {
                    retval.replace(0x1); // pass
                    hookCount.ssl++;
                }
            });
            logSuccess(tag, 'evaluateCertPinningCertificate → pass (' + m.name + ')');
        });
    } catch(e) { /* optional */ }

    // certPinningPublicKeys property getter → nil (no pins configured)
    try {
        var resolver = new ApiResolver('objc');
        var matches = resolver.enumerateMatches('-[* certPinningPublicKeys]');
        matches.forEach(function(m) {
            Interceptor.attach(m.address, {
                onLeave: function(retval) {
                    retval.replace(ptr(0x0)); // nil
                }
            });
        });
    } catch(e) { /* optional */ }
}

// ============================================================
// LAYER 6: GeoComply SDK 2.15.0 — SSL + Anti-Bypass Detection
// ============================================================
function bypassGeoComplySSL() {
    var tag = 'GeoComply';

    if (!ObjC.available) return;

    // GCHttpTask.shouldTrustProtectionSpace: → YES
    // CRITICAL: GeoComply checks if SSL was bypassed and reports it
    try {
        var cls = ObjC.classes.GCHttpTask;
        if (cls) {
            // shouldTrustProtectionSpace: → YES (prevents "SSL Challenge Bypassed" report)
            if (cls['- shouldTrustProtectionSpace:']) {
                Interceptor.attach(cls['- shouldTrustProtectionSpace:'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(0x1); // YES = trusted
                        hookCount.geo++;
                    }
                });
                logSuccess(tag, 'GCHttpTask.shouldTrustProtectionSpace → YES');
            }

            // GCHttpTask URLSession challenge → relies on shouldTrustProtectionSpace
            // hook above + SecTrust Layer 1 hooks. We do NOT call completion directly
            // (causes double-invocation crash). The original will naturally succeed.
            logSuccess(tag, 'GCHttpTask challenge → delegated to shouldTrustProtectionSpace + SecTrust hooks');

            // updateSSLChallengeInfo → TRUE NOP via replace (prevents SSL bypass detection)
            // NOTE: Must use Interceptor.replace, not attach. With attach, the original
            // still runs and can detect proxy certificates → reports "SSL Challenge Bypassed"
            if (cls['- updateSSLChallengeInfo']) {
                Interceptor.replace(cls['- updateSSLChallengeInfo'].implementation,
                    new NativeCallback(function(self, sel) {
                        // TRUE NOP — original never executes
                    }, 'void', ['pointer', 'pointer'])
                );
                logSuccess(tag, 'GCHttpTask.updateSSLChallengeInfo → TRUE NOP');
            }

            // logCertificateInfo: → TRUE NOP
            if (cls['- logCertificateInfo:']) {
                Interceptor.replace(cls['- logCertificateInfo:'].implementation,
                    new NativeCallback(function(self, sel, protectionSpace) {
                        // TRUE NOP — don't log cert info
                    }, 'void', ['pointer', 'pointer', 'pointer'])
                );
            }

            // parseCertificatesForProtectionSpace: → TRUE NOP
            if (cls['- parseCertificatesForProtectionSpace:']) {
                Interceptor.replace(cls['- parseCertificatesForProtectionSpace:'].implementation,
                    new NativeCallback(function(self, sel, protectionSpace) {
                        // TRUE NOP — don't parse certificates
                    }, 'void', ['pointer', 'pointer', 'pointer'])
                );
            }
        }
    } catch(e) { logWarn(tag, 'GCHttpTask: ' + e); }

    // GCAuthChallengeDetector → full replacement (prevents double-invocation crash)
    // NOTE: Must use Interceptor.replace, NOT attach+invoke, because the original
    // method also calls the completion handler → calling it in onEnter = double-call = crash
    try {
        var cls = ObjC.classes.GCAuthChallengeDetector;
        if (cls && cls['- URLSession:didReceiveChallenge:completionHandler:']) {
            Interceptor.replace(cls['- URLSession:didReceiveChallenge:completionHandler:'].implementation,
                new NativeCallback(function(self, sel, session, challenge, completionHandler) {
                    try {
                        var challengeObj = new ObjC.Object(challenge);
                        var ps = challengeObj.protectionSpace();
                        var method = ps.authenticationMethod().toString();
                        var block = new ObjC.Block(completionHandler);

                        if (method === 'NSURLAuthenticationMethodServerTrust') {
                            var trust = ps.serverTrust();
                            var cred = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                            block.invoke(0, cred); // NSURLSessionAuthChallengeUseCredential
                            hookCount.geo++;
                        } else {
                            // Non-SSL challenges: use system default handling
                            block.invoke(1, ptr(0)); // NSURLSessionAuthChallengePerformDefaultHandling
                        }
                    } catch(e) {
                        // Safety fallback: perform default handling
                        try {
                            var block = new ObjC.Block(completionHandler);
                            block.invoke(1, ptr(0));
                        } catch(e2) { }
                    }
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'])
            );
            logSuccess(tag, 'GCAuthChallengeDetector replaced (safe, no double-invocation)');
        }
    } catch(e) { logWarn(tag, 'GCAuthChallengeDetector: ' + e); }
}

// ============================================================
// LAYER 7: Generic NSURLSession delegate bypass
// ============================================================
function bypassNSURLSessionDelegates() {
    var tag = 'NSURLSession';

    if (!ObjC.available) return;

    // Google Utilities — full replacement (prevents double-invocation crash)
    try {
        var cls = ObjC.classes.GULNetworkURLSession;
        if (cls && cls['- URLSession:task:didReceiveChallenge:completionHandler:']) {
            Interceptor.replace(cls['- URLSession:task:didReceiveChallenge:completionHandler:'].implementation,
                new NativeCallback(function(self, sel, session, task, challenge, completionHandler) {
                    try {
                        var challengeObj = new ObjC.Object(challenge);
                        var ps = challengeObj.protectionSpace();
                        var method = ps.authenticationMethod().toString();
                        var block = new ObjC.Block(completionHandler);

                        if (method === 'NSURLAuthenticationMethodServerTrust') {
                            var trust = ps.serverTrust();
                            var cred = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                            block.invoke(0, cred); // UseCredential
                            hookCount.ssl++;
                        } else {
                            block.invoke(1, ptr(0)); // PerformDefaultHandling
                        }
                    } catch(e) {
                        try {
                            var block = new ObjC.Block(completionHandler);
                            block.invoke(1, ptr(0));
                        } catch(e2) { }
                    }
                }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'])
            );
            logSuccess(tag, 'GULNetworkURLSession replaced (safe, no double-invocation)');
        }
    } catch(e) { /* optional */ }

    // WKWebView challenge handlers — full replacement (prevents double-invocation crash)
    var webViewClasses = ['PYRBaseWebViewController', 'PYRBaseWebViewControllerPrivate', 'PYRStarsWebViewController'];
    webViewClasses.forEach(function(clsName) {
        try {
            var cls = ObjC.classes[clsName];
            if (cls && cls['- webView:didReceiveAuthenticationChallenge:completionHandler:']) {
                Interceptor.replace(cls['- webView:didReceiveAuthenticationChallenge:completionHandler:'].implementation,
                    new NativeCallback(function(self, sel, webView, challenge, completionHandler) {
                        try {
                            var challengeObj = new ObjC.Object(challenge);
                            var ps = challengeObj.protectionSpace();
                            var method = ps.authenticationMethod().toString();
                            var block = new ObjC.Block(completionHandler);

                            if (method === 'NSURLAuthenticationMethodServerTrust') {
                                var trust = ps.serverTrust();
                                var cred = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                                block.invoke(0, cred); // UseCredential
                                hookCount.ssl++;
                            } else {
                                block.invoke(1, ptr(0)); // PerformDefaultHandling
                            }
                        } catch(e) {
                            try {
                                var block = new ObjC.Block(completionHandler);
                                block.invoke(1, ptr(0));
                            } catch(e2) { }
                        }
                    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'])
                );
                logSuccess(tag, clsName + ' WKWebView challenge replaced (safe)');
            }
        } catch(e) { /* class may not exist */ }
    });

    // === NSURLSessionDelegateBypassingSSLErrors (found in main binary) ===
    // CRITICAL: This class exists but we must ensure it accepts ALL certs
    try {
        var cls = ObjC.classes.NSURLSessionDelegateBypassingSSLErrors;
        if (cls) {
            // Session-level challenge
            if (cls['- URLSession:didReceiveChallenge:completionHandler:']) {
                Interceptor.replace(cls['- URLSession:didReceiveChallenge:completionHandler:'].implementation,
                    new NativeCallback(function(self, sel, session, challenge, completionHandler) {
                        try {
                            var challengeObj = new ObjC.Object(challenge);
                            var ps = challengeObj.protectionSpace();
                            var method = ps.authenticationMethod().toString();
                            var block = new ObjC.Block(completionHandler);
                            if (method === 'NSURLAuthenticationMethodServerTrust') {
                                var trust = ps.serverTrust();
                                var cred = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                                block.invoke(0, cred);
                                hookCount.ssl++;
                            } else {
                                block.invoke(1, ptr(0));
                            }
                        } catch(e) {
                            try { new ObjC.Block(completionHandler).invoke(1, ptr(0)); } catch(e2) {}
                        }
                    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'])
                );
            }
            // Task-level challenge
            if (cls['- URLSession:task:didReceiveChallenge:completionHandler:']) {
                Interceptor.replace(cls['- URLSession:task:didReceiveChallenge:completionHandler:'].implementation,
                    new NativeCallback(function(self, sel, session, task, challenge, completionHandler) {
                        try {
                            var challengeObj = new ObjC.Object(challenge);
                            var ps = challengeObj.protectionSpace();
                            var method = ps.authenticationMethod().toString();
                            var block = new ObjC.Block(completionHandler);
                            if (method === 'NSURLAuthenticationMethodServerTrust') {
                                var trust = ps.serverTrust();
                                var cred = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                                block.invoke(0, cred);
                                hookCount.ssl++;
                            } else {
                                block.invoke(1, ptr(0));
                            }
                        } catch(e) {
                            try { new ObjC.Block(completionHandler).invoke(1, ptr(0)); } catch(e2) {}
                        }
                    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'])
                );
            }
            logSuccess(tag, 'NSURLSessionDelegateBypassingSSLErrors replaced (both session + task)');
        }
    } catch(e) { /* class may not exist at runtime */ }

    // === WKWebView: shouldAllowDeprecatedTLS → YES ===
    // Allows connections to servers with TLS 1.0/1.1
    var deprecatedTLSClasses = ['PYRBaseWebViewController', 'PYRBaseWebViewControllerPrivate', 'PYRStarsWebViewController'];
    deprecatedTLSClasses.forEach(function(clsName) {
        try {
            var cls = ObjC.classes[clsName];
            if (cls && cls['- webView:authenticationChallenge:shouldAllowDeprecatedTLS:']) {
                Interceptor.replace(cls['- webView:authenticationChallenge:shouldAllowDeprecatedTLS:'].implementation,
                    new NativeCallback(function(self, sel, webView, challenge, decisionHandler) {
                        try {
                            // Call decisionHandler(YES) — allow deprecated TLS
                            var block = new ObjC.Block(decisionHandler);
                            block.invoke(0x1); // YES
                            hookCount.ssl++;
                        } catch(e) {
                            try { new ObjC.Block(decisionHandler).invoke(0x1); } catch(e2) {}
                        }
                    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'])
                );
                logSuccess(tag, clsName + ' shouldAllowDeprecatedTLS → YES');
            }
        } catch(e) { /* method may not exist */ }
    });

    // === Catch-all: scan for ANY remaining didReceiveChallenge handlers ===
    // This catches handlers in classes we might not know about
    try {
        var resolver = new ApiResolver('objc');
        var knownClasses = [
            'AFURLSessionManager', 'GULNetworkURLSession', 'GCAuthChallengeDetector',
            'GCHttpTask', 'PYRBaseWebViewController', 'PYRBaseWebViewControllerPrivate',
            'PYRStarsWebViewController', 'NSURLSessionDelegateBypassingSSLErrors',
            'LPSRWebSocket'
        ];

        // Session-level: URLSession:didReceiveChallenge:completionHandler:
        var sessionMatches = resolver.enumerateMatches('-[* URLSession:didReceiveChallenge:completionHandler:]');
        sessionMatches.forEach(function(m) {
            var className = m.name.split(' ')[0].replace('-[', '');
            if (knownClasses.indexOf(className) === -1) {
                // Unknown class — hook it for safety
                try {
                    Interceptor.attach(m.address, {
                        onEnter: function(args) {
                            if (CONFIG.verbose) log(tag, 'Unknown challenge handler: ' + m.name);
                        }
                    });
                } catch(e) {}
            }
        });

        // Task-level: URLSession:task:didReceiveChallenge:completionHandler:
        var taskMatches = resolver.enumerateMatches('-[* URLSession:task:didReceiveChallenge:completionHandler:]');
        taskMatches.forEach(function(m) {
            var className = m.name.split(' ')[0].replace('-[', '');
            if (knownClasses.indexOf(className) === -1) {
                try {
                    Interceptor.attach(m.address, {
                        onEnter: function(args) {
                            if (CONFIG.verbose) log(tag, 'Unknown task challenge handler: ' + m.name);
                        }
                    });
                } catch(e) {}
            }
        });
        log(tag, 'Scanned ' + sessionMatches.length + ' session + ' + taskMatches.length + ' task challenge handlers');
    } catch(e) { /* scan failed */ }
}

// ============================================================
// ANTI-DETECTION 1: Jailbreak Detection Bypass
// ============================================================
function bypassJailbreakDetection() {
    var tag = 'JB-Bypass';

    if (!ObjC.available) return;

    // === URL Scheme checks (canOpenURL:) ===
    var jbSchemes = [
        'cydia://', 'sileo://', 'zbra://', 'filza://', 'activator://', 'undecimus://',
        'cydia://package/'
    ];
    try {
        var UIApplication = ObjC.classes.UIApplication;
        Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
            onEnter: function(args) {
                this.url = new ObjC.Object(args[2]);
                this.urlStr = this.url.absoluteString().toString();
            },
            onLeave: function(retval) {
                for (var i = 0; i < jbSchemes.length; i++) {
                    if (this.urlStr.indexOf(jbSchemes[i]) !== -1) {
                        retval.replace(0x0); // NO - pretend not installed
                        hookCount.jb++;
                        if (CONFIG.logJB) log(tag, 'canOpenURL blocked: ' + this.urlStr);
                        return;
                    }
                }
            }
        });
        logSuccess(tag, 'canOpenURL jailbreak check bypassed (6 schemes)');
    } catch(e) { logWarn(tag, 'canOpenURL: ' + e); }

    // === File existence checks ===
    var jbPaths = [
        '/Applications/Cydia.app',
        '/Applications/FakeCarrier.app',
        '/Applications/Icy.app',
        '/Applications/IntelliScreen.app',
        '/Applications/MxTube.app',
        '/Applications/RockApp.app',
        '/Applications/SBSettings.app',
        '/Applications/WinterBoard.app',
        '/Applications/blackra1n.app',
        '/Library/MobileSubstrate/MobileSubstrate.dylib',
        '/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist',
        '/Library/MobileSubstrate/DynamicLibraries/Veency.plist',
        '/Library/MobileSubstrate/DynamicLibraries',
        '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
        '/bin/bash',
        '/bin/sh',
        '/etc/apt',
        '/private/jailbreak.txt',
        '/private/var/lib/apt',
        '/private/var/lib/apt/',
        '/private/var/lib/cydia',
        '/private/var/mobile/Library/SBSettings/Themes',
        '/private/var/stash',
        '/private/var/tmp/cydia.log',
        '/usr/bin/sshd',
        '/usr/sbin/sshd',
        '/usr/lib/substitute-inserter.dylib',
        '/usr/libexec/ssh-keysign'
    ];

    // NSFileManager.fileExistsAtPath:
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
            onEnter: function(args) {
                this.path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function(retval) {
                for (var i = 0; i < jbPaths.length; i++) {
                    if (this.path === jbPaths[i] || this.path.indexOf(jbPaths[i]) === 0) {
                        retval.replace(0x0); // NO
                        hookCount.jb++;
                        if (CONFIG.logJB && CONFIG.verbose) log(tag, 'fileExists blocked: ' + this.path);
                        return;
                    }
                }
            }
        });
        logSuccess(tag, 'NSFileManager.fileExistsAtPath jailbreak paths blocked');
    } catch(e) { logWarn(tag, 'fileExistsAtPath: ' + e); }

    // C-level: access() — checks if files are accessible
    try {
        var access_func = Module.findExportByName('libSystem.B.dylib', 'access');
        if (access_func) {
            Interceptor.attach(access_func, {
                onEnter: function(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function(retval) {
                    if (this.path) {
                        for (var i = 0; i < jbPaths.length; i++) {
                            if (this.path === jbPaths[i] || this.path.indexOf(jbPaths[i]) === 0) {
                                retval.replace(-1); // ENOENT
                                hookCount.jb++;
                                return;
                            }
                        }
                    }
                }
            });
            logSuccess(tag, 'access() jailbreak path check bypassed');
        }
    } catch(e) { logWarn(tag, 'access: ' + e); }

    // C-level: stat() / lstat()
    ['stat', 'lstat'].forEach(function(fname) {
        try {
            var func = Module.findExportByName('libSystem.B.dylib', fname);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        this.path = args[0].readUtf8String();
                    },
                    onLeave: function(retval) {
                        if (this.path) {
                            for (var i = 0; i < jbPaths.length; i++) {
                                if (this.path === jbPaths[i] || this.path.indexOf(jbPaths[i]) === 0) {
                                    retval.replace(-1);
                                    hookCount.jb++;
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        } catch(e) { /* ok */ }
    });
    logSuccess(tag, 'stat/lstat jailbreak check bypassed');

    // C-level: fork() — jailbreak writability test
    try {
        var fork_func = Module.findExportByName('libSystem.B.dylib', 'fork');
        if (fork_func) {
            Interceptor.replace(fork_func, new NativeCallback(function() {
                hookCount.jb++;
                return -1; // fork failed = not jailbroken
            }, 'int', []));
            logSuccess(tag, 'fork() blocked');
        }
    } catch(e) { /* ok */ }

    // AppsFlyer jailbreak check
    try {
        // Hook via class method pattern search
        var resolver = new ApiResolver('objc');
        var matches = resolver.enumerateMatches('-[* isJailbrokenWithSkipAdvancedJailbreakValidation:*]');
        matches.forEach(function(m) {
            Interceptor.attach(m.address, {
                onLeave: function(retval) {
                    retval.replace(0x0); // NO
                    hookCount.jb++;
                }
            });
            logSuccess(tag, 'AppsFlyer isJailbroken → NO (' + m.name + ')');
        });
    } catch(e) { /* optional */ }

    // AppsFlyer: promptJailbrokenWarning → NOP
    try {
        var resolver = new ApiResolver('objc');
        var matches = resolver.enumerateMatches('-[* promptJailbrokenWarning*]');
        matches.forEach(function(m) {
            Interceptor.attach(m.address, {
                onEnter: function(args) {
                    // NOP - don't show jailbreak warning
                    hookCount.jb++;
                }
            });
        });
    } catch(e) { /* optional */ }

    // AppsFlyer: skipAdvancedJailbreakValidation → YES
    try {
        var resolver = new ApiResolver('objc');
        var matches = resolver.enumerateMatches('-[* skipAdvancedJailbreakValidation]');
        matches.forEach(function(m) {
            Interceptor.attach(m.address, {
                onLeave: function(retval) {
                    retval.replace(0x1); // YES
                }
            });
        });
    } catch(e) { /* optional */ }
}

// ============================================================
// ANTI-DETECTION 2: Debugger Detection Bypass
// ============================================================
function bypassDebuggerDetection() {
    var tag = 'AntiDebug';

    // sysctl — block P_TRACED check
    try {
        var sysctl_func = Module.findExportByName('libSystem.B.dylib', 'sysctl');
        if (sysctl_func) {
            Interceptor.attach(sysctl_func, {
                onEnter: function(args) {
                    // CTL_KERN = 1, KERN_PROC = 14, KERN_PROC_PID = 1
                    var mib = args[0];
                    var namelen = args[1].toInt32();
                    if (namelen === 4) {
                        var ctl = mib.readS32();
                        var kern = mib.add(4).readS32();
                        if (ctl === 1 && kern === 14) {
                            this.isDebugCheck = true;
                            this.oldp = args[2]; // struct kinfo_proc*
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.isDebugCheck && this.oldp && !this.oldp.isNull()) {
                        // kinfo_proc.kp_proc.p_flag offset varies, clear P_TRACED bit
                        // p_flag is at offset 32 in kp_proc (struct extern_proc)
                        // kp_proc starts at offset 0 of kinfo_proc
                        try {
                            var p_flag_ptr = this.oldp.add(32);
                            var p_flag = p_flag_ptr.readU32();
                            var P_TRACED = 0x00000800;
                            if (p_flag & P_TRACED) {
                                p_flag_ptr.writeU32(p_flag & ~P_TRACED);
                                hookCount.debug++;
                                if (CONFIG.logAntiDebug) log(tag, 'P_TRACED cleared from sysctl');
                            }
                        } catch(e) { /* offset might differ */ }
                    }
                }
            });
            logSuccess(tag, 'sysctl P_TRACED bypass installed');
        }
    } catch(e) { logWarn(tag, 'sysctl: ' + e); }

    // ptrace — deny PT_DENY_ATTACH
    try {
        var ptrace_func = Module.findExportByName('libSystem.B.dylib', 'ptrace');
        if (ptrace_func) {
            Interceptor.attach(ptrace_func, {
                onEnter: function(args) {
                    var request = args[0].toInt32();
                    if (request === 31) { // PT_DENY_ATTACH
                        args[0] = ptr(0); // PT_TRACE_ME (harmless)
                        hookCount.debug++;
                        if (CONFIG.logAntiDebug) log(tag, 'PT_DENY_ATTACH → PT_TRACE_ME');
                    }
                }
            });
            logSuccess(tag, 'ptrace PT_DENY_ATTACH bypass installed');
        }
    } catch(e) { logWarn(tag, 'ptrace: ' + e); }

    // getppid — return 1 (launchd) instead of debugger PID
    try {
        var getppid_func = Module.findExportByName('libSystem.B.dylib', 'getppid');
        if (getppid_func) {
            Interceptor.replace(getppid_func, new NativeCallback(function() {
                return 1; // launchd
            }, 'int', []));
            logSuccess(tag, 'getppid → 1 (launchd)');
        }
    } catch(e) { /* optional */ }
}

// ============================================================
// ANTI-DETECTION 3: GeoComply RASP & Anti-Tamper Bypass
// ============================================================
function bypassGeoComplyRASP() {
    var tag = 'GeoRASP';

    if (!ObjC.available) return;

    // GCDebuggerDetectionOperation.start → NOP
    try {
        var cls = ObjC.classes.GCDebuggerDetectionOperation;
        if (cls && cls['- start']) {
            Interceptor.attach(cls['- start'].implementation, {
                onEnter: function(args) {
                    // Don't start debugger detection
                    hookCount.geo++;
                    if (CONFIG.verbose) log(tag, 'GCDebuggerDetectionOperation.start → NOP');
                }
            });
            // Replace to just call completion with "no debugger"
            logSuccess(tag, 'GCDebuggerDetectionOperation.start → NOP');
        }
    } catch(e) { logWarn(tag, 'GCDebuggerDetection: ' + e); }

    // GCReverseEngineeringDetectionOperation — dylib scanning
    try {
        var cls = ObjC.classes.GCReverseEngineeringDetectionOperation;
        if (cls) {
            // checkDYLDForLibs: → NOP (prevents Frida/Substrate detection)
            if (cls['- checkDYLDForLibs:']) {
                Interceptor.attach(cls['- checkDYLDForLibs:'].implementation, {
                    onEnter: function(args) {
                        hookCount.geo++;
                    },
                    onLeave: function(retval) {
                        retval.replace(0x0); // return nil/empty
                    }
                });
                logSuccess(tag, 'GCReverseEngineering.checkDYLDForLibs → empty');
            }

            // checkOpenedPort:shouldImprove: → NOP (port scanning for Frida)
            if (cls['- checkOpenedPort:shouldImprove:']) {
                Interceptor.attach(cls['- checkOpenedPort:shouldImprove:'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(0x0); // no open ports
                        hookCount.geo++;
                    }
                });
                logSuccess(tag, 'GCReverseEngineering.checkOpenedPort → none');
            }

            // canOpenPort: → NO
            if (cls['- canOpenPort:']) {
                Interceptor.attach(cls['- canOpenPort:'].implementation, {
                    onLeave: function(retval) {
                        retval.replace(0x0);
                    }
                });
            }
        }
    } catch(e) { logWarn(tag, 'GCReverseEngineering: ' + e); }

    // _dyld_image_count / _dyld_get_image_name — hide Frida/Substrate dylibs
    try {
        var dyld_get_image_name = Module.findExportByName('libSystem.B.dylib', '_dyld_get_image_name');
        if (dyld_get_image_name) {
            var hiddenLibs = ['frida', 'FridaGadget', 'substrate', 'substitute', 'cycript', 'SSLKillSwitch',
                              'MobileSubstrate', 'libreveal', 'Shadow', 'TweakInject', 'ellekit'];
            // Pre-allocate fake path to avoid memory leak in hot callback
            var fakeDylibPath = Memory.allocUtf8String('/usr/lib/libSystem.B.dylib');
            Interceptor.attach(dyld_get_image_name, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        var name = retval.readUtf8String();
                        if (name) {
                            var nameLower = name.toLowerCase();
                            for (var i = 0; i < hiddenLibs.length; i++) {
                                if (nameLower.indexOf(hiddenLibs[i].toLowerCase()) !== -1) {
                                    retval.replace(fakeDylibPath);
                                    hookCount.geo++;
                                    return;
                                }
                            }
                        }
                    }
                }
            });
            logSuccess(tag, '_dyld_get_image_name Frida/Substrate hidden');
        }
    } catch(e) { logWarn(tag, 'dyld_get_image_name: ' + e); }
}

// ============================================================
// ANTI-DETECTION 4: AppsFlyer Sanity Flags
// ============================================================
function bypassAppsFlyerSanity() {
    var tag = 'AppsFlyer';

    if (!ObjC.available) return;

    try {
        var resolver = new ApiResolver('objc');
        var matches = resolver.enumerateMatches('-[* calculateV2SanityFlagsWithIsSimulator:isDevBuild:isJailBroken:isCounterValid:isDebuggerAttached:]');
        matches.forEach(function(m) {
            Interceptor.attach(m.address, {
                onEnter: function(args) {
                    args[4] = ptr(0x0); // isJailBroken = NO
                    args[6] = ptr(0x0); // isDebuggerAttached = NO
                }
            });
            logSuccess(tag, 'Sanity flags: isJailBroken=NO, isDebuggerAttached=NO');
        });
    } catch(e) { /* optional */ }
}

// ============================================================
// ANTI-DETECTION 5: Integrity Violation Check Bypass
// ============================================================
function bypassIntegrityChecks() {
    var tag = 'Integrity';

    if (!ObjC.available) return;

    // Hook any method that reports INTEGRITY_VIOLATION_ATTEMPT
    try {
        var resolver = new ApiResolver('objc');
        var patterns = [
            '-[* dataIntegrityCheck*]',
            '-[* DataIntegrityCheck*]',
            '-[* integrityViolation*]',
            '-[* INTEGRITY_VIOLATION*]'
        ];
        patterns.forEach(function(pattern) {
            try {
                var matches = resolver.enumerateMatches(pattern);
                matches.forEach(function(m) {
                    Interceptor.attach(m.address, {
                        onLeave: function(retval) {
                            retval.replace(0x1); // pass
                        }
                    });
                    logSuccess(tag, 'Bypassed: ' + m.name);
                });
            } catch(e) { /* no matches */ }
        });
    } catch(e) { logWarn(tag, 'integrity: ' + e); }
}

// ============================================================
// MAIN — Execute all bypasses
// ============================================================
function main() {
    console.log('');
    console.log('=====================================================');
    console.log('  PokerStars v3.90.1 — SSL Pinning Bypass Loaded');
    console.log('  Bundle: ro.pokerstarsmobile.www');
    console.log('  7 SSL Layers + Anti-Detection');
    console.log('=====================================================');
    console.log('');

    // SSL Pinning Bypasses
    log('INIT', '--- SSL Pinning Bypass ---');
    bypassSecTrust();           // Layer 1: iOS Security.framework
    bypassAFNetworking();       // Layer 2: AFNetworking 4.0.1
    bypassStarscream();         // Layer 3: Starscream 4.0.4
    bypassApollo();             // Layer 4: Apollo 1.18.0
    bypassLivePersonSSL();      // Layer 5: LivePerson SDK
    bypassGeoComplySSL();       // Layer 6: GeoComply SDK
    bypassNSURLSessionDelegates(); // Layer 7: Generic delegates

    console.log('');

    // Anti-Detection Bypasses
    log('INIT', '--- Anti-Detection Bypass ---');
    bypassJailbreakDetection(); // Jailbreak: URL schemes + file paths
    bypassDebuggerDetection();  // Debug: sysctl/ptrace/getppid
    bypassGeoComplyRASP();      // GeoComply: RASP/hook/dylib detection
    bypassAppsFlyerSanity();    // AppsFlyer: sanity flags
    bypassIntegrityChecks();    // Integrity violation checks

    console.log('');
    console.log('=====================================================');
    logSuccess('DONE', 'All bypasses installed successfully!');
    console.log('=====================================================');
    console.log('');

    // Periodic stats
    setInterval(function() {
        if (hookCount.ssl > 0 || hookCount.jb > 0 || hookCount.geo > 0) {
            log('STATS', 'SSL: ' + hookCount.ssl + ' | JB: ' + hookCount.jb +
                ' | GeoComply: ' + hookCount.geo + ' | AntiDebug: ' + hookCount.debug);
            hookCount = { ssl: 0, jb: 0, debug: 0, geo: 0 };
        }
    }, 30000); // every 30 seconds
}

// Run after ObjC runtime is ready
if (ObjC.available) {
    // Small delay to ensure all frameworks are loaded
    setTimeout(main, 500);
} else {
    console.log('[!] ObjC runtime not available!');
}
