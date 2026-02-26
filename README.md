# PokerStars SSL Pinning Bypass

Frida-based SSL pinning bypass for **PokerStars iOS v3.90.1** (Build 80957)
Bundle ID: `ro.pokerstarsmobile.www`

## Bypasses

### 7 SSL Pinning Layers
| Layer | Target | Method |
|-------|--------|--------|
| 1 | iOS Security.framework | SecTrustEvaluateWithError, SecTrustEvaluate, SecTrustGetTrustResult |
| 2 | AFNetworking 4.0.1 | AFSecurityPolicy (7 hooks: evaluate, pinningMode, allowInvalid, etc.) |
| 3 | Starscream 4.0.4 | WebSocket FoundationSecurity.evaluateTrust |
| 4 | Apollo 1.18.0 | GraphQL SSLSecurity.isValid, WebSocket.disableSSLCertValidation |
| 5 | LivePerson LPMessagingSDK 6.22.0 | LPSRSecurityPolicy, LPSRPinningSecurityPolicy, public key pinning |
| 6 | GeoComply SDK 2.15.0 | shouldTrustProtectionSpace, anti-bypass detection NOP |
| 7 | NSURLSession delegates | GULNetworkURLSession, WKWebView, NSURLSessionDelegateBypassingSSLErrors |

### OpenSSL 3.3.2 (CommLib2a — statically linked)
- `X509_verify_cert` → success
- `X509_check_host` → match (runtime symbol scan)
- `X509_STORE_CTX_init` → success
- `SSL_do_handshake` → monitored

### 5 Anti-Detection Layers
| Layer | Target |
|-------|--------|
| Jailbreak | 6 URL schemes + 28 file paths + fork/access/stat/lstat |
| Debugger | sysctl P_TRACED, ptrace PT_DENY_ATTACH, getppid |
| GeoComply RASP | Debugger detection, dylib scanning, port scanning, Frida hiding |
| AppsFlyer | Sanity flags (isJailBroken, isDebuggerAttached) |
| Integrity | dataIntegrityCheck, integrityViolation patterns |

### Total: 65 Interceptor hooks, 1351 lines

## Requirements

- Jailbroken iOS device (or corellium/palera1n)
- [Frida](https://frida.re/) installed on device and host
- PokerStars IPA v3.90.1 (ro.pokerstarsmobile.www)

## Usage

### Spawn mode (recommended)
```bash
frida -U -f ro.pokerstarsmobile.www -l pokerstars_ssl_bypass.js --no-pause
```

### Attach mode (if already running)
```bash
frida -U -n pokerstars -l pokerstars_ssl_bypass.js
```

### With proxy (Burp/Charles)
```bash
# 1. Set proxy on device (Wi-Fi settings → HTTP Proxy → Manual)
# 2. Install Burp/Charles CA certificate on device
# 3. Run the bypass:
frida -U -f ro.pokerstarsmobile.www -l pokerstars_ssl_bypass.js --no-pause
```

### Objection
```bash
objection -g ro.pokerstarsmobile.www explore --startup-script pokerstars_ssl_bypass.js
```

## Configuration

Edit the `CONFIG` object at the top of the script:

```javascript
var CONFIG = {
    verbose: false,    // true = log every hook hit
    logSSL: true,      // log SSL bypass events
    logJB: true,       // log jailbreak bypass events
    logAntiDebug: false, // log anti-debug bypass
    colorLog: true     // colored console output
};
```

## Output

```
=====================================================
  PokerStars v3.90.1 — SSL Pinning Bypass Loaded
  Bundle: ro.pokerstarsmobile.www
  7 SSL Layers + Anti-Detection
=====================================================

[*] [INIT] --- SSL Pinning Bypass ---
[+] [SecTrust] SecTrustEvaluateWithError hooked
[+] [SecTrust] SecTrustEvaluate hooked
[+] [SecTrust] SecTrustGetTrustResult hooked
[+] [SecTrust] X509_verify_cert hooked (covers CommSSL chain verification)
[+] [AFNet] AFSecurityPolicy fully bypassed (7 hooks)
[+] [AFNet] AFURLSessionManager.serverTrustError → nil
[+] [Starscream] evaluateTrust hooked (interceptor)
[+] [Apollo] SSLSecurity.isValid hooked → true
[+] [LivePerson] LPSRSecurityPolicy.evaluateServerTrust → YES
[+] [GeoComply] GCHttpTask.shouldTrustProtectionSpace → YES
[+] [GeoComply] GCHttpTask.updateSSLChallengeInfo → TRUE NOP
[+] [GeoComply] GCAuthChallengeDetector replaced (safe, no double-invocation)
...
[+] [DONE] All bypasses installed successfully!
```

Stats are printed every 30 seconds showing hook hit counts.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  pokerstars_ssl_bypass.js (Frida Script)            │
├─────────────────────────────────────────────────────┤
│  Layer 1: SecTrust*         ← Nuclear option        │
│  Layer 2: AFNetworking      ← HTTPS requests        │
│  Layer 3: Starscream        ← WebSocket             │
│  Layer 4: Apollo            ← GraphQL               │
│  Layer 5: LivePerson        ← Chat + public key pin │
│  Layer 6: GeoComply         ← Geolocation + anti-   │
│                                bypass detection      │
│  Layer 7: NSURLSession      ← Catch-all delegates   │
│           + WKWebView                                │
│           + deprecated TLS                           │
├─────────────────────────────────────────────────────┤
│  OpenSSL: X509_verify_cert  ← CommSSL/CommLib2a     │
│           X509_check_host                            │
├─────────────────────────────────────────────────────┤
│  Anti-Detection: JB + Debug + RASP + AppsFlyer      │
└─────────────────────────────────────────────────────┘
```

## Safety

All delegate methods that call completion handlers use `Interceptor.replace` (full method replacement) instead of `Interceptor.attach` to prevent double-invocation crashes. Non-SSL challenges fall through to `PerformDefaultHandling`.

## Files

| File | Description |
|------|-------------|
| `pokerstars_ssl_bypass.js` | Main Frida bypass script (1351 lines, 65 hooks) |
| `POKERSTARS_FULL_ANALYSIS.md` | Complete IPA reverse engineering analysis |

## Disclaimer

For authorized security research and educational purposes only.
