# PokerStars iOS IPA — Complete Reverse Engineering Analysis
**Generated:** 2026-02-25
**IPA Version:** 3.90.1 (Build 80957)
**Source:** `C:\Users\Administrator\Downloads\A617C156-5A08-41F1-8422-19295BE3A5C5\pokerstars.app\`

---

## Table of Contents
1. [App Identity](#1-app-identity)
2. [Critical Credentials](#2-critical-credentials)
3. [All Servers & Endpoints](#3-all-servers--endpoints)
4. [Frameworks (35 total)](#4-frameworks-35-total)
5. [Security Architecture](#5-security-architecture)
6. [Communication Protocol (CommLib2a)](#6-communication-protocol-commlib2a)
7. [Authentication Flow](#7-authentication-flow)
8. [WebView Bridge (starsweb_api.js)](#8-webview-bridge-starswebapijs)
9. [Multi-License Architecture (26+ regions)](#9-multi-license-architecture-26-regions)
10. [Airship Push Keys (decoded, per-license)](#10-airship-push-keys-decoded-per-license)
11. [OneTrust Consent IDs (per-license)](#11-onetrust-consent-ids-per-license)
12. [Casino Lobby API](#12-casino-lobby-api)
13. [Game Protocol Messages](#13-game-protocol-messages)
14. [Payment Providers](#14-payment-providers)
15. [Jailbreak Detection](#15-jailbreak-detection)
16. [Crypto Stack](#16-crypto-stack)
17. [Device Fingerprinting](#17-device-fingerprinting)
18. [UI / Theme System](#18-ui--theme-system)
19. [Localization (21 languages)](#19-localization-21-languages)
20. [On-Demand Resources](#20-on-demand-resources)
21. [Build Infrastructure (Leaked)](#21-build-infrastructure-leaked)
22. [Key Obfuscation System](#22-key-obfuscation-system)
23. [Encrypted Files](#23-encrypted-files)
24. [Entitlements](#24-entitlements)
25. [Privacy Manifest](#25-privacy-manifest)
26. [Legal / Licensing Entity](#26-legal--licensing-entity)

---

## 1. App Identity

| Item | Value |
|---|---|
| **Bundle ID** | `ro.pokerstarsmobile.www` |
| **Display Name** | PokerStars |
| **CFBundleVersion** | `3.90.1.80957` |
| **CFBundleShortVersionString** | `3.90.1` |
| **Commit ID** | `069e867a9bf32394f2f281be8064ed61f6dcc30c` |
| **Apple Team ID** | `DRFJ9CFR4X` |
| **App Identifier Prefix** | `DRFJ9CFR4X.` |
| **License** | Romania (RO) |
| **Environment** | Production (pr) |
| **Min iOS** | 15.0 |
| **SDK** | iphoneos 18.5 |
| **Xcode** | 16.4 (Build 16F6) |
| **Build Machine OS** | macOS 24G419 (Sequoia) |
| **Architecture** | arm64 only |
| **DRM Scheme** | FairPlay v2 |
| **URL Scheme** | `pokerstarsro://` |
| **Package Type** | APPL |
| **Game Engine** | Cocos2d-x (MetalANGLE backend) |
| **Protocol Library** | CommLib2a (proprietary binary protocol over TLS) |
| **Binary Size** | ~42 MB |
| **Total App Size** | ~244 MB |
| **Supported Devices** | iPhone 7 Plus → iPhone 15 Pro Max (iPhone 16 NOT in whitelist) |
| **UIDeviceFamily** | iPhone + iPad |
| **UIFileSharingEnabled** | true (Documents accessible via iTunes/Finder) |
| **Encryption Export** | ITSAppUsesNonExemptEncryption = false |

### Supported Devices Whitelist
iPhone9,2/9,4 (7 Plus), iPhone10,2/10,3/10,5/10,6 (8 Plus/X), iPhone11,2/11,4/11,6 (XS/XS Max),
iPhone12,3/12,5 (11 Pro/Pro Max), iPhone13,1-13,4 (12 series), iPhone14,2-14,5/14,7/14,8 (13/14 series),
iPhone15,2-15,5 (14 Pro/15 series), iPhone16,1/16,2 (15 Pro/Pro Max)

### Background Modes
- `remote-notification` only

### Custom Fonts
- DrukTextLCGApp-Medium.ttf (PokerStars branding font)
- Roboto family: Regular, Medium, Bold, BoldCondensed, Black, Condensed-Regular

### Internal Build Keys
| Key | Value |
|---|---|
| MF_EMBEDDED | NO |
| MF_INTERNAL_BUILD_LOG | (empty) |
| ADD_ISP_HEADERS | (empty) |
| OVERRIDE_RESOLVERS_URL | (empty — used for dev overrides) |

---

## 2. Critical Credentials

### Firebase / Google
| Item | Value |
|---|---|
| **Firebase API Key** | `AIzaSyA0Xo1cpfUhRvMfUuKR_eZMuaakD_LYnxI` |
| **Firebase Project ID** | `mobile-ng` |
| **Firebase DB URL** | `https://mobile-ng.firebaseio.com` |
| **Firebase Storage** | `mobile-ng.appspot.com` |
| **GCM Sender ID** | `315094763305` |
| **Google App ID** | `1:315094763305:ios:baddfd5e2cb576ab8d5938` |
| **iOS Client ID** | `315094763305-cdv8biqdgifgh9c0trmuiafijff1i41b.apps.googleusercontent.com` |
| **Android Client ID** | `315094763305-mfhq2a57lsmad1je616d3c0utb3l30na.apps.googleusercontent.com` |
| **Reversed Client ID** | `com.googleusercontent.apps.315094763305-cdv8biqdgifgh9c0trmuiafijff1i41b` |
| **GTM Container ID** | `GTM-WZGGCD7Z` |
| IS_ADS_ENABLED | false |
| IS_ANALYTICS_ENABLED | false (Firebase level) |
| IS_GCM_ENABLED | true |
| IS_SIGNIN_ENABLED | true |
| IS_APPINVITE_ENABLED | true |

### AppsFlyer
| Item | Value |
|---|---|
| **Dev Key** | `87PCPVi2q7MjH5kk4hvdza` |
| **SKAdNetwork Endpoint** | `https://appsflyer-skadnetwork.com/` |
| **Deep Link Domain** | `amaya.onelink.me` |

### Address Verification (Loqate/Addressy)
| Item | Value |
|---|---|
| **API Key** | `H4-U1N2-C1N2D1-Y9A1` |
| **Endpoint** | `https://api.addressy.com/Capture/Interactive` |

### Analytics
| Item | Value |
|---|---|
| **GA Tracker ID** | `U-2702-A128851` |
| **Snowplow Collector** | `com-starsgroup-prod1.collector.snplow.net` |

### Health Counters (Monitoring)
| Item | Value |
|---|---|
| **PROD API Key** | `gUuRM5gjsb1Wabi232KFVcCKZu6TE84ROZtwA2CN` |
| **QA API Key** | `RfARJ4lUjX8y2kjW6CHG2vMfgX1bZNSxVBh9S7ad` |

### LivePerson (Customer Support Chat)
| Item | Value |
|---|---|
| **PROD Account ID** | `62211188` |
| **PROD Install ID** | `3e13-714b-fde2b8cd9b0c24-82a8-9c09a6` |
| **QA Account ID** | `72224791` |
| **QA Install ID** | `4446-6546-f0f4dab3056fa6-0ba1-7a8b75` |
| **PROD Auth Issuer** | `https://ipauth.starsmessenger.com` |
| **QA Auth Issuer** | `https://qa-ipauth.starsmessenger.com` |

### Salesforce (CRM)
| Item | Value |
|---|---|
| **PROD Org ID** | `0Dd009rT080000M` |
| **QA Org ID** | `0Dz000mG020008y` |

### OAuth (HARDCODED!)
| Item | Value |
|---|---|
| **OAuth Client ID** | `messaging-client` |
| **OAuth Client Secret** | `secret` (literally hardcoded) |
| **Grant Type** | `authorization_code` |

### Key Obfuscation
| Item | Value |
|---|---|
| **XOR Key** | `0x8F` (143 decimal) |
| **Deobfuscation Class** | `MfKeyDeobfuscation` (in MfAppLibrary module) |
| **Method** | Each char = `(charCode XOR 0x8F)`, stored as groups of 4 integers |

### Apple Pay Merchants
- `merchant.pokerstars.uk`
- `merchant.production.pokerstars.uk`

---

## 3. All Servers & Endpoints

### Core Production Infrastructure

| Service | URL |
|---|---|
| **GraphQL API (Wallet/PAM)** | `https://api.starsweb.io/pam/wallet/graphql` |
| **WebSocket (Wallet)** | `wss://api.starsweb.io/pam/wallet/subscription` |
| **WebSocket (Notifications UK)** | `wss://api.starsweb.io/pam/notifications/subscription` |
| **IDP OAuth** | `https://api.starsweb.io/oauth2` |
| **Sports Auth** | `https://www.pokerstarssports.com/api/v1-preview/auth/session` |
| **URL Resolver** | `https://pokerstars.com/resolve/` |
| **Hand Replayer** | `https://www.pokerstarsreplayer.com/api/sources/create` |
| **ACMS CMS (PROD)** | `https://acms.acms-flutter.com/content/v1/doc` |
| **ACMS NG Proxy** | `https://acms.acms-flutter.com/ng-proxy/v1` |
| **RUM Observability** | `https://api.rum.obs.flutterint.com/events` |
| **NPS Survey** | `https://surveys.rationalgroup.com/index.php/437288/newtest/Y` |
| **NPS Dismiss** | `https://surveys.rationalgroup.com/index.php/988931` |
| **Avatar Service** | `https://res.ps.im/psutils/mvc/avatar/%@` |
| **Red Tiger Jackpots** | `https://feed-stars.redtiger.cash/jackpots/` |

### CDN Infrastructure (rationalcdn.com)

| URL | Purpose |
|---|---|
| `https://csapp.rationalcdn.com/ng-updater/version.json` | App update version check |
| `https://csapp.rationalcdn.com/pokerstars/ios` | iOS app resources |
| `https://csapp.rationalcdn.com/pokerstars/ios/public` | Public assets |
| `https://csapp.rationalcdn.com/pokerstars/ios/public/tiles/missing_asset.jpg` | Placeholder tile |
| `https://csapp.rationalcdn.com/starscasino/new_lobby/marketing_icons/` | Casino marketing |
| `https://csapp.rationalcdn.com/starscasino/new_lobby/provider_logos/` | Casino provider logos |
| `https://csapp.rationalcdn.com/starscasino/new_lobby/provider_logos_v4/` | Provider logos v4 |
| `https://csapp.rationalcdn.com/common/legal/` | Legal icons |
| `https://csapp.rationalcdn.com/common/mf-html5/v7/{env}/` | Micro-frontend HTML5 |
| `https://csapp.rationalcdn.com/mp4` | MP4 videos |
| `https://cashier.rationalcdn.com/mg/` | Cashier resources |
| `https://cmsstorage.rationalcdn.com/assets` | CMS storage |
| `https://s1.rationalcdn.com/vendors/starsweb/icon/` | StarsWeb icons |
| `starscrm.rationalcdn.com` | CRM zones config |

### Rewards WebSocket Endpoints (CIPWA/STOMP)

| URL | Region |
|---|---|
| `https://rewards.starsaccount.com/cipwa/cipwawap/ws` | Global/COM |
| `https://rewards.starsaccountmi.com/cipwa/cipwawap/ws` | Michigan |
| `https://rewards.starsaccountnj.com/cipwa/cipwawap/ws` | New Jersey |
| `https://rewards.starsaccountpa.com/cipwa/cipwawap/ws` | Pennsylvania |

### Avatar/Resource Servers (per region)

| Domain | Region |
|---|---|
| `res.ps.im` | Global |
| `res.mi.ps.im` | Michigan |
| `res.nj.ps.im` | New Jersey |
| `res.pa.ps.im` | Pennsylvania |

### Third-Party Service Endpoints

| Service | Endpoint |
|---|---|
| **GeoComply Logger** | `https://logger.geocomply.net/logs` |
| **GeoComply Beacons** | `https://logger.geocomply.net/logs?type=beaconscanninglog` |
| **GeoComply Latency** | `https://logger.geocomply.net/logs?type=latencydata` |
| **GeoComply MyIP** | `https://logger.geocomply.net/logs?type=myiplog` |
| **SumSub API** | `https://api.sumsub.com` |
| **SumSub Support** | `https://support.sumsub.com/hc/` |
| **SumSub Token** | `/api/v1-preview/account/sumsub/token` |
| **LivePerson Auth (PROD)** | `https://ipauth.starsmessenger.com` |
| **LivePerson Auth (QA)** | `https://qa-ipauth.starsmessenger.com` |
| **LivePerson Tag** | `lptag.liveperson.net` / `lptag-a.liveperson.net` |
| **Plaid Production** | `https://production.plaid.com` |
| **Plaid Sandbox** | `https://sandbox.plaid.com` |
| **Plaid Development** | `https://development.plaid.com` |
| **Airship EU Device API** | `https://device-api.asnapieu.com` |
| **Airship EU Remote Data** | `https://remote-data.asnapieu.com` |
| **Airship EU Combine** | `https://combine.asnapieu.com` |
| **Airship US Device API** | `https://device-api.urbanairship.com` |
| **Airship US Remote Data** | `https://remote-data.urbanairship.com` |
| **Airship US Combine** | `https://combine.urbanairship.com` |
| **Addressy API** | `https://api.addressy.com/Capture/Interactive` |
| **AppsFlyer SKAd** | `https://appsflyer-skadnetwork.com/` |
| **AppsFlyer App** | `https://app.appsflyer.com` |
| **Firebase Settings** | `https://firebase-settings.crashlytics.com` |
| **Firebase Installations** | `https://firebaseinstallations.googleapis.com` |
| **Firebase RemoteConfig** | `https://firebaseremoteconfig.googleapis.com` |
| **Firebase Realtime Config** | `https://firebaseremoteconfigrealtime.googleapis.com` |
| **Crashlytics Reports** | `https://reports.crashlytics.com` |
| **Crashlytics Update** | `https://update.crashlytics.com` |
| **Google Analytics** | `https://ssl.google-analytics.com/collect` and `/batch` |
| **Google Tag Manager** | `https://www.googletagmanager.com/gtm/ios?id=GTM-WZGGCD7Z` |
| **Google Ad Services** | `https://www.googleadservices.com/pagead/conversion/app/deeplink` |
| **Apple Ad Attribution** | `https://api-adservices.apple.com/api/v1/` |
| **Apple App Analytics** | `https://app-analytics-services.com/a` |
| **OneTrust CDN** | `cdn.cookielaw.org` |

### Casino Domains (per regulated market)

```
https://casinoapp.pokerstarscasino.{license}     (default per-license)
https://casino.pokerstarscasinomi.com             (Michigan)
https://casino.pokerstarscasinonj.com             (New Jersey)
https://casino.starsmtairycasino.com              (Mt. Airy PA)
https://onlinecasino.pokerstars.bg                (Bulgaria)
https://onlinecasino.pokerstars.cz                (Czech Republic)
https://starsweb.pokerstarscasino.se              (Sweden)
https://rationalcasino.com                        (default fallback)
```

### Micro-Frontend WebView Paths

```
Panic Button:        csapp.rationalcdn.com/common/mf-html5/v7/{env}/#/panic-button/info
Panic Ack:           csapp.rationalcdn.com/common/mf-html5/v7/{env}/#/panic-button/acknowledgement
Update App:          csapp.rationalcdn.com/common/mf-html5/v7/{env}/#/update-app/
Uniclient Confirm:   csapp.rationalcdn.com/common/mf-html5/v7/{env}/#/uniclient/confirm-state/
Push Notifications:  csapp.rationalcdn.com/pokerstars/confirm-box/b26/push.html
Calendar:            csapp.rationalcdn.com/pokerstars/confirm-box/b26/calendar.html
Reminders:           csapp.rationalcdn.com/pokerstars/confirm-box/b26/reminders.html
Tickets:             csapp.rationalcdn.com/pokerstars/zero-tickets/b19/index.html
```

### RAM2 (Remote Action Manager) WebView Paths

```
Account Details:     /embedded/modal/account/details/{address,email,phone,password,verify-account}
Responsible Gaming:  /embedded/modal/account/responsible/{self-exclude,deposit-limit,casino-limit,...}
History:             /embedded/modal/account/history/{login-history,hand-history,tournament-history,...}
Auth:                /embedded/modal/auth/{password-recovery,login/eula,login/sms,...}
Settings:            /embedded/modal/account/settings/{communication,language,multi-currency,...}
```

### Leaked Dev/QA/Internal Endpoints

| URL | Purpose |
|---|---|
| `https://casinoapp.dev116.pyr` | Dev casino server |
| `https://mg.qa-ps.pyr/cipwa/cipwawap/ws` | QA rewards WebSocket |
| `https://prestotest.qa.devops.csr.pstars` | QA test server |
| `http://10.30.11.171:8080/geocomplyemulator/player` | Internal GeoComply emulator |
| `https://acms.dev.acms-flutter.com` | Dev CMS |
| `https://api.rum.test.obs.flutterint.com/events` | Test RUM |
| `https://qa-ipauth.starsmessenger.com` | QA LivePerson auth |
| `res.%@.pyr` | Dev resource template |
| `mx1.pyrsoftwaresys.com` | Internal mail server |
| `bs-local.com` | BrowserStack local testing |

### Email Addresses Found
```
psclientlogs@pyrsoftware.com      -- Client logging
info@pokerstars.it                -- Italy support
info@sisal.it                     -- Sisal partner
info@casino777.ch                 -- Switzerland partner
verification@pokerstars.dk        -- Denmark verification
verifyme@starsaccount.it          -- Italy account verification
```

---

## 4. Frameworks (35 total)

### Networking (3)
| Framework | Version | Purpose | Size |
|---|---|---|---|
| AFNetworking | 4.0.1 | HTTP networking (Obj-C) | 483 KB |
| Starscream | 4.0.4 | WebSocket client (Swift) | 493 KB |
| Apollo | 1.18.0 | GraphQL client (PAM/wallet) | 1.9 MB |

### Firebase Suite (11)
| Framework | Version |
|---|---|
| FirebaseCore | 11.8.1 |
| FirebaseCrashlytics | 11.8.0 |
| FirebasePerformance | 11.8.0 |
| FirebaseRemoteConfig | 11.8.0 |
| FirebaseRemoteConfigInterop | 11.8.0 |
| FirebaseABTesting | 11.8.0 |
| FirebaseSessions | 11.8.0 |
| FirebaseInstallations | 11.8.0 |
| FirebaseCoreInternal | 11.8.0 |
| FirebaseCoreExtension | 11.8.0 |
| FirebaseSharedSwift | 11.8.0 |

### Google Support (4)
| Framework | Version |
|---|---|
| GoogleDataTransport | 10.1.0 |
| GoogleUtilities | 8.0.2 |
| nanopb | 3.30910.0 |
| FBLPromises / Promises | 2.4.0 |

### Analytics & Attribution (1)
| Framework | Version | Notes |
|---|---|---|
| SnowplowTracker | 6.0.9 | Behavioral analytics |
| (AppsFlyer 6.14.2) | — | Statically linked, not separate framework |

### Push Notifications (2)
| Framework | Version | Size |
|---|---|---|
| AirshipKit | 18.14.2 | **25.7 MB** (largest!) |
| AirshipServiceExtension | 18.14.2 | 298 KB |

### Geolocation Compliance (1)
| Framework | Version | Size |
|---|---|---|
| GeoComplySDK | 2.15.0 | 5.3 MB |

### KYC / Identity Verification (1)
| Framework | Version | Size |
|---|---|---|
| IdensicMobileSDK (SumSub) | 1.32.0 | 4.2 MB |

### Privacy & Consent (1)
| Framework | Version | Size |
|---|---|---|
| OTPublishersHeadlessSDK (OneTrust) | 202503.1.0 | 9.3 MB |

### Customer Support (3)
| Framework | Version | Size |
|---|---|---|
| LPMessagingSDK (LivePerson) | 6.22.0 | 8.0 MB |
| SMIClientCore (Salesforce) | 1.6.0 | 2.6 MB |
| SMIClientUI (Salesforce) | 1.6.0 | 2.0 MB |

### Payments (1)
| Framework | Version | Size |
|---|---|---|
| LinkKit (Plaid) | 4.3.1 | **14.6 MB** (2nd largest) |

### UI & Utility (7)
| Framework | Version | Purpose |
|---|---|---|
| Lottie | 4.4.2 | Animation rendering |
| SwiftMessages | 9.0.6 | In-app notification banners |
| IGListKit | 4.0.0 | Data-driven UICollectionView |
| IGListDiffKit | 4.0.0 | Diffing algorithm |
| SSZipArchive | 2.2.3 | ZIP compression/extraction |
| JWTDecode | 3.0.1 | JWT token decoding |
| Factory | 2.1.3 | Dependency injection |

### SDKs NOT Found
Adjust, Braze, Segment, Branch.io, Amplitude — none present.

---

## 5. Security Architecture

### Jailbreak Detection — URL Scheme Checks (6)
```
cydia://        — Cydia app store
activator://    — Activator tweak
filza://        — Filza file manager
zbra://         — Zebra package manager
sileo://        — Sileo package manager
undecimus://    — unc0ver jailbreak
```

### Jailbreak Detection — File System Checks
```
/Applications/Cydia.app
/Library/MobileSubstrate/MobileSubstrate.dylib
/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist
/Library/MobileSubstrate/DynamicLibraries/Veency.plist
/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist
/private/jailbreak.txt
/private/var/lib/cydia
/private/var/tmp/cydia.log
/private/var/lib/apt/
/bin/bash
/etc/apt
/usr/bin/sshd
/usr/sbin/sshd
```

### GeoComply GPS Spoofer Detection
```
GPSTravellerTweakVIP + GPSTravellerTweakVIP.plist
LocationFakerX + LocationFakerX.plist + .com.apple.LocationFakerX.plist
installed_tweaks (enumerates all tweaks)
ios_app_hooked (hook detection)
ios_audio_detection (audio analysis)
```

### Anti-Debug
- `sysctl` / `sysctlbyname` — kern.proc-based debugger detection
- `IsDebuggerAttachedEv` / `BreakDebuggerEv` — C++ anti-debug events
- `GCDebuggerDetectionOperation` — GeoComply dedicated debugger detector
- AppsFlyer sanity flags: `isSimulator`, `isDevBuild`, `isJailBroken`, `isCounterValid`, `isDebuggerAttached`

### Anti-Tamper / Integrity
```
INTEGRITY_VIOLATION_ATTEMPT
DataIntegrityCheck
PYRA_DataIntegrityCheck
AFSDKChecksum
checksumEnabled
commsslchksum.cpp (dedicated checksum module)
PRAGMA integrity_check (SQLite)
```

### Certificate Pinning
- **AFNetworking:** `AFSecurityPolicy` with pinningMode (Certificate/PublicKey)
- **Starscream:** `CertificatePinning` protocol via `FoundationSecurity`
- **CommSSL:** Custom cert verification (`CommSSLClient: Certificate verification failed`, `CommonName does not match`)
- **GeoComply:** Embedded RSA public/private keys + cert chain parsing
- **No standalone .cer/.pem/.p12 files** — pinning uses programmatic configuration

### App Transport Security
```
NSAllowsArbitraryLoads: false              — strict default
NSAllowsArbitraryLoadsInWebContent: true   — WebViews unrestricted
NSExceptionDomains:
  "pyr":  insecure HTTP allowed (+ subdomains)  — internal Pyramid domain
  "10.30.11.171": insecure HTTP allowed          — dev server IP leaked
```

---

## 6. Communication Protocol (CommLib2a)

### Guard System (9 authentication types)
| # | Guard Type | Source File | Purpose |
|---|---|---|---|
| 1 | NullGuard | `commgrdnullcli.cpp` | No auth (dev?) |
| 2 | PlainTextPasswordSidGuard | `commgrdppwdsidcli.cpp` | Password + Session ID |
| 3 | RsaGuard | `commgrdrsacli.cpp` | RSA key-based auth |
| 4 | JwtGuard | `commgrdjwtcli.cpp` | JWT token auth |
| 5 | AesEncryptedGuard | `commgrdaesencryptedcli.cpp` | AES encrypted channel |
| 6 | TokenGuard | `commgrdtokencli.cpp` | Token-based auth |
| 7 | ExternAuthGuard | `commgrdextauthcli.cpp` | External auth provider |
| 8 | ExternAuthOperatorTokenGuard | — | Operator token auth |
| 9 | WebTokenIntGuard | `commgrdwebtokenintcli.cpp` | Web token internal |

### Connection Architecture
```
LobbyConnection            — Main lobby
AuxLobbyConnection         — Auxiliary lobby
CashierConnection          — Cashier/payments
GuestLobbyNullConnection   — Pre-login (guest)
PokerTableServerStream     — Game table
PokerTableServerStreamMessenger        — Table messenger
PokerTableServerStreamBlitzMessenger   — Zoom/Blitz mode
PokerTableServerStreamTournMessenger   — Tournaments
```

### Connection String Format
```
server=%s serverObject=%s connType=%s clientUniqueId=%s clientGroupId=%s
protocol %u(%s), BlockSize %d, Compression %d, keepAlives - %d(%d), muxEnabled = %s
```

### SSL/TLS Layer Modules
```
commsslc.cpp        — SSL client
commsslaes.cpp      — AES within SSL
commssldh.cpp       — DH key exchange
commsslbio.cpp      — BIO I/O
commsslcipher.cpp   — Cipher management
commsslverify.cpp   — Certificate verification
commsslpasswordhash.cpp — Password hashing
commsslchksum.cpp   — Checksum verification
```

### Protocol Message Types (Connection)
```
_COMM_MSGTYPE_CONNECT_REQUEST
_COMM_MSGTYPE_CONNECT_REQUEST_ACCEPTED
_COMM_MSGTYPE_CONNECT_REQUEST_GRANTED
_COMM_MSGTYPE_CONNECT_GUARD_REQUEST_GRANTED
_COMM_MSGTYPE_CONNECT_GUARD_ADD_RESPONSE
_COMM_MSGTYPE_CONNECT_SERVER_DISCONNECT
_COMM_MSGTYPE_CONNECT_SERVER_ERROR
_COMM_MSGTYPE_CONNECT_SERVER_FATALERROR
_COMM_MSGTYPE_CONNECT_SERVER_TRANSITDISCONNECT
_COMM_MSGTYPE_CONNECT_SERVER_HIGHPRIORITY_TRANSITDISCONNECT
_COMM_MSGTYPE_PHYSICAL_CONNECT
_COMM_MSGTYPE_PHYSICAL_DISCONNECT
```

### Protocol Message Types (Subscription)
```
_COMM_MSGTYPE_SUBSCRIPTION_REQUEST_ACCEPTED
_COMM_MSGTYPE_SUBSCRIPTION_RESPONSE
_COMM_MSGTYPE_SUBSCRIPTION_RESYNC
_COMM_MSGTYPE_SUBSCRIPTION_FATALERROR
_COMM_MSGTYPE_SUBSCRIPTION_TRANSITDISCONNECT
_COMM_MSGTYPE_SUBSCRIPTION_ONLINE_UPDATE
_COMM_MSGTYPE_SUBSCRIPTION_UNSUBSCRIBE
_COMM_MSGTYPE_SUBSCRIPTION_COUNT_UPDATE
_COMM_MSGTYPE_SUBSCRIPTION_LIGHT_*
_COMM_MSGTYPE_CONNQUALITY_CLIUPDATE
_COMM_MSGTYPE_CONNQUALITY_SRVMONITOR
_COMM_MSGTYPE_CONNQUALITY_SRVREQISALIVE
```

---

## 7. Authentication Flow

### IDP (Identity Provider) System
```
Endpoint:        https://api.starsweb.io
Path:            oauth2
Token refresh:   60 seconds offset
Feature flag:    "ng-idp-login-enabled"
```

### Auth Guard Types Sequence
1. Guard request → `_COMM_MSGTYPE_CONNECT_GUARD_REQUEST`
2. Guard add → `_COMM_MSGTYPE_CONNECT_GUARD_ADD_REQUEST/RESPONSE`
3. Guard granted → `_COMM_MSGTYPE_CONNECT_GUARD_REQUEST_GRANTED`
4. Version check at each step

### Auth Classes
```
PYRAuthenticationServiceWrapper
PYRAuthenticationListenerImpl
MfAuthenticator
MfExternalAuthViewController
CommClientGuardAuth
CommClientJwtGuard / CommClientJwtGuardFactory
CommClientRsaGuard / CommClientRsaGuardFactory
CommClientAesEncryptedGuard
CommClientPlainTextPasswordSidGuard
CommClientExternAuthGuard
CommClientExternAuthOperatorTokenGuard
CommClientWebTokenIntGuard
CommClientTokenGuard
CommClientNullGuard
```

### IDP Token Handling
```
$idpToken / IDPToken
IDP.on / IDP.refreshOffset
MfIDPClient / MfIDPCodeRequest / MfIDPRevokeTokenRequest / MfIDPTokenRequest
Renewing IDP token...
IDP: Reconnecting / IDP: Restoring connections
IDP: Update token error %d (%s)
```

### Login Flow (JavaScript bridge)
```javascript
(function() {try {ps.adapt.getAppRef().login(%@);return 'ok';} catch(err) {return err.message;}})()
```

### Login Storyboard Screens
1. `LoginWithCredentialsViewController` — Username/Password
2. `LoginWithPINViewController` — PIN login
3. `LoginWithDOBViewController` — Date of birth verification
4. `LoginWithRSAViewController` — RSA SecurID token

### OAuth Redirect URLs (per license)
```
pokerstarsitps://oauth/callback   (Italy PS)
pokerstarsukps://oauth/callback   (UK PS)
pokerstarscomps://oauth/callback  (COM PS)
pokerstarsptps://oauth/callback   (PT)
pokerstarsesps://oauth/callback   (ES)
pokerstarsfrps://oauth/callback   (FR)
pokerstarsdeps://oauth/callback   (DE)
pokerstarseeps://oauth/callback   (EE)
pokerstarsseps://oauth/callback   (SE)
pokerstarsdkps://oauth/callback   (DK)
pokerstarsbgps://oauth/callback   (BG)
pokerstarsgrps://oauth/callback   (GR)
pokerstarsrops://oauth/callback   (RO)
pokerstarsbeps://oauth/callback   (BE)
snai://oauth/callback             (SNAI)
sisalit://oauth/callback          (Sisal)
```

---

## 8. WebView Bridge (starsweb_api.js)

### Architecture
```
window.starsweb
  ├── auth
  │   ├── token          — Web session token
  │   ├── signature      — Session signature
  │   ├── webId          — Web identifier
  │   └── idpToken       — IDP OAuth token
  ├── $client
  │   ├── sendMsgToClient()               — Primary native→web channel
  │   ├── dispatchEventToStarsWithJson()   — Custom DOM event dispatch
  │   ├── updateAuth()                     — Legacy auth (token, sig, webId)
  │   ├── updateAuthIDP()                  — Modern auth (+ idpToken)
  │   ├── notifyStarsReady()              — Web content loaded signal
  │   ├── forceClose()                     — Emergency close (4 clicks/3sec)
  │   ├── enableForceClose()              — Toggle force close
  │   ├── beforeClose()                    — Pre-close hook
  │   ├── log()                            — Debug logging
  │   ├── initSendMsgToClientFunctions()  — Dynamic function registration
  │   ├── initClientFunction()            — Dynamic window function reg
  │   ├── stringToJson()                  — Safe JSON parsing
  │   └── createObjIfNull()              — Nested object creation
  └── app
      ├── close()          — Close webview
      ├── ready            — Ready flag
      ├── execute()        — Execute native command
      └── forceClose()     — Force close
```

### Communication Protocol
```
Web → Native:  window.webkit.messageHandlers.$encodedStars.postMessage(msg)
Native → Web:  evaluateJavaScript() calling window.starsweb.$client.*
```

### Events
- `starslogin` — User logged in
- `starslogout` — User logged out
- `starsready` — WebView initialized
- `starsbeforeclose` — Before WebView closes (cancellable)

### Force Close Mechanism
4 rapid taps within 3 seconds (hidden feature)

### Encrypted JS Modules (7 files)
All encrypted with magic header `7c ac 2e 26 4f 35`:
```
res/js/starsweb/init.js          — WebView initialization
res/js/starsweb/start.js         — App startup sequence
res/js/starsweb/modules/casino.js     — Casino vertical
res/js/starsweb/modules/googlepay.js  — Google Pay payments
res/js/starsweb/modules/minigames.js  — Mini-games bridge
res/js/starsweb/modules/touchpoint.js — CRM touchpoint tracking
res/js/starsweb/modules/twitch.js     — Twitch integration
```

### GraphQL WebSocket Config
```
API Resolver Tag:     starsweb_api
Socket Resolver Tag:  wss_starsweb_api
API Path:             pam/wallet/graphql
Socket Path (ES):     pam/wallet/subscription
Socket Path (UK):     pam/notifications/subscription
Token Type:           Bearer
Ping Interval:        30 seconds
Pong Timeout:         60 seconds
Reconnect Delay:      60 seconds
```

---

## 9. Multi-License Architecture (26+ regions)

### Complete License Matrix

| License | App Store ID | PokerStars Domain | Stars Account Domain | URL Scheme |
|---|---|---|---|---|
| **nl** | 1450283147 | pokerstars.nl | starsaccount.nl | `pokerstarsnl://` |
| **ch** | 1450283147 | pokerstars.ch | starsaccount.ch | `pokerstarsch://` |
| **net** | 606944207 | pokerstars.net | starsaccount.net | `pokerstarsnet://` |
| **ruso** | 1198223998 | pokerstars.com | starsaccount.com | `pokerstarsruso://` |
| **br** | 1448478295 | pokerstars.com | starsaccount.com | `pokerstarsbr://` |
| **gr** | 1490096962 | pokerstars.gr | starsaccount.gr | `pokerstarsgr://` |
| **arba** | 1145892643 | pokerstars.com | starsaccount.com | `pokerstars://` |
| **com** | 497361777 | pokerstars.com | starsaccount.com | `pokerstars://` |
| **it** | 463801955 | pokerstars.it | starsaccount.it | `pokerstarsit://` |
| **es** | 533787554 | pokerstars.es | starsaccount.es | `pokerstarses://` |
| **dk** | 526074631 | pokerstars.dk | starsaccount.dk | `pokerstarsdk://` |
| **bg** | 897141031 | pokerstars.bg | starsaccount.bg | `pokerstarsbg://` |
| **pt** | 1128328008 | pokerstars.pt | starsaccount.pt | `pokerstarspt://` |
| **ro** | 1128328156 | pokerstars.ro | starsaccount.ro | `pokerstarsro://` |
| **se** | 1434043599 | pokerstars.se | starsaccount.se | `pokerstarsse://` |
| **ee** | 526072221 | pokerstars.ee | starsaccount.ee | `pokerstarsee://` |
| **be** | 526068685 | pokerstars.be | starsaccount.be | `pokerstarsbe://` |
| **eu** | 515257559 | pokerstars.eu | starsaccount.eu | `pokerstars://` |
| **uk** | 897137765 | pokerstars.uk | starsaccount.uk | `pokerstarsuk://` |
| **fr** | 509469724 | pokerstars.fr | starsaccount.fr | `pokerstarsfr://` |
| **de** | 6444265562 | pokerstars.de | starsaccount.de | `pokerstarsde://` |
| **in** | 1384897952 | pokerstars.in | starsaccount.in | `pokerstarsin://` |
| **uspa** | 1454778152 | pokerstarspa.com | starsaccountpa.com | `pokerstarsuspa://` |
| **usnj** | 897152078 | pokerstarsnj.com | starsaccountnj.com | `pokerstarsusnj://` |
| **usmi** | 1454778152 | pokerstarsmi.com | starsaccountmi.com | `pokerstarsusmi://` |
| **caon** | 1594624219 | on.pokerstars.ca | on.starsaccount.ca | `pokerstarscaon://` |

### Italian White-Label Partners
| Partner | Domain | App Store ID | URL Scheme |
|---|---|---|---|
| Sisal | sisal.it | 463801955 | `pokersisal://` |
| SNAI | snaipoker.it | 1098901277 | `snaipoker://` |

### Product Availability by License
- **Poker:** All licenses
- **Casino:** NOT in FR, BE, EE, BR, RUSO, IN, CH, NET
- **Live Casino:** UK, IT only
- **Sports:** NOT in BG, BE, EE, BR, NET, RUSO, IN, CH, PT, USA

---

## 10. Airship Push Keys (decoded, per-license)

Obfuscation: XOR 0x8F per character, stored as arrays of 4-integer groups.
Deobfuscation class: `MfKeyDeobfuscation` in `MfAppLibrary`.

| License | App Key (Store) | App Secret (Store) | App Key (Enterprise) | App Secret (Enterprise) |
|---|---|---|---|---|
| **NL** | `_-JjQarpSNS1xMwBvZfexQ` | `jedzRWkfT3ZrnUUxbZNXew` | `e14fSGhHd49M9QioWcOt9g` | `eevcSOrEfelau-7SkDx4qQ` |
| **CH** | `fOwIReAcOlgQZb1W50t8uA` | `Ba3-Ra9Sfprl8vKjn3XgWA` | `zNQ9Quwghr4g6xFZxl1yAg` | `gkdDSmvqYers61Nklte6iw` |
| **NET** | `lPi8R6IlYuujAHxs0xMIkw` | `PwiLSCD911EeElQyQI-t6g` | `e14fSGhHd49M9QioWcOt9g` | `eevcSOrEfelau-7SkDx4qQ` |
| **RUSO** | `_-JjQarpSNS1xMwBvZfexQ` | `jedzRWkfT3ZrnUUxbZNXew` | `e14fSGhHd49M9QioWcOt9g` | `eevcSOrEfelau-7SkDx4qQ` |
| **BR** | `mFhmQqatD0uypiIUCgp2cw` | `KP-aTGKEOzCc0Mmpn_20Fw` | `CBWkQuXDVtoyqqg3YPlp0w` | `dsuxTSn05Ty1bJTWZ4aOLg` |
| **GR** | `8Ig3QehXavzRFdfYEPySrA` | `8kGuQOsveZs-rvHZWAnj-g` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **ARBA** | `a4MrRiNwyi2Ra3A2PxHIwQ` | `l-76RSl340G12kr6_GuAgg` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **COM** | `EFRBR6MZ9tdsvGhtaP-NZQ` | `uhA6TmyRyGaApzpHHCbUcA` | `V6S7SiEAjDLcpC5aX_1HTw` | `kQwQRWnMFtaWSUTK2ByasQ` |
| **IT** | `bcriR-SnB494uKfSKNRhcA` | `SG7ZQKfVZjSFNyNw1pZNWQ` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **ES** | `GWZ6SuZp9JkbA2l3nWEjEA` | `lmhyTifLL0PeN1pzyZAGjQ` | `eeQWRKECMwVul9eKnzq9qA` | `ArtNSCCk1YMvYQIRP4wL8g` |
| **DK** | `r82vRS7-icUx1U2iIL7Pew` | `8zVzT642ENp9-ZXx4ksPgw` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **BG** | `mH3KSq8D6WITpkFvqd8opA` | `sT-KSGvnpHt_7hBYVkGCIw` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **PT** | `4u6vQS1sQpeRVmsLR1uSbw` | `rI2tSiaBkxGYn1qi-b8Yeg` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **RO** | `JRTNTOTjSdiLv4tUCmWwvw` | `ntdrQWPzPetSYWtGYF-Umg` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **SE** | `xodwQC973wDDxQjMD_tqXA` | `7avCSm4v4WcMdOQH8FcHVQ` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **EE** | `TBZdQ2jqBopB-sjmxKBotQ` | `l4xuSWuOBdi-5YkcMKOYUA` | `r4ZFSCtjtBlGey0Mph8IrA` | `uPk3ROR0XVtZCg7vlkGK9Q` |
| **BE** | `mC8zTOAto47NSq4WXD04LA` | `m_RcSaVO2GUp4-_09CHNcg` | `rV-rQSket95iXGcH_bZaTA` | `bUXDQa-YrC_V_1qA0OvhLA` |
| **EU** | `qgm3SyakRIdewkOaUZ5A2A` | `eI8LR-959p7w7h4KajPf5g` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **UK** | `QyzYRCUQJbndDtya8CjRaw` | `VP7OTCyxkMwEX-3_srNLzA` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **FR** | `KZIXS6jz6PnuuUHuqyslQw` | `XcHdRqw-K2ftIrS8MsqvLw` | `PS64QODf9zsSu0PzoDKR9Q` | `lNm4SKfkKmvPY4tg4fxjeA` |
| **DE** | `fiMgSON0zaWUmxJ9k2KnNQ` | `VpZzTKzo9mpFnuLWmo1kmw` | `uXkyTiw73Ljj6c60sgWskg` | `5KA4QmAqfY86VW3OTHKIrw` |
| **IN** | `ODMXRWreCmibuO7aa7kZzg` | `a-V_RivZSiy2Pri6Xkc3ow` | `IJDZq2X_MTt-K4IW-CiGyg` | `g4elT69Qq60N4723no8YXw` |
| **USPA** | `XCHJTGgjxnw4xQJ9I6qoeQ` | `qv_TTexuU0NlDtjzAKsCNg` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **USNJ** | `HnWiQiOzzpHg2iR4GBON0w` | `67SYQ-1ZQONBAk-iEattCQ` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **USMI** | `XCHJTGgjxnw4xQJ9I6qoeQ` | `qv_TTexuU0NlDtjzAKsCNg` | `Pr2PQif-ldRX_zAJEhHxNA` | `C-W_T6M9KSlLBtRcYOcefw` |
| **CAON** | `XGMFQy8devodjQfZE08Icg` | `WUBKT2fwx4LT90URPe4BiQ` | `Ao9vS2FaGg4tcKJnYnImhQ` | `GpCtQ6uXlYjlW2jSb1FM1A` |

### Shared Enterprise Keys (reused across many licenses)
- Enterprise Key (shared): `Pr2PQif-ldRX_zAJEhHxNA`
- Enterprise Secret (shared): `C-W_T6M9KSlLBtRcYOcefw`
- NL/RUSO/NET Enterprise Key: `e14fSGhHd49M9QioWcOt9g`
- NL/RUSO/NET Enterprise Secret: `eevcSOrEfelau-7SkDx4qQ`

---

## 11. OneTrust Consent IDs (per-license)

| License | OneTrust App ID |
|---|---|
| **CH** | `1f44-c644-b96a52fb790b4b-debe-b521d3` |
| **NET** | `651e-0e4a-fcc8d0dd160bc6-4bab-2f17a5` |
| **RUSO** | `c67a-274d-b21e4012ebc64d-319f-333001` |
| **BR** | `0f85-dd40-38e4b89816b23c-5e87-c9f781` |
| **GR** | `5e7c-8746-03f5c26875d00f-5da2-134bfc` |
| **COM** | `5b53-a541-99230f53250438-6695-18f34d` |
| **IT** | `b9f7-ca4d-07a359d8e3a5cd-44ae-f789fd` |
| **ES** | `8595-1748-7f37e31f478968-d08b-9591ca` |
| **DK** | `d6b3-4f45-763c5831bdafc2-b4a5-518cb6` |
| **BG** | `9521-3145-8d755ca8069da0-52be-d72ad0` |
| **PT** | `6fca-b140-7ca464a4825f55-19b9-1549f7` |
| **RO** | `3e8b-be4d-251b4e969a5dcd-9dae-dbf6ec` |
| **SE** | `f319-764d-fe33a618ac8ce6-2f98-6daa75` |
| **EE** | `6625-9d4c-218649188e4c3a-ffa7-e587d0` |
| **BE** | `7985-1b4e-ad1590913f0ad5-9788-a4c54d` |
| **EU** | `57a8-d849-7ce9674a5e548d-e29d-90f790` |
| **UK** | `1d18-0b49-a221718e311676-ba8b-06e1d0` |
| **FR** | `0a3a-a747-c4053c528b71ee-bea6-56b8ab` |
| **DE** | `953c-cd49-9d25ab67c98e95-b18a-c8b9b8` |
| **IN** | `9724-634a-2053d501e377b8-9fb3-0c8a24` |
| **USPA/USNJ/USMI** | `44e3-624d-a6e0d1e3c3d765-1785-7adbab` |
| **CAON** | `ac72-3b49-33b2979d442747-5985-4969f4` |

---

## 12. Casino Lobby API

### REST Endpoints (CLB Service)
```
/clbservice/player/login
/clbservice/player/logout
/clbservice/player/appdata
/clbservice/player/activebonus2
/clbservice/player/firstfsb
/clbservice/player/fsb
/clbservice/player/esgamesession
/clbservice/player/games/recommended
/clbservice/player/games/playergames
/clbservice/player/games/recent
/clbservice/player/rapid
/clbservice/games/launch
/clbservice/games/resume
/clbservice/games/select/all
/clbservice/games/select/livecasino
/clbservice/game/getPopularGames
/clbservice/prizeGame/acceptTerms
/clbservice/prizeGame/latestTCVersion
/clbservice/races/acceptTerms
/clbservice/races/all
/clbservice/races/join
/clbservice/races/leaderboard
/clbservice/races/user
/clbservice/utils/auxstatus
/clbservice/utils/messages
/clbservice/ws/stmp
```

### StarsWeb REST APIs
```
api/v1-preview/auth/session
api/v1-preview/account/sumsub/token
api/v1-preview/account/docverify/state
api/v1-preview/tierupdown
api/v0/wc3/bonus/getCodeInfo
api/v0/wc3/user/check/fiscalCode
api/v0/wc3/user/get/italyBirthPlace
```

---

## 13. Game Protocol Messages

### Table Messages
```
MSG_TABLE_LOGIN / MSG_TABLE_LOGOUT
MSG_TABLE_SIT1 / MSG_TABLE_SIT2
MSG_TABLE_SITIN / MSG_TABLE_FORCE_SITOUT
MSG_TABLE_ADDCHIPS / MSG_TABLE_CHIPSAVAIL
MSG_TABLE_ENABLE_TIMEBANK
MSG_TABLE_HAND_RANK
MSG_TABLE_THROW (throw animation)
MSG_TABLE_IHH_GET_HANDBLOB (instant hand history)
MSG_TABLE_PLAYER_CARD_DICTIONARY_UPDATE
MSG_TABLE_USER_DICTIONARY_UPDATE
MSG_TABLE_SUBSCR_BEGINHAND
MSG_TABLE_SUBSCR_ENDHAND
MSG_TABLE_SUBSCR_NEWGAME
MSG_TABLE_SUBSCR_ACTION
MSG_TABLE_SUBSCR_ANIMATION
MSG_TABLE_SUBSCR_DEALPLAYERCARDS
MSG_TABLE_SUBSCR_DEALBOARD_RIT (Run-It-Twice)
MSG_TABLE_SUBSCR_MOVETOPOT
MSG_TABLE_SUBSCR_POT_DISTRIBUTION
MSG_TABLE_SUBSCR_KNOCKOUT
MSG_TABLE_SUBSCR_MESSAGE / MESSAGE2
MSG_TABLE_SUBSCR_I18N_MESSAGE
MSG_TABLE_SUBSCR_CHAT_BUBBLE
MSG_TABLE_SUBSCR_THROW
MSG_TABLE_SUBSCR_DELAYED_TABLECLOSE
```

### Lobby Messages
```
MSG_LOBBY_REGISTER_NEW_USER
MSG_LOBBY_VALIDATE_MOBILE / RESEND_MOBILE_VALIDATION
MSG_LOBBY_NAME_AVAILABLE
MSG_LOBBY_ADMIN_INFO
MSG_LOBBY_COMPARE_SITE_FOR_IP
MSG_LOBBY_FORCECLIENTLOGOUT
MSG_LOBBY_JOIN_SEATFINDER / UNJOIN / GET_JOINED
MSG_LOBBY_SEATFINDER_CHECK_CHIPS
MSG_LOBBY_FIND_SIMILAR_TABLE_BY_TYPE
MSG_LOBBY_REGISTER_TOURN_USER
MSG_LOBBY_UPDATE_USER2
MSG_LOBBY_SET_BUYIN_LIMIT_EX
MSG_LOBBY_EXCLUDE_PLAYER
MSG_LOBBY_DONT_SHOW_WHERE
MSG_LOBBY_DISABLE_SNG_AUTO_UNREG
MSG_LOBBY_NOTIFICATION / NOTIFICATION_PGAD_IS_BACK
MSG_LOBBY_PLAYER_BLACKLISTED_NOTIFY
MSG_LOBBY_REMAINING_PLAYING_TIME_NOTIFY
MSG_LOBBY_CLIENT_CURR_CONV_OPT
MSG_LOBBY_GET_ARJEL_EVENTS
MSG_LOBBY_TOURN_INVITE
MSG_LOBBY_TOURN_REG_INFO_64
MSG_LOBBY_REMIND_SID
MSG_LOBBY_REQUEST_RM_ACCOUNT_NOTIFY
MSG_LOBBY_CLI_PWD_CHANGE_REMINDER
MSG_LOBBY_CLI_SEATFINDER_SEATED / REMOVE_NOTIFY
MSG_LOBBY_FIND_REGISTERING_TOURN_BYREF
```

### Mobile Lobby NG
```
MSG_MLOBBYNG_FILTER_GAMES
MSG_MLOBBYNG_GET_BRANDED_LOBBIES
MSG_MLOBBYNG_GET_GAME_INFO
MSG_MLOBBYNG_GET_SUGGESTED_GAMES2
MSG_MLOBBYNG_SATELLITES_TO_TOURN
MSG_MLOBBYNG_SEARCH_BY_NAME
MSG_MLOBBYNG_SNG_COUNTS
MSG_MLOBBYNG_TABLE_TYPE_COUNTS
MSG_MLOBBYNG_TOURNAMENT_COUNTS
```

### Lobby Etc (Miscellaneous)
```
MSG_LOBBYETC_SIGNAL_EVENT_LOGIN / INSTALLATION
MSG_LOBBYETC_GET_LOGIN_LIMIT_INFO
MSG_LOBBYETC_GET_SESSION_STATS / WINLOSS_DATA
MSG_LOBBYETC_SET_GAME_LIMITS2
MSG_LOBBYETC_GET_ALL_APPROVED_GAME_LIMITS
MSG_LOBBYETC_GET_REALITY_CHECK_FREQ
MSG_LOBBYETC_PLAYER_SESSION_TIMEOUT
MSG_LOBBYETC_LUGAS_LONG_SESSION_ACK (German LUGAS regulation)
MSG_LOBBYETC_GET_USER_PROPS
MSG_LOBBYETC_GET_MY_STARS_COUNTERS
MSG_LOBBYETC_CLI_GET_IMAGE_GALLERY / SET_USER_GALLERY_IMAGE
MSG_LOBBYETC_CLI_ICE_GET_UPDATES / SET_ALL_USER_BOARD_PREF
MSG_LOBBYETC_CLI_TWITCH_CONNECT
MSG_LOBBYETC_GEOCOMPLY_LOCATE
MSG_LOBBYETC_CLI_NOTIFY_ACCOUNT_REINSTATE
MSG_LOBBYETC_CLI_NOTIFY_CVL_STATE
MSG_LOBBYETC_CLI_NOTIFY_ICE_NUDGE
MSG_LOBBYETC_CLI_NOTIFY_LOGOUT_APC
MSG_LOBBYETC_CLI_NOTIFY_LUGAS_LONG_SESSION
MSG_LOBBYETC_CLI_NOTIFY_MPC_ISSUED
MSG_LOBBYETC_CLI_NOTIF_GEOIP_RESULT
MSG_LOBBYETC_CLI_SE_SESSION_NOTIF
MSG_LOBBYETC_CVL_OPTED_IN
MSG_LOBBYETC_SE_CHANGE_USER_NOTIFICATION
MSG_LOBBYETC_U_POOL_BLOCK_TIME_PENALTY_UPDATE
MSG_LOBBYETC_U_UPDATE_FLAGS_PRIV
MSG_LOBBYETC_CLI_UNSOLICITED_NOTIFICATION
MSG_LOBBYETC_GET_CVL_STATE_FOR_USER
MSG_LOBBYETC_CLI_GET_IMAGE_USER_APPROVALS
```

### Cashier Messages
```
MSG_CASHIER_CHIPS_INFO2
MSG_CASHIER_GET_USER_LIMIT / SET / _EX variants
MSG_CASHIER_GET_SPENDING_LIMIT / SET
MSG_CASHIER_PLAY_MONEY_REFILL / GET_INFO
MSG_CASHIER_SET_USERROLL_STATUS
MSG_CASHIER_SET_GAMETICKET_STATUS
MSG_CASHIER_USER_LOGGED_IN
MSG_CASHIER_GET_RM_NOK_HELD_FUNDS
MSG_CASHIER_TO_CLIENT_INFO_NOTIFICATION
MSG_CASHIER_TO_CLIENT_USERROLLS_GAMETICKETS_DATA_NOTIFICATION
MSG_CASHIER_TO_CLIENT_USERROLL_CLEARED_NOTIFICATION
```

### Tournament (MTL)
```
MTL_LOBBY_REGISTER_USER / UNREGISTER
MTL_LOBBY_TOURNAMENT_USER_STATS_64
MTL_LOBBY_WHERE_IS_PLAYER
MTL_USER_SITIN / ADDON / REBUY / DECLINE_REBUY
MTL_USER_AUTO_RELOAD_STACKS_NOTIFY
MTL_GET_IMREADY / SET_IMREADY
MTL_CLIENT_SIMPLE_DEAL_ATTEMPT_COMPLETED
```

### Poker Client Gateway
```
MSG_POKER_CLIENT_GATEWAY_GET_USER_ASSETS
MSG_POKER_CLIENT_GATEWAY_SET_PRESTIGE_TO_SHOW
MSG_POKER_CLIENT_GATEWAY_USER_SAW_NEW_PRESTIGE
MSG_POKER_CLIENT_GATEWAY_TWITCH_CONNECT
MSG_POKER_CLIENT_GATEWAY_TWITCH_CHECK_CONNECTION_STATUS
```

### Regulator Messages
```
MSG_REGULATOR_GET_SWISS_URL
MSG_REGULATOR_ES_SET_SESSION_LIMITS
MSG_REGULATOR_RE_INSTATE_USER
MSG_REGULATOR_SAVE_USER_NET_DEPOSIT_LIMIT_CHOICE
MSG_REGULATOR_SET_AUTO_ACCEPT_PRICE_CHANGES_FLAG
MSG_REGULATOR_GET_USER_LOGOUT_INFO
```

### Other Protocol Messages
```
MSG_RESOLVER_TAG / _REPLY
MSG_PPP_REG_INFO / UNREGISTER_USER / SET_ENTRY_STATUS
MSG_SAG_TOURN_REG_INFO_BY_SCRIPTID
BL_USER_BUYIN / SITIN / ADDON / GET_INFO / GET_ENTRIES / SET_AUTOREBUY / GET_BUYIN_INFO
HG_ADD_USER_CLUB / GET_CLUB_INFO / GET_CLUB_GAME_INFO / GET_USER_CLUBS_ATF / CHANGE_PLAYERS_STATUS
PS_Q_FILTER_GAMES / SEARCH_BY_NAME / GET_TICKET_COUNTS / GET_TICKET_TOURNS2
PS_Q_GET_BRANDED_LOBBIES / GET_SUGGESTED_GAMES / SATELLITES_TO_TOURN
PS_Q_GET_RECENT_GAME_LIST / GAMES_HAVE_TICKETS_FOR
TS_Q_I18N_GET_TRANSLATED_INTERNAL_ERROR
MINIGAME_MSG_TICKET_LOOKUP
```

---

## 14. Payment Providers

| Provider | Evidence |
|---|---|
| **Apple Pay** | `merchant.pokerstars.uk`, `merchant.production.pokerstars.uk` |
| **Plaid** | LinkKit 4.3.1 framework (bank linking) |
| **Adyen** | `ERR_ADYENHOSTED_MISCONFIGURATION` error string |
| **PayPal** | `DBM_PAYPAL_TRANS_XED` string |
| **Google Pay** | Encrypted `googlepay.js` module |
| **MitID** | Denmark digital ID integration |
| **NemID** | Denmark legacy digital ID |
| **BankID** | Sweden digital ID |
| **RSA SecurID** | Hardware token 2FA for login |

---

## 15. Jailbreak Detection

### URL Scheme Checks (LSApplicationQueriesSchemes)
```
cydia://        — Cydia app store
activator://    — Activator tweak
filza://        — Filza file manager
zbra://         — Zebra package manager
sileo://        — Sileo package manager
undecimus://    — unc0ver jailbreak
```

### File System Checks
```
/Applications/Cydia.app
/Library/MobileSubstrate/MobileSubstrate.dylib
/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist
/Library/MobileSubstrate/DynamicLibraries/Veency.plist
/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist
/private/jailbreak.txt
/private/var/lib/cydia
/private/var/tmp/cydia.log
/private/var/lib/apt/
/bin/bash
/etc/apt
/usr/bin/sshd
/usr/sbin/sshd
```

### GeoComply Anti-Spoofing
```
GPSTravellerTweakVIP + GPSTravellerTweakVIP.plist
LocationFakerX + LocationFakerX.plist
installed_tweaks enumeration
ios_app_hooked (hook detection)
ios_audio_detection
```

### Debugger Detection
```
sysctl / sysctlbyname (kern.proc process inspection)
IsDebuggerAttachedEv / BreakDebuggerEv (C++ events)
GCDebuggerDetectionOperation (GeoComply)
AppsFlyer sanity: isSimulator, isDevBuild, isJailBroken, isDebuggerAttached
/dev/tty (terminal detection)
```

### Integrity Checks
```
INTEGRITY_VIOLATION_ATTEMPT
DataIntegrityCheck / PYRA_DataIntegrityCheck
AFSDKChecksum
checksumEnabled
commsslchksum.cpp
PRAGMA integrity_check (SQLite)
```

### Configurable Toggle
```
skipAdvancedJailbreakValidation (AppsFlyer)
_skipAdvancedJailbreakValidation (native)
promptJailbrokenWarning (UI warning)
```

---

## 16. Crypto Stack

### OpenSSL
- **Version:** OpenSSL 3.3.2 (3 Sep 2024)
- **Type:** Statically linked (FIPS-certified)
- **Build Path:** `/Users/alexeys/Projects/fips-mobile-client/platform/openssl/ios/3.X/iPhoneOS/arm64`
- **TLS 1.3 support** with modern ciphers

### Symmetric Encryption
- **AES-256:** Password encoding (`aes256-password-encoding.on` feature flag)
  - `toAES256EncryptWithKey:` / `toAES256DecryptWithKey:`
  - `CommClientAesEncryptedGuard` for communication
- **AES-128:** AppsFlyer analytics encryption (`AppsFlyerAES128Crypto`)
- Supported: AES-CBC, ECB, CTR, GCM, CFB, OFB, XTS, SIV, OCB, CCM, WRAP
- Also: ARIA, DESX, SEED, CHACHA20-POLY1305

### Asymmetric Encryption
- **RSA:** Login via RSA SecurID + `CommClientRsaGuard`
- **ECDH:** `CommSSLECDH::generateKeys` / `generateSecret` (forward secrecy)
- **DH:** `CommSSLDH::generateSecret` (classic Diffie-Hellman)

### Key Derivation
- **PBKDF2:** `PKCS5_pbkdf2_set_ex` (password-based)
- **HKDF:** TLS 1.3 key derivation
- **scrypt:** Available (`SCRYPT_PARAMS`)
- **X9.63 KDF / X942KDF:** EC key agreement
- **Custom:** `commsslpasswordhash.cpp` module

### Hash Functions
- **SHA-256:** Primary (`sha256:`, `sha256InBytes:`)
- **SHA-1:** Device ID hashing (`sha1_idfa`, `sha1_idfv`)
- **MD5:** Legacy/analytics (`md5_idfa`, `md5_idfv`)
- **HMAC:** Message authentication (`hmacSig:`)
- **SHA-384/512:** Available

### Random Number Generation
- `SecRandomCopyBytes` + `kSecRandomDefault` (Apple CSPRNG — primary)
- `CCRandomGenerateBytes` (CommonCrypto)
- `arc4random` / `arc4random_uniform` (BSD)
- OpenSSL entropy: `ossl_rand_get_entropy`

### Keychain
- **Access Group:** `DRFJ9CFR4X.pokerstars`
- **Protection:** `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
- **Classes:** `kSecClassGenericPassword`
- **Wrappers:** `MfKeyChainBroker`, `AppsFlyerKeychainWrapper`, `APMKeychainWrapper`

### Biometric Auth
- FaceID/TouchID via `LocalAuthentication.framework`
- `touchIdCapable`, `canEvaluatePolicy:`, `evaluatePolicy:`
- `withBiometricLogin` / `withBiometricLoginFlow`

---

## 17. Device Fingerprinting

### Identifiers Collected
```
identifierForVendor (IDFV)     — md5_idfv, sha1_idfv
advertisingIdentifier (IDFA)   — md5_idfa, sha1_idfa, hashedIdfa
appsFlyerDeviceID              — AppsFlyer's own device ID
resettableDeviceID / hashedResettableDeviceID
deviceUUID
idfaChangeCount                — tracks IDFA resets
```

### Device Attributes
```
deviceModel / deviceModelVersion / deviceName
localizedModel
systemVersion
carrierName
timeZone / estTimeZone / localTimeZone
metadataFingerprint            — composite hash
```

### GeoComply Signals
```
ios_app_hooked (hook detection result)
hooked_id
installed_tweaks (tweak enumeration)
ios_audio_detection (audio analysis)
```

### Plaid Fingerprinting
```
fingerprintOpenSource + fingerprintPro (dual fingerprinting)
fingerprintProVisitorID (persistent visitor ID)
fingerprintDataCollected event
```

---

## 18. UI / Theme System

### PYR Stylesheet System (pyr-stylesheets.json)
- Device-responsive: `_5`, `_6`, `_6plus`, `_X`, `_ipad`, `_ipadpro`
- Dark/Light mode: `{app.withSystemAppearanceNavBar}`
- Drawer widths: 85%–100% (phone), 30%–35% (tablet)
- Bottom sheets, blur shadows, glass-morphism

### Foundation Layouts (foundation_layouts.json — 3,022 lines)
- Declarative JSON-driven UI framework
- All screens, menus, navigation defined in JSON
- Visibility rules based on license + player state + feature flags
- iPad split-screen awareness (half-screen, two-thirds-screen)

### Tab Bar Products
- **Poker** — Always visible
- **Casino** — Not in FR, BE, EE, BR, RUSO, IN, CH, NET
- **Live Casino** — UK, IT only
- **My Stars / PXR** — Promotions & Rewards
- **Sports** — Not in BG, BE, EE, BR, NET, RUSO, IN, CH, PT, USA

### Regional Branding
- **USMI:** Odawa branding
- **USPA:** Mount Airy branding
- **CH:** 777 branding
- **FR:** Regulatory link to joueurs-info-service.fr
- **Default:** Dynamic VIP logo

### Poker Table Themes (30+ variants)
table, zoom, spingo, spingoflash, spingomax, spingosixmax, fusion, knockout, knockout-zoom,
mystery-bounty, prestige, progressive-plus, showtime, sixplus-holdem, splitholdem, swap-holdem, tempest

### Promotional Themes (55+)
neymar, ept-season, bounty-builders, carnival-series, scoop, wcoop, winter-series, xmas,
sunday-million, sunday-storm, turbo-series, galactic, stealth, hot-turbos, euro2020, redbull, irish-open, etc.

### Feature Flags (dyn.hsp: system)
```
dyn.hsp:PromoExp_PromotionsAndRewards
dyn.hsp:StarsWebHelp
dyn.hsp:ng-action-bar-bounce-enabled
dyn.hsp:ng-cta-bounce-disabled
dyn.hsp:submit-documents
dyn.hsp:hideStarsPinMenu
dyn.hsp:hideRsaTokenMenu
dyn.hsp:hideOneTimePinMenu
dyn.hsp:chest_widget_table
dyn.hsp:withPNRHubUX-enabled
dyn.hsp:ng-casino-sotd-enabled
dyn.hsp:ng-with-new-casino-menu-sotd-enabled
dyn.hsp:ng-with-new-casino-menu-enabled
```

---

## 19. Localization (21 languages)

### iOS .lproj (11 locales)
en, da-DK, de, el, es, fr, hu, it, pt-PT, ru, sv

### Custom Translation Packs (21 languages)
| Language | File | Size |
|---|---|---|
| bg (Bulgarian) | lang.pak | 462 KB |
| cs (Czech) | lang.pak | 282 KB |
| da (Danish) | lang.pak | 257 KB |
| de (German) | lang.pak | 290 KB |
| el (Greek) | lang.pak | 479 KB |
| en (English) | lang.pak | 258 KB |
| es (Spanish) | lang.pak | 291 KB |
| es-419 (LatAm Spanish) | lang.pak | 313 KB |
| et (Estonian) | lang.pak | 263 KB |
| fr (French) | lang.pak | 304 KB |
| hu (Hungarian) | lang.pak | 300 KB |
| it (Italian) | lang.pak | 288 KB |
| ja (Japanese) | lang.pak | 326 KB |
| nl (Dutch) | lang.pak | 274 KB |
| pl (Polish) | lang.pak | 282 KB |
| pt (Portuguese) | lang.pak | 285 KB |
| pt-BR (Brazilian Portuguese) | lang.pak | 298 KB |
| ro (Romanian) | lang.pak | 295 KB |
| ru (Russian) | lang.pak | 451 KB |
| sv (Swedish) | lang.pak | 259 KB |
| uk (Ukrainian) | lang.pak | 433 KB |

Format: Proprietary binary `.lang.pak` (not standard .strings/.xliff)
Version marker: `translations/b4c4d82f43db9e81a03a1da9a691a909788e7019`

---

## 20. On-Demand Resources

| Tag | Asset Pack ID |
|---|---|
| `ps-bonusgames` | `ro.pokerstarsmobile.www.asset-pack-2b9e17e8835f8ef0c28499d0f4362e8c` |
| `ps-punter` | `ro.pokerstarsmobile.www.asset-pack-28cc4d02e029155ee0a9e08ebdfb9964` |

Both downloaded on-demand from App Store (not bundled).

---

## 21. Build Infrastructure (Leaked)

### CI/CD
```
Build Server:   /Volumes/bigdisk0/builds/workspace/mobile-prod/
Jenkins Job:    PROD-Jobs/PROD-MobileNG.iOS/
Project Name:   ios_starscasino
Platform path:  platform/modules/...
```

### Source Code Paths
```
platform/modules/commlib2a/          — Communication library (TCP/SSL/guards)
platform/modules/client_shared/      — Shared client code
  cocos/                             — Cocos2d-x rendering
  poker/table/                       — Poker table logic
  poker/history/                     — Hand history
  i18n/                              — Internationalization
  obscure/                           — Obfuscation module
platform/modules/atf/                — ATF (CIPWA connection)
platform/modules/client_certs/       — Client certificates
platform/modules/protocols/          — Protocol definitions
platform/modules/plib/               — Platform library
platform/services/services/          — Services
platform/ios/platform/mpsrv/         — MPSRV (message processing server)
```

### Developer Names
```
alexeys    — OpenSSL/FIPS compilation
sergueim   — MetalANGLE (Cocos2d-x renderer)
ivan.obodovskyi — AppsFlyer SDK integration
```

### Internal Framework
- **MfAppLibrary** = "Mobile Framework App Library"
- Architecture: SpadePlus with Router/Coordinator/Receiver/Transmitter pattern

---

## 22. Key Obfuscation System

### Method
Each API key is stored as arrays of 4-integer tuples in `service_keys.json` and `foundation_keys.json`.
Deobfuscation: Each integer XOR'd with `0x8F` (143 decimal) to produce the character.

### Deobfuscation Class
- Class: `MfKeyDeobfuscation` (in `MfAppLibrary` module)
- Protocol: `MfKeyDeobfuscationProtocol`
- Methods: `keyDeobfuscation` / `obfuscate:`

### Covered Keys (80+)
AppsFlyer, Google Analytics, Airship (per-license), OneTrust (per-license),
Addressy/Loqate, LivePerson, Salesforce, Health Counters

---

## 23. Encrypted Files

| File | Magic Header | Purpose |
|---|---|---|
| `res/brand.ini` | `7cac 2e26 4f35...` | Server configuration |
| `res/themes/modes.ini` | binary | Theme modes |
| `res/themes/themeinfo.ini` | binary | Theme info |
| `res/js/starsweb/init.js` | `7c ac 2e 26 4f 35` | WebView init |
| `res/js/starsweb/start.js` | `7c ac 2e 26 4f 35` | App startup |
| `res/js/starsweb/modules/casino.js` | `7c ac 2e 26 4f 35` | Casino module |
| `res/js/starsweb/modules/googlepay.js` | `7c ac 2e 26 4f 35` | Google Pay |
| `res/js/starsweb/modules/minigames.js` | `7c ac 2e 26 4f 35` | Mini-games |
| `res/js/starsweb/modules/touchpoint.js` | `7c ac 2e 26 4f 35` | CRM touchpoint |
| `res/js/starsweb/modules/twitch.js` | `7c ac 2e 26 4f 35` | Twitch integration |

All JS files share magic `7cac2e264f35` — proprietary PokerStars encryption, decrypted at runtime.

---

## 24. Entitlements

```xml
<dict>
    <key>com.apple.developer.networking.wifi-info</key>
    <true/>
    <key>keychain-access-groups</key>
    <array>
        <string>DRFJ9CFR4X.pokerstars</string>
    </array>
    <key>com.apple.developer.team-identifier</key>
    <string>DRFJ9CFR4X</string>
    <key>application-identifier</key>
    <string>DRFJ9CFR4X.ro.pokerstarsmobile.www</string>
    <key>aps-environment</key>
    <string>production</string>
    <key>com.apple.developer.in-app-payments</key>
    <array>
        <string>merchant.pokerstars.uk</string>
        <string>merchant.production.pokerstars.uk</string>
    </array>
    <key>com.apple.developer.associated-domains</key>
    <array>
        <string>applinks:amaya.onelink.me</string>
    </array>
</dict>
```

| Entitlement | Purpose |
|---|---|
| `wifi-info` | WiFi SSID/BSSID for GeoComply geolocation |
| `keychain-access-groups` | Shared keychain (`DRFJ9CFR4X.pokerstars`) |
| `aps-environment` | Production push notifications |
| `in-app-payments` | Apple Pay (UK merchants) |
| `associated-domains` | Universal Links via AppsFlyer/OneLink |

---

## 25. Privacy Manifest

### Declared Privacy APIs (PrivacyInfo.xcprivacy)
| API Category | Reason Code | Meaning |
|---|---|---|
| SystemBootTime | 35F9.1 | Measure time between events |
| DiskSpace | E174.1 | Check before writing to disk |
| FileTimestamp | C617.1 | Access file timestamps in container |
| UserDefaults | CA92.1 | Access own UserDefaults |

### Permission Descriptions (14 types!)
| Permission | Description |
|---|---|
| FaceID | Sign In with Face ID |
| Camera | Video chat tables and documentation |
| Microphone | Video chat tables |
| Photo Library | Uploading documents to CS for KYC |
| Photo Library Add | Uploading documents to CS for KYC |
| Location (Always) | Ensure real money gaming is available |
| Location (WhenInUse) | Ensure real money gaming is available |
| Local Network | Improve location accuracy |
| Bluetooth (Always) | Ensure real money gaming is available |
| Bluetooth (Peripheral) | Ensure real money gaming is available |
| Motion | Confirm within real money gaming location |
| Calendars | Manage tournament schedule |
| Reminders | Manage tournament schedule |
| Speech Recognition | Voice customer support features |
| User Tracking (ATT) | Personalized Navigation, Messaging, Promotions |

### Google Analytics Controls (all disabled)
```
GOOGLE_ANALYTICS_DEFAULT_ALLOW_AD_PERSONALIZATION_SIGNALS: false
GOOGLE_ANALYTICS_DEFAULT_ALLOW_AD_USER_DATA: false
GOOGLE_ANALYTICS_DEFAULT_ALLOW_AD_STORAGE: false
GOOGLE_ANALYTICS_DEFAULT_ALLOW_ANALYTICS_STORAGE: false
```

---

## 26. Legal / Licensing Entity

### EU/COM License
- **Entity:** TSG Interactive Gaming Europe Limited
- **Country:** Malta (Registration C54266)
- **MGA License:** MGA/B2C/213/2011 (August 1, 2018)
- **VAT:** MT24413927
- **MGA Verification:** `https://authorisation.mga.org.mt/verification.aspx?lang=EN&company=68341bc6-27d7-4a0c-a142-5e5f5526b206&details=1`
- **GLC Certification:** `https://access.gaminglabs.com/Certificate/Index?i=187`
- **RG Check:** `https://www.responsiblegambling.org/for-industry/rg-check-accreditation/`
- **IBIA:** `https://ibia.bet/`
- **Gambling Therapy:** `https://www.gamblingtherapy.org/?ReferrerID=342`
- **Copyright:** Rational Intellectual Holdings Limited, 2001–present

---

## PlugIn (1 extension only)

### PokerstarsNotificationAppExt.appex
- **Type:** UNNotificationServiceExtension
- **Bundle ID:** `ro.pokerstarsmobile.www.NotificationExt`
- **Purpose:** Rich push notifications via Airship SDK
- **Min iOS:** 14.0
- **Principal Class:** `NotificationService`
- **Linked:** AirshipServiceExtension.framework

No Today Widget, Share Extension, iMessage, Watch, or Intents extension.

---

## FairPlay DRM (SC_Info)

```
DRM Scheme:    FairPlay v2
sinf atom:     SC_Info/pokerstars.sinf (device binding)
supf cert:     SC_Info/pokerstars.supf (Apple FairPlay CA)
supp key:      SC_Info/pokerstars.supp (private key cert)
supx data:     SC_Info/pokerstars.supx (key hashes)
Replication:   sinf replicated to PlugIns/PokerstarsNotificationAppExt.appex/SC_Info/
User Hash:     0x6C4B1AA6
Platform:      iOS (0x00000002)
Tool:          P611
```

---

## Code Signature Stats

- **Total signed files:** 5,095
- **Frameworks:** 556 entries (36 unique frameworks)
- **Poker themes:** 3,574 files
- **Card images:** 346 files
- **Resource bundle:** 385 files
- **Translations:** 22 packs
- **JS modules:** 7 files

---

*End of analysis. This document covers every aspect of the PokerStars iOS IPA v3.90.1 (Build 80957) — Romania variant.*
