# KAAVAL — Two-Laptop Demo Re-Engineering: LAN + mkcert (replaces ngrok)

> This is an amendment to `KAAVAL_Two_Laptop_Demo_Plan.md`, not a rewrite. Everything in that document's Scenes 1-5, dialogue, and fallback table stays as-is. This changes exactly one thing: how Laptop A reaches Laptop B — a trusted local network connection instead of a public tunnel. Nothing about PulseLock, Guardian, Radar, or Chronicle's logic changes.

## 1. Why this change

The original plan routes Laptop A → public internet → ngrok → Laptop B, for two machines sitting in the same room. That trades a risk you don't have (no LAN available) for one you do have on stage (tunnel latency, ngrok free-tier disconnects, DNS propagation, a subdomain that isn't fixed until the moment you start the tunnel). It also means `WEBAUTHN_RP_ID` isn't known until demo day, so it can't be tested in advance under the exact value you'll use live.

The fix: both laptops are physically co-located, so use that. A local network connection with a real, browser-trusted certificate removes the tunnel as a failure surface entirely and turns today's "emergency fallback" (LAN IP) into the primary, rehearsed path.

## 2. New topology

```text
LAPTOP A (Victim)                              LAPTOP B (Attacker / Host / SOC Projector)
------------------                             -------------------------------------------
[ Chrome Browser ]                             [ WiFi hotspot OR shared venue WiFi ]
       │                                                        │
       │ HTTPS (mkcert-trusted cert,                            │
       │ no public tunnel)                                      │
       ▼                                                        ▼
https://kaaval.demo  ───── LAN ─────►  [ attacker-proxy.js ] (terminates TLS, port 443)
                                                        │
                                                        │ Intercepts & logs Set-Cookie headers
                                                        ▼
                                                [ Next.js Frontend ] (Port 3000)
                                                        │
                                                        ▼
                                                [ FastAPI Gateway ] (Port 8000)
                                                        │
                                        ┌───────────────┴───────────────┐
                                        ▼                                ▼
                                [ SQLite DB ]                    [ SOC Dashboard ]
                                                                          ▲
                                                                          │
                                                                [ Chronicle LLM ]
```

No ngrok. No public internet dependency for the attack path (Chronicle's live LLM call is still the one deliberate external dependency, per TRD §8/NFR-6, and still has its scripted fallback).

## 3. One-time setup (do this before demo day, not on stage)

### 3.1 Fix the hostname and IP in advance

Pick one fixed hostname for every rehearsal and the live demo — don't regenerate it per session.

```text
DEMO_HOSTNAME=kaaval.demo
```

Find Laptop B's LAN IP once the venue network is known (or once the hotspot is up):

```bash
# macOS
ipconfig getifaddr en0
# Linux
hostname -I
# Windows
ipconfig
```

### 3.2 Generate a browser-trusted cert with mkcert (Laptop B)

```bash
# install mkcert (once)
brew install mkcert        # macOS
# or: choco install mkcert  (Windows)
# or: apt install libnss3-tools && download the mkcert binary (Linux)

mkcert -install             # installs mkcert's local CA into Laptop B's trust store
mkcert kaaval.demo          # generates kaaval.demo.pem + kaaval.demo-key.pem in the current dir
```

Move the two generated files into `attacker-proxy/certs/`.

### 3.3 Trust the same CA on Laptop A

mkcert's root CA is a single file (`rootCA.pem`, found via `mkcert -CAROOT` on Laptop B). Copy it to Laptop A and install it into Chrome's trust store *before* demo day:

```bash
# find it on Laptop B
mkcert -CAROOT
# copy rootCA.pem to Laptop A, then on Laptop A:
mkcert -install    # if mkcert is installed there too, simplest path
```

If you'd rather not install mkcert on Laptop A at all, import `rootCA.pem` manually into the OS certificate trust store (macOS Keychain → System → Certificates → mark "Always Trust"; Windows: `certmgr.msc` → Trusted Root Certification Authorities → Import).

### 3.4 Point Laptop A's hostname at Laptop B

Edit Laptop A's hosts file, mapping the fixed hostname to Laptop B's LAN IP found in §3.1:

```text
# macOS/Linux: /etc/hosts
# Windows: C:\Windows\System32\drivers\etc\hosts

192.168.1.15   kaaval.demo
```

Confirm resolution:

```bash
ping kaaval.demo
```

### 3.5 Update `attacker-proxy.js` to terminate TLS directly

```javascript
// attacker-proxy.js
const https = require('https');
const fs = require('fs');
const httpProxy = require('http-proxy'); // or your existing proxy lib

const TARGET = process.env.TARGET || 'http://localhost:3000';
const PORT = process.env.PORT || 443;

const options = {
  key: fs.readFileSync('./certs/kaaval.demo-key.pem'),
  cert: fs.readFileSync('./certs/kaaval.demo.pem'),
};

const proxy = httpProxy.createProxyServer({ target: TARGET, changeOrigin: true });

proxy.on('proxyRes', (proxyRes, req) => {
  const setCookie = proxyRes.headers['set-cookie'];
  if (setCookie) {
    console.log('[captured cookie]', { time: new Date().toISOString(), cookies: setCookie });
  }
});

https.createServer(options, (req, res) => proxy.web(req, res)).listen(PORT, () => {
  console.log(`attacker-proxy listening on https://kaaval.demo:${PORT}`);
});
```

Port 443 needs elevated privileges on most OSes — run with `sudo` on Laptop B, or use `authbind`/`setcap`, or just pick a non-privileged port (e.g. `8443`) and put it in the hosts-file-adjacent URL (`https://kaaval.demo:8443`) if you'd rather not run the proxy as root.

### 3.6 Environment variables (Laptop B, `backend/.env`)

```bash
DATABASE_URL=sqlite:///./kaaval.db
WEBAUTHN_RP_ID=kaaval.demo
WEBAUTHN_RP_ORIGIN=https://kaaval.demo
NONCE_TTL_SECONDS=30
REQUEST_FRESHNESS_WINDOW_SECONDS=30
```

Fixed, known, testable days in advance — not dependent on whatever subdomain a tunnel service assigns that day.

### 3.7 Next.js rewrites — unchanged

`frontend/next.config.js`'s rewrite rules from the original plan (§4.1) are unaffected — they still point `/auth/*`, `/api/*`, `/guardian/*`, `/radar/*`, `/events/*` at `http://localhost:8000` on Laptop B. Nothing here changes because the routing hop being replaced is Laptop A → Laptop B, not Laptop B's internal service-to-service routing.

### 3.8 Browser SDK config — unchanged

`frontend/app/demo/page.tsx`'s origin-relative config still works as-is:

```typescript
const sdkConfig: KaavalSdkConfig = {
  relyingPartyId: window.location.hostname,  // now resolves to "kaaval.demo"
  gatewayOrigin: window.location.origin,      // now resolves to "https://kaaval.demo"
};
```

## 4. One-command startup — `start-demo.sh`

Replaces manually driving 5 terminal tabs. Run from repo root on Laptop B.

```bash
#!/usr/bin/env bash
set -e

echo "Starting KAAVAL demo stack..."

# 1. Backend
(cd backend && source venv/bin/activate && uvicorn main:app --port 8000 --reload) &
BACKEND_PID=$!

# 2. Frontend
(cd frontend && npm run dev -- -p 3000) &
FRONTEND_PID=$!

# 3. Wait for both to be reachable before starting the proxy
echo "Waiting for backend and frontend..."
until curl -sf http://localhost:8000/events/stream -o /dev/null 2>/dev/null || [ $? -eq 28 ]; do sleep 1; done
until curl -sf http://localhost:3000 -o /dev/null; do sleep 1; done
echo "Backend and frontend are up."

# 4. Attacker proxy (TLS-terminating, LAN-facing)
(cd attacker-proxy && TARGET=http://localhost:3000 PORT=443 node attacker-proxy.js) &
PROXY_PID=$!

echo ""
echo "KAAVAL demo stack is live:"
echo "  Backend:   http://localhost:8000"
echo "  Frontend:  http://localhost:3000"
echo "  Proxy:     https://kaaval.demo (LAN)"
echo ""
echo "Laptop A should browse to: https://kaaval.demo/demo"
echo "Press Ctrl+C to stop all services."

trap "kill $BACKEND_PID $FRONTEND_PID $PROXY_PID 2>/dev/null" EXIT
wait
```

Make it executable once: `chmod +x start-demo.sh`. Add a matching `stop-demo.sh` if you want a clean kill switch, or just rely on the `trap` above.

## 5. Updated fallback table

Replaces the original plan's §7 row for tunnel failure; every other row is unchanged.

| Failure scenario | Remedy |
|---|---|
| Laptop A can't resolve `kaaval.demo` | Re-check the hosts-file entry (§3.4) matches Laptop B's *current* LAN IP — this is the one value that can drift if either laptop reconnects to WiFi. Re-run `ping kaaval.demo` before walking on stage. |
| WiFi/hotspot drops mid-demo | If both laptops support it, switch to a wired connection via USB-C/Ethernet adapter with static IPs, update the hosts-file entry, restart `attacker-proxy.js`. Rehearse this switch once beforehand so it isn't improvised live. |
| Cert not trusted on Laptop A (padlock warning) | Confirm `rootCA.pem` was actually installed on Laptop A *before* today (§3.3) — this can't be fixed live without admin access to the cert store. Keep a Chrome flag as last resort: `--unsafely-treat-insecure-origin-as-secure="https://kaaval.demo"`. |
| Chronicle LLM API timeout | Unchanged from original plan: toggle `CHRONICLE_FALLBACK_MODE=true`. |
| Laptop A hardware biometrics fail | Unchanged from original plan: Chrome DevTools → WebAuthn → Virtual Authenticator. |

## 6. Pre-demo checklist

- [ ] `mkcert` cert generated for `kaaval.demo`, files in `attacker-proxy/certs/`.
- [ ] `rootCA.pem` installed in Laptop A's trust store, confirmed by loading `https://kaaval.demo` with **no** padlock warning, at least once before the live run.
- [ ] Laptop A's hosts file points at Laptop B's *current* LAN IP — re-verify same day, since venue WiFi can reassign IPs between rehearsal and demo.
- [ ] `backend/.env`'s `WEBAUTHN_RP_ID`/`WEBAUTHN_RP_ORIGIN` set to `kaaval.demo` — not the old `localhost` dev value from Amendment FIX-4, and not an ngrok subdomain.
- [ ] `start-demo.sh` run end-to-end at least once on the actual venue network, not just at your desk.
- [ ] Full Scene 1-5 dry run over the LAN path, including one deliberate WiFi-drop test of the wired-fallback row above.

## 7. What did not change

Scenes 1-5, their dialogue, the reason strings (`proof_absent`, `body_hash_mismatch`, `nonce_reused`, `unverified_publisher_with_offline_access_scope`), the Chronicle/Radar closing beats, and the Chronicle-LLM fallback contingency are all unchanged from the original two-laptop plan. This document only replaces *how Laptop A reaches Laptop B* and *how the stack is started* — the security logic, the modules, and the demo story are untouched.
