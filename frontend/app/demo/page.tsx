"use client";

// frontend/app/demo/page.tsx — amendment FIX-1.
//
// The browser half of PRD acceptance criteria 1-2. Until this page existed,
// the SDK -> gateway path was only ever proven from Python (the attacker
// console and backend/test_integration_smoke.py); nothing imported `sdk/`.
//
// What this page does, all against the REAL gateway:
//   1. registerPasskey()   — a real WebAuthn registration ceremony
//   2. loginWithPasskey()  — a real login, binding a non-exportable session
//                            key pair to the session
//   3. the SDK's own protection-state indicator, mounted and refreshed
//   4. kaavalFetch()       — one signed request to /api/transfer
//   5. the same request replayed WITHOUT a proof, so the block is visible
//      next to the success rather than merely described
//
// The private key never appears here. The SDK holds a non-exportable
// CryptoKey and a sign() closure; this page only ever sees a session id.

import { useCallback, useEffect, useRef, useState } from "react";
import {
  clearActiveSession,
  createProtectionIndicator,
  kaavalFetch,
  loginWithPasskey,
  registerPasskey,
  type KaavalSdkConfig,
  type ProtectionIndicatorHandle,
} from "@kaaval/sdk";

const GATEWAY_ORIGIN =
  process.env.NEXT_PUBLIC_BACKEND_ORIGIN?.replace(/\/$/, "") ??
  "http://localhost:8000";

// Must equal the gateway's WEBAUTHN_RP_ID exactly — the SDK checks this and
// refuses to continue on a mismatch, which is what stops a look-alike proxy
// origin from driving the ceremony (amendment FIX-4).
const RELYING_PARTY_ID =
  process.env.NEXT_PUBLIC_WEBAUTHN_RP_ID ?? "localhost";

const config: KaavalSdkConfig = {
  relyingPartyId: RELYING_PARTY_ID,
  gatewayOrigin: GATEWAY_ORIGIN,
};

type LogKind = "info" | "ok" | "blocked" | "error";

interface LogLine {
  id: number;
  kind: LogKind;
  label: string;
  detail: string;
}

const KIND_STYLES: Record<LogKind, string> = {
  info: "border-white/10 bg-white/5 text-slate-300",
  ok: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
  blocked: "border-amber-400/30 bg-amber-400/10 text-amber-200",
  error: "border-rose-400/30 bg-rose-400/10 text-rose-200",
};

export default function DemoPage() {
  const [username, setUsername] = useState("demo@kaaval.local");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [log, setLog] = useState<LogLine[]>([]);
  const nextId = useRef(0);
  const indicatorHost = useRef<HTMLDivElement | null>(null);
  const indicator = useRef<ProtectionIndicatorHandle | null>(null);

  const append = useCallback((kind: LogKind, label: string, detail: string) => {
    setLog((lines) => [
      ...lines,
      { id: nextId.current++, kind, label, detail },
    ]);
  }, []);

  // Mount the SDK's own indicator widget (T-AJ.6) rather than reimplementing
  // it — the point is to show the real SDK surface working in a browser.
  useEffect(() => {
    const host = indicatorHost.current;
    if (!host) return;
    indicator.current = createProtectionIndicator(host);
    return () => {
      indicator.current?.destroy();
      indicator.current = null;
    };
  }, []);

  const refreshIndicator = useCallback(() => {
    indicator.current?.refresh();
  }, []);

  const run = useCallback(
    async (name: string, task: () => Promise<void>) => {
      setBusy(name);
      try {
        await task();
      } catch (error) {
        append(
          "error",
          `${name} failed`,
          error instanceof Error ? error.message : String(error),
        );
      } finally {
        setBusy(null);
        refreshIndicator();
      }
    },
    [append, refreshIndicator],
  );

  const onRegister = () =>
    run("Register passkey", async () => {
      append("info", "Registering passkey…", `RP ID ${RELYING_PARTY_ID}`);
      const result = await registerPasskey(config, username);
      append(
        "ok",
        "Passkey registered",
        `credential ${result.credentialId.slice(0, 24)}…`,
      );
    });

  const onLogin = () =>
    run("Login", async () => {
      append("info", "Starting login ceremony…", username);
      const id = await loginWithPasskey(config, username);
      setSessionId(id);
      append(
        "ok",
        "Session bound to a non-exportable key",
        `session ${id.slice(0, 16)}…`,
      );
    });

  const onSignedTransfer = () =>
    run("Signed transfer", async () => {
      const body = JSON.stringify({ to_account: "acct-demo-1", amount: 250 });
      append("info", "Sending a signed request…", "POST /api/transfer");
      const response = await kaavalFetch(config, "/api/transfer?mode=protected", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
      });
      const payload = await response.json();
      if (response.ok) {
        append(
          "ok",
          `Signed request accepted (HTTP ${response.status})`,
          JSON.stringify(payload),
        );
      } else {
        append(
          "blocked",
          `Signed request rejected (HTTP ${response.status})`,
          JSON.stringify(payload),
        );
      }
    });

  // The contrast case: the same endpoint, same body, no X-KAAVAL-Proof.
  // This is what a stolen cookie alone can do once PulseLock is on.
  const onUnsignedTransfer = () =>
    run("Unsigned transfer", async () => {
      append("info", "Sending the same request WITHOUT a proof…", "no X-KAAVAL-Proof");
      const response = await fetch(
        `${GATEWAY_ORIGIN}/api/transfer?mode=protected`,
        {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ to_account: "acct-demo-1", amount: 250 }),
        },
      );
      const payload = await response.json();
      append(
        response.ok ? "error" : "blocked",
        response.ok
          ? `Unsigned request WAS ACCEPTED (HTTP ${response.status}) — this should not happen`
          : `Unsigned request blocked (HTTP ${response.status})`,
        JSON.stringify(payload),
      );
    });

  const onReset = () => {
    clearActiveSession();
    setSessionId(null);
    setLog([]);
    refreshIndicator();
  };

  const loggedIn = sessionId !== null;

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex min-h-screen w-full max-w-4xl flex-col gap-6 px-5 py-10 sm:px-8">
        <header className="border-b border-white/10 pb-6">
          <p className="text-xs font-semibold tracking-[0.28em] text-slate-400 uppercase">
            PulseLock browser demo
          </p>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white">
            Prove possession, not just presentation
          </h1>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Every button below drives the real{" "}
            <code className="rounded bg-white/10 px-1.5 py-0.5 text-xs">
              @kaaval/sdk
            </code>{" "}
            against the live gateway at{" "}
            <code className="rounded bg-white/10 px-1.5 py-0.5 text-xs">
              {GATEWAY_ORIGIN}
            </code>
            . Nothing here is mocked.
          </p>
        </header>

        <section className="flex flex-col gap-4 rounded-2xl border border-white/10 bg-white/5 p-5">
          <label className="flex flex-col gap-2 text-sm">
            <span className="text-slate-300">Username</span>
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              disabled={busy !== null}
              className="rounded-lg border border-white/10 bg-slate-900 px-3 py-2 text-slate-100 outline-none focus:border-emerald-300/50"
            />
          </label>

          <div className="flex flex-wrap gap-3">
            <Action onClick={onRegister} busy={busy} label="1 · Register passkey" />
            <Action onClick={onLogin} busy={busy} label="2 · Log in" />
            <Action
              onClick={onSignedTransfer}
              busy={busy}
              label="3 · Signed transfer"
              disabled={!loggedIn}
            />
            <Action
              onClick={onUnsignedTransfer}
              busy={busy}
              label="4 · Same request, no proof"
              variant="danger"
            />
            <Action onClick={onReset} busy={busy} label="Reset" variant="quiet" />
          </div>

          <p className="text-xs leading-5 text-slate-500">
            Step 4 needs no session — that is the point. It is the request an
            attacker holding only a cookie can make.
          </p>
        </section>

        <section className="flex-1">
          <h2 className="mb-3 text-sm font-semibold tracking-wide text-slate-300 uppercase">
            What actually happened
          </h2>
          {log.length === 0 ? (
            <p className="rounded-xl border border-dashed border-white/10 px-4 py-8 text-center text-sm text-slate-500">
              Nothing yet. Start with “Register passkey”.
            </p>
          ) : (
            <ol className="flex flex-col gap-2">
              {log.map((line) => (
                <li
                  key={line.id}
                  className={`rounded-xl border px-4 py-3 text-sm ${KIND_STYLES[line.kind]}`}
                >
                  <p className="font-medium">{line.label}</p>
                  <p className="mt-1 font-mono text-xs break-all opacity-80">
                    {line.detail}
                  </p>
                </li>
              ))}
            </ol>
          )}
        </section>

        {/* The SDK mounts its own indicator element in here. */}
        <div ref={indicatorHost} aria-label="PulseLock protection state" />
      </div>
    </main>
  );
}

function Action({
  onClick,
  label,
  busy,
  disabled,
  variant = "primary",
}: {
  onClick: () => void;
  label: string;
  busy: string | null;
  disabled?: boolean;
  variant?: "primary" | "danger" | "quiet";
}) {
  const styles = {
    primary:
      "border-emerald-300/30 bg-emerald-300/10 text-emerald-200 hover:bg-emerald-300/20",
    danger:
      "border-amber-300/30 bg-amber-300/10 text-amber-200 hover:bg-amber-300/20",
    quiet: "border-white/10 bg-white/5 text-slate-300 hover:bg-white/10",
  }[variant];

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy !== null || disabled}
      className={`rounded-lg border px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${styles}`}
    >
      {busy === label ? "Working…" : label}
    </button>
  );
}
