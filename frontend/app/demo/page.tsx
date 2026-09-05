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
//
// Presentation follows the Verge design system shared with the dashboard
// (design_md_files/DESIGN-theverge.md), via the same primitives in
// app/components/vergeUi.tsx. No behaviour changed in this redesign — every
// handler, ref and SDK call is exactly as before.

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

import { buttonStyles, Tag } from "@/app/components/vergeUi";

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

// Colour carries meaning here and is always paired with a text tag, never
// standing alone: mint for a success, a white spotlight for a deterministic
// refusal (PulseLock doing its job), ultraviolet for the alarming case — an
// unsigned request accepted, or a step that errored.
const KIND: Record<
  LogKind,
  { border: string; tag: "mint" | "white" | "violet" | "quiet"; word: string }
> = {
  info: { border: "border-hazard/15", tag: "quiet", word: "Info" },
  ok: { border: "border-mint", tag: "mint", word: "Accepted" },
  blocked: { border: "border-hazard/40", tag: "white", word: "Refused" },
  error: { border: "border-ultraviolet", tag: "violet", word: "Alert" },
};

// The colour-block story tiles that explain WHY the buttons above matter.
// Every claim is the project's own ground truth (CLAUDE.md one-liner, the
// PulseLock proof-of-possession model, PRD §4.2), not illustrative copy: the
// page's whole argument is that you should not trust what cannot be verified,
// so its own text has to be verifiable too. Layout mirrors the dashboard's
// SystemStory: an asymmetric 7/5, 5/7 grid, depth from fill not shadow.
const STORY = [
  {
    kicker: "The attack",
    title: "A stolen cookie is the whole prize",
    body: "Adversary-in-the-middle phishing runs a reverse proxy between you and the real site. It relays every step of your login, then skims the session cookie the site hands back. That cookie is a bearer credential: whoever holds it is trusted, no questions asked.",
    fill: "bg-mint text-inverted",
    span: "lg:col-span-7",
    scale: "text-[1.9rem] leading-[1.1] font-normal tracking-[0.02em]",
  },
  {
    kicker: "Why MFA is not enough",
    title: "A passkey login still leaves a cookie behind",
    body: "The proxy relays the passkey ceremony too. What it steals is the session that comes after, which is why presenting a cookie has to stop being enough on its own.",
    fill: "border-hazard/25 border bg-panel",
    span: "lg:col-span-5",
    scale: "text-[1.5rem] leading-none font-bold",
  },
  {
    kicker: "The fix",
    title: "The session is bound to a key that never leaves the browser",
    body: "At login the browser generates a non-exportable ECDSA P-256 key pair through the Web Crypto API. The private key never appears in a variable, a log, or any network payload, only signatures do.",
    fill: "bg-ultraviolet text-hazard",
    span: "lg:col-span-5",
    scale: "text-[1.5rem] leading-none font-bold",
  },
  {
    kicker: "What you just saw",
    title: "Same cookie, opposite outcome",
    body: "Every protected request carries a fresh signature the gateway re-checks, and a replay is rejected. Step 4 is the stolen-cookie request with no signature. Before PulseLock it is accepted; after step 5 the identical request is refused.",
    fill: "bg-hazard text-inverted",
    span: "lg:col-span-7",
    scale: "text-[1.9rem] leading-[1.1] font-normal tracking-[0.02em]",
  },
] as const;

export default function DemoPage() {
  const [username, setUsername] = useState("demo@kaaval.local");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [log, setLog] = useState<LogLine[]>([]);
  const [pulseLockOn, setPulseLockOn] = useState(false);
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
      const response = await kaavalFetch(config, "/api/transfer", {
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

  // The contrast case: the same endpoint, same body, no X-KAAVAL-Proof — a
  // stolen cookie alone. Its outcome is honest and depends on PulseLock:
  // BEFORE you enable it this is accepted (the vulnerability), AFTER you enable
  // it the identical request is refused. No ?mode= is forced; the server
  // decides from this session's PulseLock enrollment.
  const onUnsignedTransfer = () =>
    run("Unsigned transfer", async () => {
      append("info", "Sending the same request WITHOUT a proof…", "no X-KAAVAL-Proof");
      const response = await fetch(`${GATEWAY_ORIGIN}/api/transfer`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to_account: "acct-demo-1", amount: 250 }),
      });
      const payload = await response.json();
      append(
        response.ok ? "error" : "blocked",
        response.ok
          ? `Unsigned request WAS ACCEPTED (HTTP ${response.status}). A cookie alone still works (PulseLock is OFF)`
          : `Unsigned request blocked (HTTP ${response.status}). PulseLock refused a cookie with no proof`,
        JSON.stringify(payload),
      );
    });

  // The victim turns PulseLock ON for their own session. After this, a bare
  // cookie (theirs or a stolen copy) no longer works — only signed requests do.
  const onEnablePulseLock = () =>
    run("Enable PulseLock", async () => {
      append("info", "Enabling PulseLock for this session…", "POST /api/protection/enable");
      const response = await fetch(`${GATEWAY_ORIGIN}/api/protection/enable`, {
        method: "POST",
        credentials: "include",
      });
      const payload = await response.json();
      if (response.ok) {
        setPulseLockOn(true);
        append("ok", "PulseLock enabled for this session", JSON.stringify(payload));
      } else {
        append("error", `Could not enable PulseLock (HTTP ${response.status})`, JSON.stringify(payload));
      }
    });

  // Ends this session server-side (POST /auth/session/revoke) — distinct
  // from "Enable PulseLock": that only changes how THIS session is verified;
  // this ends the session itself. Exercises verify.py's check 1
  // (session_inactive), which runs before signature, origin/path, body_hash,
  // nonce or sequence — so it defeats even a validly-signed, never-replayed
  // request the attacker already captured.
  const onRevokeSession = () =>
    run("Revoke this session", async () => {
      append("info", "Revoking this session…", "POST /auth/session/revoke");
      const response = await fetch(`${GATEWAY_ORIGIN}/auth/session/revoke`, {
        method: "POST",
        credentials: "include",
      });
      const payload = await response.json();
      if (response.ok) {
        append(
          "ok",
          "Session revoked — any request bearing it is now refused, signed or not",
          JSON.stringify(payload),
        );
        clearActiveSession();
        setSessionId(null);
        setPulseLockOn(false);
      } else {
        append("error", `Could not revoke session (HTTP ${response.status})`, JSON.stringify(payload));
      }
    });

  const onReset = () =>
    run("Reset", async () => {
      // Un-enroll this session so the before/after can be replayed on stage.
      try {
        await fetch(`${GATEWAY_ORIGIN}/api/protection/disable`, {
          method: "POST",
          credentials: "include",
        });
      } catch {
        // best-effort; a fresh login starts a new, un-enrolled session anyway
      }
      clearActiveSession();
      setSessionId(null);
      setPulseLockOn(false);
      setLog([]);
      refreshIndicator();
    });

  const loggedIn = sessionId !== null;

  return (
    <main className="text-hazard min-h-[100dvh]">
      <div className="mx-auto flex min-h-[100dvh] w-full max-w-[900px] flex-col gap-8 px-6 py-10 lg:px-10">
        <header className="border-hazard/15 border-b pb-8">
          <p className="text-mint font-mono text-[0.8rem] font-semibold tracking-[0.18em] uppercase">
            PulseLock browser demo
          </p>
          <h1 className="font-display mt-4 text-[clamp(2.5rem,8vw,4.5rem)] leading-[0.95] tracking-[0.01em] uppercase">
            Prove possession,
            <br />
            not presentation
          </h1>
          <p className="text-muted mt-5 max-w-xl text-sm leading-6">
            Every button below drives the real{" "}
            <code className="text-mint font-mono">@kaaval/sdk</code> against the
            live gateway at{" "}
            <code className="text-mint font-mono break-all">
              {GATEWAY_ORIGIN}
            </code>
            . Nothing here is mocked.
          </p>
        </header>

        <section className="border-hazard/15 bg-panel rounded-feature flex flex-col gap-6 border p-6 sm:p-8">
          <label className="flex flex-col gap-2">
            <span className="text-meta font-mono text-[0.65rem] font-semibold tracking-[0.16em] uppercase">
              Username
            </span>
            {/* Input: tight 2px radius and a mint focus border, per the spec's
                "newspaper-form feel". */}
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              disabled={busy !== null}
              className="border-hazard/35 rounded-tag text-hazard focus:border-mint bg-transparent px-3 py-2.5 font-mono text-sm transition-colors duration-150 disabled:opacity-50"
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
            <Action
              onClick={onEnablePulseLock}
              busy={busy}
              label="5 · Enable PulseLock"
              variant="cta"
              disabled={!loggedIn || pulseLockOn}
            />
            <Action
              onClick={onRevokeSession}
              busy={busy}
              label="6 · Revoke this session"
              variant="danger"
              disabled={!loggedIn}
            />
            <Action onClick={onReset} busy={busy} label="Reset" variant="quiet" />
          </div>

          <p className="text-meta text-xs leading-5">
            Step 6 ends the session itself — not just PulseLock enrollment. If the
            attacker captured a validly-signed request beforehand, it is still
            refused afterwards: a dead session is checked before its signature is.
          </p>

          {/* State line as a colour-block, so PulseLock ON/OFF is legible from
              across a room: mint means protected, ultraviolet means exposed. */}
          <div
            className={`rounded-tile p-4 ${
              pulseLockOn ? "bg-mint text-inverted" : "bg-ultraviolet text-hazard"
            }`}
          >
            <p className="font-mono text-[0.72rem] font-semibold tracking-[0.14em] uppercase">
              {pulseLockOn ? "PulseLock ON" : "PulseLock OFF"}
            </p>
            <p className="mt-2 text-sm leading-5 opacity-90">
              {pulseLockOn
                ? "A bare cookie is now refused for this session; only signed requests work."
                : "This session is a plain bearer cookie. Run step 4 to see it accepted, then enable PulseLock (step 5) and run step 4 again."}
            </p>
          </div>

          <p className="text-meta text-xs leading-5">
            Step 4 needs no session key: that is the point. It is the request an
            attacker holding only a stolen cookie can make. Enabling PulseLock
            (step 5) is what turns that same request from accepted into refused.
          </p>
        </section>

        <section className="flex-1">
          <h2 className="font-mono text-[0.75rem] font-semibold tracking-[0.16em] uppercase">
            What actually happened
          </h2>

          {log.length === 0 ? (
            <p className="border-hazard/15 rounded-tile text-meta mt-4 border border-dashed px-4 py-10 text-center text-sm">
              Nothing yet. Start with step 1, Register passkey.
            </p>
          ) : (
            // The StoryStream rail from the dashboard: a dashed timeline spine
            // with each outcome as a pill-cornered tile beside it.
            <ol className="border-rule mt-4 space-y-3 border-l border-dashed pl-4 sm:pl-6">
              {log.map((line) => {
                const k = KIND[line.kind];
                return (
                  <li
                    key={line.id}
                    className={`rounded-tile bg-canvas border p-4 sm:p-5 ${k.border}`}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Tag tone={k.tag}>{k.word}</Tag>
                      <p className="text-sm font-bold">{line.label}</p>
                    </div>
                    <p className="text-meta mt-2 font-mono text-[0.72rem] leading-5 break-all">
                      {line.detail}
                    </p>
                  </li>
                );
              })}
            </ol>
          )}
        </section>

        <section
          aria-labelledby="demo-story-title"
          className="border-hazard/15 border-t pt-10"
        >
          <h2
            id="demo-story-title"
            className="font-mono text-[0.75rem] font-semibold tracking-[0.16em] uppercase"
          >
            Why this works
          </h2>

          <div className="mt-6 grid gap-4 lg:grid-cols-12">
            {STORY.map((tile) => (
              <article
                key={tile.kicker}
                className={`rounded-feature p-8 sm:p-10 ${tile.fill} ${tile.span}`}
              >
                <p className="font-mono text-[0.7rem] font-semibold tracking-[0.16em] uppercase opacity-80">
                  {tile.kicker}
                </p>
                <h3 className={`mt-4 ${tile.scale}`}>{tile.title}</h3>
                <p className="mt-4 max-w-[52ch] text-sm leading-6 opacity-80">
                  {tile.body}
                </p>
              </article>
            ))}
          </div>
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
  variant?: "primary" | "danger" | "cta" | "quiet";
}) {
  const style = {
    primary: buttonStyles.outline,
    danger: buttonStyles.violet,
    cta: buttonStyles.mint,
    quiet: buttonStyles.quiet,
  }[variant];

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy !== null || disabled}
      className={style}
    >
      {busy === label ? "Working…" : label}
    </button>
  );
}
