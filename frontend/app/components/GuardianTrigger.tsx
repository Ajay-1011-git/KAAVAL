"use client";

// frontend/app/components/GuardianTrigger.tsx — amendment FIX-5.
//
// Guardian's policy and endpoints were real and unit-tested, but nothing in
// the UI ever fired one, so PRD acceptance criterion 6 ("malicious OAuth
// consent request blocked with a stated policy reason") could only be shown
// from a test file.
//
// Two buttons, both hitting the real /guardian/oauth/evaluate endpoint: one
// with a consent-phishing shaped request, one with a clean request. Both
// paths are shown deliberately — a policy that blocks everything demonstrates
// nothing. Each decision writes a SecurityEvent, so the result also appears
// on the live feed and timeline beside this panel.
//
// The applications below are fabricated demo inputs, labelled as such in the
// UI; there is no real publisher registry behind them.

import { useState } from "react";

const BACKEND_ORIGIN = process.env.NEXT_PUBLIC_BACKEND_ORIGIN?.replace(/\/$/, "");

const MALICIOUS_GRANT = {
  application_id: "app-consent-phish-01",
  application_name: "Docs Sync Helper",
  publisher_verified: false,
  requested_scopes: ["Mail.ReadWrite", "Files.ReadWrite.All", "offline_access"],
  redirect_uri: "https://docs-sync-helper.example/callback",
  offline_access_requested: true,
  is_org_allowlisted: false,
};

const CLEAN_GRANT = {
  application_id: "app-approved-crm-01",
  application_name: "Approved CRM",
  publisher_verified: true,
  requested_scopes: ["User.Read"],
  redirect_uri: "https://crm.corp.example/callback",
  offline_access_requested: false,
  is_org_allowlisted: true,
};

interface Decision {
  decision: "allow" | "block";
  reason: string;
  application: string;
}

export function GuardianTrigger() {
  const [pending, setPending] = useState<string | null>(null);
  const [result, setResult] = useState<Decision | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function evaluate(label: string, grant: typeof MALICIOUS_GRANT) {
    if (!BACKEND_ORIGIN) {
      setError(
        "Set NEXT_PUBLIC_BACKEND_ORIGIN to evaluate against the live Guardian.",
      );
      return;
    }
    setPending(label);
    setError(null);
    try {
      const response = await fetch(`${BACKEND_ORIGIN}/guardian/oauth/evaluate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(grant),
      });
      if (!response.ok) {
        throw new Error(`Guardian returned HTTP ${response.status}`);
      }
      const payload = await response.json();
      setResult({
        decision: payload.decision,
        reason: payload.reason,
        application: grant.application_name,
      });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setResult(null);
    } finally {
      setPending(null);
    }
  }

  return (
    <section
      aria-label="Guardian consent evaluation"
      className="lg:col-span-12 rounded-2xl border border-white/10 bg-white/5 p-5"
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold tracking-wide text-slate-200 uppercase">
            Guardian · consent policy
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            Deterministic if/else policy. Simulated applications — no real
            publisher registry.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => evaluate("malicious", MALICIOUS_GRANT)}
            disabled={pending !== null}
            className="rounded-lg border border-amber-300/30 bg-amber-300/10 px-3 py-2 text-sm font-medium text-amber-200 transition hover:bg-amber-300/20 disabled:opacity-40"
          >
            {pending === "malicious" ? "Evaluating…" : "Request malicious consent"}
          </button>
          <button
            type="button"
            onClick={() => evaluate("clean", CLEAN_GRANT)}
            disabled={pending !== null}
            className="rounded-lg border border-emerald-300/30 bg-emerald-300/10 px-3 py-2 text-sm font-medium text-emerald-200 transition hover:bg-emerald-300/20 disabled:opacity-40"
          >
            {pending === "clean" ? "Evaluating…" : "Request clean consent"}
          </button>
        </div>
      </div>

      {error ? (
        <p className="mt-4 rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </p>
      ) : null}

      {result ? (
        <div
          className={`mt-4 rounded-xl border px-4 py-3 text-sm ${
            result.decision === "block"
              ? "border-amber-400/30 bg-amber-400/10 text-amber-200"
              : "border-emerald-400/30 bg-emerald-400/10 text-emerald-200"
          }`}
        >
          <p className="font-medium">
            {result.application} · {result.decision === "block" ? "BLOCKED" : "ALLOWED"}
          </p>
          <p className="mt-1 font-mono text-xs break-all opacity-80">
            {result.reason}
          </p>
          <p className="mt-2 text-xs opacity-70">
            Recorded as a SecurityEvent — it appears on the live feed above.
          </p>
        </div>
      ) : null}
    </section>
  );
}
