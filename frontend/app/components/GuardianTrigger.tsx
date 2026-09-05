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

import { buttonStyles, Panel, Tag } from "@/app/components/vergeUi";

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
    <Panel
      id="guardian-title"
      title="Guardian / consent policy"
      className="lg:col-span-12"
      badge={<Tag tone="quiet">Simulated apps</Tag>}
    >
      <div className="flex flex-wrap items-center justify-between gap-5 pt-5">
        <p className="text-meta max-w-md text-xs leading-5">
          Deterministic if/else policy. The applications below are fabricated
          demo inputs, not a real publisher registry.
        </p>
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={() => evaluate("malicious", MALICIOUS_GRANT)}
            disabled={pending !== null}
            className={buttonStyles.violet}
          >
            {pending === "malicious" ? "Evaluating" : "Malicious consent"}
          </button>
          <button
            type="button"
            onClick={() => evaluate("clean", CLEAN_GRANT)}
            disabled={pending !== null}
            className={buttonStyles.outline}
          >
            {pending === "clean" ? "Evaluating" : "Clean consent"}
          </button>
        </div>
      </div>

      {error ? (
        <p
          role="alert"
          className="border-ultraviolet rounded-tile text-muted mt-5 border px-4 py-3 font-mono text-xs leading-5"
        >
          {error}
        </p>
      ) : null}

      {result ? (
        <div
          className={`rounded-tile mt-5 p-5 ${
            result.decision === "block"
              ? "bg-ultraviolet text-hazard"
              : "bg-mint text-inverted"
          }`}
        >
          <p className="font-mono text-[0.75rem] font-semibold tracking-[0.16em] uppercase">
            {result.application} / {result.decision === "block" ? "Blocked" : "Allowed"}
          </p>
          <p className="mt-2 font-mono text-xs leading-5 break-all opacity-90">
            {result.reason}
          </p>
          <p className="mt-3 font-mono text-[0.62rem] tracking-[0.12em] uppercase opacity-70">
            Recorded as a SecurityEvent. It appears on the decision stream above.
          </p>
        </div>
      ) : null}
    </Panel>
  );
}
