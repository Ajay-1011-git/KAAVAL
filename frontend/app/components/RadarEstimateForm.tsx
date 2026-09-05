"use client";

import { useState } from "react";

import { buttonStyles } from "@/app/components/vergeUi";
import type { RadarReport } from "@/lib/contracts";

// Radar's checks consume only (affected_count, population) — none of them
// inspect which account is affected — so these counts reproduce exactly the
// score a full directory integration would produce. That is what makes this
// worth offering: it is not a downgraded preview of the real thing, it is the
// real scoring engine with the numbers entered by hand.
//
// The numbers must come from the operator. Nothing here invents a value or
// fills a plausible default, because a score built from guessed inputs would
// be indistinguishable from a measured one on screen — the exact kind of
// unearned trust this project exists to argue against.

interface Field {
  name: string;
  label: string;
  hint?: string;
}

const ACCOUNT_FIELDS: Field[] = [
  { name: "total_accounts", label: "Total accounts", hint: "required" },
  { name: "phishable_mfa_accounts", label: "On phishable MFA (SMS/voice)" },
  { name: "passkey_enrolled_not_enforced", label: "Passkey enrolled, not enforced" },
  { name: "weak_fallback_accounts", label: "Weak fallback enabled" },
  { name: "device_code_enabled_accounts", label: "Device-code unrestricted" },
  { name: "admin_accounts", label: "Admin accounts" },
  { name: "unmonitored_admin_accounts", label: "…of those, unmonitored" },
  { name: "conditional_access_excluded_accounts", label: "Conditional Access exclusions" },
  { name: "long_lived_session_accounts", label: "Sessions longer than 7 days" },
];

const APP_FIELDS: Field[] = [
  { name: "total_oauth_apps", label: "Total OAuth apps" },
  { name: "unverified_unallowlisted_apps", label: "Unverified & not allowlisted" },
  { name: "excessive_permission_apps", label: "Over-permissioned" },
];

const ALL_FIELDS = [...ACCOUNT_FIELDS, ...APP_FIELDS];

function backendOrigin() {
  return process.env.NEXT_PUBLIC_BACKEND_ORIGIN?.replace(/\/$/, "");
}

interface RadarEstimateFormProps {
  onReport: (report: RadarReport) => void;
  onCancel: () => void;
}

export function RadarEstimateForm({ onReport, onCancel }: RadarEstimateFormProps) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const origin = backendOrigin();

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    if (!origin) {
      setError("Set NEXT_PUBLIC_BACKEND_ORIGIN to score against the live engine.");
      return;
    }

    // Blank means zero, but total_accounts has no sensible default — an
    // organisation of unknown size cannot be scored.
    const payload: Record<string, number> = {};
    for (const field of ALL_FIELDS) {
      const raw = (values[field.name] ?? "").trim();
      if (raw === "") continue;
      const parsed = Number(raw);
      if (!Number.isInteger(parsed) || parsed < 0) {
        setError(`${field.label} must be a whole number of zero or more.`);
        return;
      }
      payload[field.name] = parsed;
    }
    if (payload.total_accounts === undefined) {
      setError("Total accounts is required.");
      return;
    }

    setSubmitting(true);
    try {
      const response = await fetch(`${origin}/radar/estimate`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(payload),
      });

      if (response.status === 422) {
        // The server rejects impossible counts (a subset larger than its
        // population) rather than scoring them. Surface its reason verbatim
        // instead of a generic failure.
        const detail: unknown = await response.json();
        const message =
          Array.isArray((detail as { detail?: unknown })?.detail) &&
          typeof ((detail as { detail: Array<{ msg?: unknown }> }).detail[0]?.msg) === "string"
            ? String((detail as { detail: Array<{ msg?: unknown }> }).detail[0].msg)
            : "Those counts are not internally consistent.";
        setError(message.replace(/^Value error,\s*/, ""));
        return;
      }
      if (!response.ok) {
        setError(`Radar returned HTTP ${response.status}.`);
        return;
      }

      onReport((await response.json()) as RadarReport);
    } catch {
      setError("Could not reach the Radar service.");
    } finally {
      setSubmitting(false);
    }
  }

  function renderField(field: Field) {
    return (
      <label
        key={field.name}
        className="flex items-center justify-between gap-3 text-xs"
      >
        <span className="text-muted">
          {field.label}
          {field.hint ? (
            <span className="text-meta ml-1">({field.hint})</span>
          ) : null}
        </span>
        <input
          type="number"
          min={0}
          step={1}
          inputMode="numeric"
          value={values[field.name] ?? ""}
          onChange={(event) =>
            setValues((current) => ({ ...current, [field.name]: event.target.value }))
          }
          className="border-hazard/35 rounded-tag text-hazard tnum focus:border-mint w-20 border bg-transparent px-2 py-1.5 text-right font-mono text-xs transition-colors duration-150"
        />
      </label>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="mt-5 flex flex-col gap-5">
      <p className="text-meta text-xs leading-5">
        Enter your organisation&apos;s own numbers. Radar scores them with the
        same nine checks it uses everywhere else, so counts alone produce the
        identical result to a full directory integration. Blank counts as zero.
      </p>

      <fieldset className="flex flex-col gap-2">
        <legend className="mb-2 font-mono text-[0.65rem] font-semibold tracking-[0.16em] uppercase">
          Accounts
        </legend>
        {ACCOUNT_FIELDS.map(renderField)}
      </fieldset>

      <fieldset className="flex flex-col gap-2">
        <legend className="mb-2 font-mono text-[0.65rem] font-semibold tracking-[0.16em] uppercase">
          OAuth applications
        </legend>
        {APP_FIELDS.map(renderField)}
      </fieldset>

      {error ? (
        <p
          role="alert"
          className="border-ultraviolet rounded-tag text-muted border px-3 py-2 text-xs leading-5"
        >
          {error}
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="submit"
          disabled={submitting}
          className={buttonStyles.mint}
        >
          {submitting ? "Scoring" : "Score my org"}
        </button>
        <button type="button" onClick={onCancel} className={buttonStyles.quiet}>
          Cancel
        </button>
      </div>
    </form>
  );
}
