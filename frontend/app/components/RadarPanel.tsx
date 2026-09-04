"use client";

import { useCallback, useEffect, useState } from "react";

import { RadarEstimateForm } from "@/app/components/RadarEstimateForm";
import type { RadarFinding, RadarReport } from "@/lib/contracts";

const MOCK_ORGANIZATION_ID = "mock-org-01";
// Set by the backend on any report scored from operator-supplied counts. The
// badge is derived from this rather than hardcoded, so it can never claim
// "simulated" while showing a real organisation's numbers, or vice versa.
const ESTIMATE_ORGANIZATION_ID = "operator-estimate";

const severityStyles: Record<RadarFinding["severity"], string> = {
  low: "border-sky-300/25 bg-sky-300/10 text-sky-200",
  medium: "border-amber-300/25 bg-amber-300/10 text-amber-200",
  high: "border-rose-300/25 bg-rose-300/10 text-rose-200",
};

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isRadarFinding(value: unknown): value is RadarFinding {
  if (!value || typeof value !== "object") return false;

  const finding = value as Record<string, unknown>;
  return (
    isString(finding.finding_id) &&
    isString(finding.check) &&
    ["low", "medium", "high"].includes(String(finding.severity)) &&
    typeof finding.affected_count === "number" &&
    Number.isInteger(finding.affected_count) &&
    finding.affected_count >= 0 &&
    isString(finding.description) &&
    isString(finding.remediation)
  );
}

function isRadarReport(value: unknown): value is RadarReport {
  if (!value || typeof value !== "object") return false;

  const report = value as Record<string, unknown>;
  return (
    isString(report.organization_id) &&
    typeof report.exposure_score === "number" &&
    report.exposure_score >= 0 &&
    report.exposure_score <= 100 &&
    ["Low", "Medium", "High"].includes(String(report.exposure_label)) &&
    isString(report.generated_at) &&
    !Number.isNaN(Date.parse(report.generated_at)) &&
    Array.isArray(report.findings) &&
    report.findings.every(isRadarFinding)
  );
}

function getReportUrl() {
  const backendOrigin = process.env.NEXT_PUBLIC_BACKEND_ORIGIN?.replace(
    /\/$/,
    "",
  );

  if (!backendOrigin) return "/fixtures/radar-report.json";

  return `${backendOrigin}/radar/report?org_id=${encodeURIComponent(MOCK_ORGANIZATION_ID)}`;
}

function formatGeneratedAt(value: string) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}

interface RadarPanelProps {
  initialReport?: unknown;
}

export function RadarPanel({ initialReport }: RadarPanelProps) {
  const [report, setReport] = useState<RadarReport | null>(() =>
    isRadarReport(initialReport) ? initialReport : null,
  );
  const [error, setError] = useState<string | null>(null);
  const [requestVersion, setRequestVersion] = useState(0);
  const [showEstimateForm, setShowEstimateForm] = useState(false);

  // Derived from the report itself, never from which button was pressed, so
  // the badge cannot drift out of step with the data actually on screen.
  const isEstimate = report?.organization_id === ESTIMATE_ORGANIZATION_ID;

  const retry = useCallback(() => {
    // Also the way back from an estimate: re-fetching restores the simulated
    // organisation report.
    setShowEstimateForm(false);
    setRequestVersion((version) => version + 1);
  }, []);

  useEffect(() => {
    const controller = new AbortController();

    async function loadReport() {
      setError(null);

      try {
        const response = await fetch(getReportUrl(), {
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Radar returned HTTP ${response.status}.`);
        }

        const payload: unknown = await response.json();
        if (!isRadarReport(payload)) {
          throw new Error("Radar returned a report with an invalid shape.");
        }

        setReport(payload);
      } catch (loadError) {
        if (controller.signal.aborted) return;
        setError(
          loadError instanceof Error
            ? loadError.message
            : "The Radar report could not be loaded.",
        );
      }
    }

    void loadReport();
    return () => controller.abort();
  }, [requestVersion]);

  return (
    <section
      aria-labelledby="radar-title"
      aria-busy={!report && !error}
      className="flex min-h-72 flex-col rounded-2xl border border-white/10 bg-slate-900/70 p-5 shadow-2xl shadow-black/10 sm:p-6 lg:col-span-4"
    >
      <div className="flex items-start justify-between gap-4 border-b border-white/10 pb-4">
        <div>
          <p className="text-[0.68rem] font-semibold tracking-[0.2em] text-emerald-300 uppercase">
            Exposure posture
          </p>
          <h2
            id="radar-title"
            className="mt-2 text-xl font-semibold tracking-tight text-white"
          >
            Radar
          </h2>
        </div>
        {isEstimate ? (
          <span className="rounded-full border border-emerald-300/25 bg-emerald-300/10 px-2.5 py-1 text-[0.65rem] font-semibold tracking-wide text-emerald-200 uppercase">
            Your numbers · estimate
          </span>
        ) : (
          <span className="rounded-full border border-violet-300/20 bg-violet-300/10 px-2.5 py-1 text-[0.65rem] font-semibold tracking-wide text-violet-200 uppercase">
            Simulated organization
          </span>
        )}
      </div>

      {showEstimateForm ? (
        <RadarEstimateForm
          onReport={(estimate) => {
            setReport(estimate);
            setError(null);
            setShowEstimateForm(false);
          }}
          onCancel={() => setShowEstimateForm(false)}
        />
      ) : (
        <button
          type="button"
          onClick={() => (isEstimate ? retry() : setShowEstimateForm(true))}
          className="mt-4 self-start rounded-lg border border-white/15 bg-white/5 px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:bg-white/10 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
        >
          {isEstimate ? "Back to simulated organization" : "Score your own organization"}
        </button>
      )}

      {!report && !error ? (
        <div className="grid flex-1 place-items-center py-12 text-center">
          <div role="status" className="text-sm text-slate-400">
            <span
              aria-hidden="true"
              className="mx-auto mb-4 block size-7 animate-spin rounded-full border-2 border-slate-700 border-t-emerald-300"
            />
            Loading exposure report…
          </div>
        </div>
      ) : null}

      {error ? (
        <div className="grid flex-1 place-items-center py-10 text-center">
          <div className="max-w-sm">
            <p className="text-sm font-medium text-rose-200">
              Exposure report unavailable
            </p>
            <p className="mt-2 text-xs leading-5 text-slate-400">{error}</p>
            <button
              type="button"
              onClick={retry}
              className="mt-4 rounded-lg border border-white/15 bg-white/5 px-3 py-2 text-xs font-semibold text-white transition hover:bg-white/10 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
            >
              Try again
            </button>
          </div>
        </div>
      ) : null}

      {report ? (
        <div className="pt-5">
          <div className="flex items-end justify-between gap-5 rounded-xl border border-white/10 bg-slate-950/55 p-4">
            <div>
              <p className="text-xs text-slate-500">Exposure score</p>
              <p className="mt-1 text-4xl font-semibold tracking-tight text-white">
                {report.exposure_score}
                <span className="ml-1 text-base font-normal text-slate-500">
                  /100
                </span>
              </p>
            </div>
            <div className="text-right">
              <p className="text-sm font-semibold text-rose-200">
                {report.exposure_label}
              </p>
              <p className="mt-1 font-mono text-[0.65rem] text-slate-500">
                {report.organization_id}
              </p>
            </div>
          </div>

          <div className="mt-5 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">
              Findings ({report.findings.length})
            </h3>
            <time
              dateTime={report.generated_at}
              className="text-[0.65rem] text-slate-500"
            >
              {formatGeneratedAt(report.generated_at)} UTC
            </time>
          </div>

          <ul className="mt-3 space-y-3">
            {report.findings.map((finding) => (
              <li
                key={finding.finding_id}
                className="rounded-xl border border-white/10 bg-white/[0.025] p-4"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`rounded-full border px-2 py-0.5 text-[0.65rem] font-semibold uppercase ${severityStyles[finding.severity]}`}
                  >
                    {finding.severity}
                  </span>
                  <span className="text-xs text-slate-400">
                    {finding.affected_count} affected
                  </span>
                </div>
                <p className="mt-3 break-words font-mono text-xs text-emerald-200">
                  {finding.check}
                </p>
                <p className="mt-2 text-xs leading-5 text-slate-300">
                  {finding.description}
                </p>
                <div className="mt-3 border-t border-white/10 pt-3">
                  <p className="text-[0.65rem] font-semibold tracking-wide text-slate-500 uppercase">
                    Remediation
                  </p>
                  <p className="mt-1 text-xs leading-5 text-slate-300">
                    {finding.remediation}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
