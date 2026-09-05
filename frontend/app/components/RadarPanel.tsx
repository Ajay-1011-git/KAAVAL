"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { RadarEstimateForm } from "@/app/components/RadarEstimateForm";
import {
  buttonStyles,
  Panel,
  PanelMessage,
  Spinner,
  Tag,
} from "@/app/components/vergeUi";
import type { RadarFinding, RadarReport } from "@/lib/contracts";

const MOCK_ORGANIZATION_ID = "mock-org-01";
// Set by the backend on any report scored from operator-supplied counts. The
// badge is derived from this rather than hardcoded, so it can never claim
// "simulated" while showing a real organisation's numbers, or vice versa.
const ESTIMATE_ORGANIZATION_ID = "operator-estimate";

// The panel used to render every finding with its full remediation text
// expanded, which made it the tallest thing on the page. The most severe few
// are shown, remediation is one disclosure away, and the count below the list
// says how many findings are not on screen.
const MAX_VISIBLE_FINDINGS = 3;

const severityRank: Record<RadarFinding["severity"], number> = {
  high: 0,
  medium: 1,
  low: 2,
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

  // Most severe first, so the three that get shown are the three that matter.
  const rankedFindings = useMemo(() => {
    if (!report) return [];
    return [...report.findings].sort(
      (left, right) => severityRank[left.severity] - severityRank[right.severity],
    );
  }, [report]);

  const visibleFindings = rankedFindings.slice(0, MAX_VISIBLE_FINDINGS);

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
    <Panel
      id="radar-title"
      title="Radar / exposure"
      busy={!report && !error}
      className="min-h-72 lg:col-span-4"
      badge={
        <Tag tone={isEstimate ? "quiet" : "violet"}>
          {isEstimate ? "Your numbers" : "Simulated org"}
        </Tag>
      }
    >
      {!report && !error ? <Spinner label="Loading exposure report" /> : null}

      {error ? (
        <PanelMessage
          title="Exposure report unavailable"
          body={error}
          action={
            <button type="button" onClick={retry} className={buttonStyles.quiet}>
              Try again
            </button>
          }
        />
      ) : null}

      {report ? (
        <div className="pt-5">
          {/* The one saturated colour block on the page. Depth here comes from
              fill, not from a shadow, per the design spec. */}
          <div className="bg-mint text-inverted rounded-feature flex items-end justify-between gap-4 p-6">
            <p className="font-display tnum text-[4.5rem] leading-[0.85]">
              {report.exposure_score}
              <span className="ml-1 font-mono text-[0.9rem] tracking-[0.1em] opacity-60">
                /100
              </span>
            </p>
            <p className="font-mono text-[0.75rem] font-semibold tracking-[0.16em] uppercase">
              {report.exposure_label} exposure
            </p>
          </div>

          <div className="mt-6 flex items-baseline justify-between gap-3">
            <h3 className="font-mono text-[0.7rem] font-semibold tracking-[0.16em] uppercase">
              Top findings
            </h3>
            <time
              dateTime={report.generated_at}
              className="text-meta tnum font-mono text-[0.62rem]"
            >
              {formatGeneratedAt(report.generated_at)} UTC
            </time>
          </div>

          <ul className="mt-3 space-y-3">
            {visibleFindings.map((finding) => (
              <li
                key={finding.finding_id}
                className="border-hazard/15 rounded-tile border p-4"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <Tag tone={finding.severity === "high" ? "white" : "quiet"}>
                    {finding.severity}
                  </Tag>
                  <span className="text-meta tnum font-mono text-[0.65rem]">
                    {finding.affected_count} affected
                  </span>
                </div>
                {/* The check id is a machine identifier, so it is set in mono
                    rather than dressed up as prose. */}
                <p className="mt-3 font-mono text-[0.8rem] leading-5 font-bold break-words">
                  {finding.check}
                </p>
                <p className="text-meta mt-2 text-xs leading-5">
                  {finding.description}
                </p>
                <details className="group border-hazard/10 mt-3 border-t pt-3">
                  <summary className="text-mint hover:text-linkhover cursor-pointer font-mono text-[0.62rem] font-semibold tracking-[0.16em] uppercase transition-colors duration-150">
                    Remediation
                  </summary>
                  <p className="text-muted mt-2 text-xs leading-5">
                    {finding.remediation}
                  </p>
                </details>
              </li>
            ))}
          </ul>

          <p className="text-meta mt-4 font-mono text-[0.65rem] tracking-[0.14em] uppercase">
            Showing {visibleFindings.length} of {report.findings.length} checks
          </p>

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
              className={`${buttonStyles.outline} mt-5 w-full`}
            >
              {isEstimate ? "Back to simulated" : "Score your org"}
            </button>
          )}
        </div>
      ) : null}
    </Panel>
  );
}
