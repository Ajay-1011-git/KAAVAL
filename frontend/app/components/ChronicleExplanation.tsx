"use client";

import { useState } from "react";

import {
  type ChronicleResult,
  requestIncidentExplanation,
} from "@/lib/chronicleClient";
import { useIncidentSelection } from "@/lib/incidentSelection";

type RequestState =
  | { selectionKey: string; status: "loading" }
  | { selectionKey: string; status: "error"; message: string }
  | { selectionKey: string; status: "complete"; result: ChronicleResult };

function formatGeneratedAt(value: string) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}

export function ChronicleExplanation() {
  const { selectedIncident } = useIncidentSelection();
  const [requestState, setRequestState] = useState<RequestState | null>(null);
  const selectionKey = selectedIncident?.event_ids.join("|") ?? "";
  const currentState =
    requestState?.selectionKey === selectionKey ? requestState : null;

  async function explainSelectedIncident() {
    if (!selectedIncident) return;

    const requestedSelectionKey = selectedIncident.event_ids.join("|");
    setRequestState({
      selectionKey: requestedSelectionKey,
      status: "loading",
    });

    try {
      const result = await requestIncidentExplanation(
        selectedIncident.event_ids,
      );
      setRequestState({
        selectionKey: requestedSelectionKey,
        status: "complete",
        result,
      });
    } catch (error) {
      setRequestState({
        selectionKey: requestedSelectionKey,
        status: "error",
        message:
          error instanceof Error
            ? error.message
            : "Chronicle could not explain this incident.",
      });
    }
  }

  return (
    <section
      aria-labelledby="chronicle-title"
      aria-busy={currentState?.status === "loading"}
      className="flex min-h-72 flex-col rounded-2xl border border-white/10 bg-slate-900/70 p-5 shadow-2xl shadow-black/10 sm:p-6 lg:col-span-5"
    >
      <div className="flex items-start justify-between gap-4 border-b border-white/10 pb-4">
        <div>
          <p className="text-[0.68rem] font-semibold tracking-[0.2em] text-emerald-300 uppercase">
            Post-decision explanation
          </p>
          <h2
            id="chronicle-title"
            className="mt-2 text-xl font-semibold tracking-tight text-white"
          >
            Chronicle
          </h2>
        </div>
        <span className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-[0.65rem] font-semibold text-slate-400">
          Explains only
        </span>
      </div>

      <div aria-live="polite" className="flex flex-1 flex-col pt-5">
        {!selectedIncident ? (
          <div className="grid flex-1 place-items-center py-8 text-center">
            <div className="max-w-xs">
              <span
                aria-hidden="true"
                className="mx-auto mb-4 block size-10 rounded-full border border-dashed border-slate-600 bg-slate-950/50"
              />
              <p className="text-sm font-medium text-slate-300">
                Select an incident to explain
              </p>
              <p className="mt-2 text-xs leading-5 text-slate-500">
                Chronicle runs only after the recorded security decision.
              </p>
            </div>
          </div>
        ) : null}

        {selectedIncident && !currentState ? (
          <div className="grid flex-1 place-items-center py-8 text-center">
            <div className="max-w-sm">
              <p className="text-sm font-medium text-white">
                Incident selected
              </p>
              <p className="mt-2 text-xs leading-5 text-slate-400">
                {selectedIncident.event_ids.length} recorded events will be sent
                for a grounded, post-decision explanation.
              </p>
              <button
                type="button"
                onClick={explainSelectedIncident}
                className="mt-5 rounded-lg bg-emerald-300 px-4 py-2.5 text-xs font-bold text-slate-950 transition hover:bg-emerald-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
              >
                Explain incident
              </button>
            </div>
          </div>
        ) : null}

        {currentState?.status === "loading" ? (
          <div role="status" className="grid flex-1 place-items-center py-8">
            <div className="text-center text-sm text-slate-300">
              <span
                aria-hidden="true"
                className="mx-auto mb-4 block size-8 animate-spin rounded-full border-2 border-slate-700 border-t-emerald-300"
              />
              Building grounded explanation…
            </div>
          </div>
        ) : null}

        {currentState?.status === "error" ? (
          <div className="grid flex-1 place-items-center py-8 text-center">
            <div className="max-w-sm">
              <p className="text-sm font-medium text-rose-200">
                Explanation unavailable
              </p>
              <p className="mt-2 text-xs leading-5 text-slate-400">
                {currentState.message}
              </p>
              <button
                type="button"
                onClick={explainSelectedIncident}
                className="mt-4 rounded-lg border border-white/15 bg-white/5 px-3 py-2 text-xs font-semibold text-white transition hover:bg-white/10 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300"
              >
                Try again
              </button>
            </div>
          </div>
        ) : null}

        {currentState?.status === "complete" ? (
          <div>
            <div
              className={`rounded-lg border px-3 py-2 text-xs ${
                currentState.result.mode === "fallback"
                  ? "border-amber-300/20 bg-amber-300/10 text-amber-100"
                  : currentState.result.mode === "live"
                    ? "border-emerald-300/20 bg-emerald-300/10 text-emerald-100"
                    : "border-slate-500/30 bg-slate-500/10 text-slate-300"
              }`}
            >
              {currentState.result.mode === "fallback"
                ? "Scripted fallback narrative — no live model output was used."
                : currentState.result.mode === "live"
                  ? "Live model explanation, validated against the selected events."
                  : "Explanation source was not reported by the backend."}
            </div>

            <p className="mt-5 text-sm leading-6 text-slate-200">
              {currentState.result.explanation.summary}
            </p>

            <dl className="mt-5 grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-white/10 bg-white/[0.025] p-3">
                <dt className="text-[0.65rem] font-semibold tracking-wide text-slate-500 uppercase">
                  Affected user
                </dt>
                <dd className="mt-1 break-words font-mono text-xs text-slate-300">
                  {currentState.result.explanation.affected_user ?? "Not stated"}
                </dd>
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.025] p-3">
                <dt className="text-[0.65rem] font-semibold tracking-wide text-slate-500 uppercase">
                  Application
                </dt>
                <dd className="mt-1 break-words font-mono text-xs text-slate-300">
                  {currentState.result.explanation.affected_application ??
                    "Not stated"}
                </dd>
              </div>
            </dl>

            <div className="mt-5">
              <h3 className="text-xs font-semibold tracking-wide text-slate-400 uppercase">
                Suggested remediation
              </h3>
              {currentState.result.explanation.suggested_remediation.length ? (
                <ul className="mt-2 space-y-2">
                  {currentState.result.explanation.suggested_remediation.map(
                    (remediation) => (
                      <li
                        key={remediation}
                        className="flex gap-2 text-xs leading-5 text-slate-300"
                      >
                        <span aria-hidden="true" className="text-emerald-300">
                          →
                        </span>
                        {remediation}
                      </li>
                    ),
                  )}
                </ul>
              ) : (
                <p className="mt-2 text-xs text-slate-500">
                  No remediation was stated in the referenced events.
                </p>
              )}
            </div>

            <p className="mt-5 border-t border-white/10 pt-3 text-[0.65rem] text-slate-500">
              Generated {formatGeneratedAt(currentState.result.explanation.generated_at)} UTC
            </p>
          </div>
        ) : null}
      </div>
    </section>
  );
}
