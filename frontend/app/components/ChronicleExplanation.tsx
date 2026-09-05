"use client";

import { useState } from "react";

import {
  buttonStyles,
  Panel,
  PanelMessage,
  Spinner,
  Tag,
} from "@/app/components/vergeUi";
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

const sourceLabels: Record<ChronicleResult["mode"], string> = {
  fallback: "Scripted fallback narrative. No live model output was used.",
  live: "Live model explanation, validated against the selected events.",
  unknown: "Explanation source was not reported by the backend.",
};

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
    <Panel
      id="chronicle-title"
      title="Chronicle"
      busy={currentState?.status === "loading"}
      className="min-h-72 lg:col-span-7"
      badge={<Tag tone="quiet">Explains only</Tag>}
    >
      <div aria-live="polite" className="flex flex-1 flex-col pt-5">
        {!selectedIncident ? (
          <PanelMessage
            title="Select an incident to explain"
            body="Chronicle runs only after the recorded security decision, never before it."
          />
        ) : null}

        {selectedIncident && !currentState ? (
          <PanelMessage
            title="Incident selected"
            body={`${selectedIncident.event_ids.length} recorded events will be sent for a grounded, post-decision explanation.`}
            action={
              <button
                type="button"
                onClick={explainSelectedIncident}
                className={buttonStyles.mint}
              >
                Explain incident
              </button>
            }
          />
        ) : null}

        {currentState?.status === "loading" ? (
          <Spinner label="Building grounded explanation" />
        ) : null}

        {currentState?.status === "error" ? (
          <PanelMessage
            title="Explanation unavailable"
            body={currentState.message}
            action={
              <button
                type="button"
                onClick={explainSelectedIncident}
                className={buttonStyles.quiet}
              >
                Try again
              </button>
            }
          />
        ) : null}

        {currentState?.status === "complete" ? (
          <div>
            <p
              className={`rounded-tag border px-3 py-2 font-mono text-[0.65rem] leading-5 tracking-[0.06em] ${
                currentState.result.mode === "live"
                  ? "border-mint text-mint"
                  : "border-ultraviolet text-muted"
              }`}
            >
              {sourceLabels[currentState.result.mode]}
            </p>

            <p className="mt-5 text-[1.05rem] leading-6">
              {currentState.result.explanation.summary}
            </p>

            <dl className="text-meta mt-5 grid gap-x-8 gap-y-2 font-mono text-[0.7rem] sm:grid-cols-2">
              <div className="flex gap-2">
                <dt className="tracking-[0.14em] uppercase">User</dt>
                <dd className="text-muted break-words">
                  {currentState.result.explanation.affected_user ?? "Not stated"}
                </dd>
              </div>
              <div className="flex gap-2">
                <dt className="tracking-[0.14em] uppercase">App</dt>
                <dd className="text-muted break-words">
                  {currentState.result.explanation.affected_application ??
                    "Not stated"}
                </dd>
              </div>
            </dl>

            <div className="border-hazard/10 mt-5 border-t pt-4">
              <h3 className="font-mono text-[0.65rem] font-semibold tracking-[0.16em] uppercase">
                Suggested remediation
              </h3>
              {currentState.result.explanation.suggested_remediation.length ? (
                <ul className="mt-3 space-y-2">
                  {currentState.result.explanation.suggested_remediation.map(
                    (remediation) => (
                      <li
                        key={remediation}
                        className="text-muted flex gap-3 text-xs leading-5"
                      >
                        <span
                          aria-hidden="true"
                          className="bg-mint mt-2 size-1.5 shrink-0 rounded-full"
                        />
                        {remediation}
                      </li>
                    ),
                  )}
                </ul>
              ) : (
                <p className="text-meta mt-2 text-xs">
                  No remediation was stated in the referenced events.
                </p>
              )}
            </div>

            <p className="text-meta tnum mt-5 font-mono text-[0.62rem]">
              Generated{" "}
              {formatGeneratedAt(currentState.result.explanation.generated_at)}{" "}
              UTC
            </p>
          </div>
        ) : null}
      </div>
    </Panel>
  );
}
