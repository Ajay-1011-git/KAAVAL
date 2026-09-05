import { AttackAlertBanner } from "@/app/components/AttackAlertBanner";
import { ChronicleExplanation } from "@/app/components/ChronicleExplanation";
import { DecisionStats } from "@/app/components/DecisionStats";
import { GuardianTrigger } from "@/app/components/GuardianTrigger";
import { IncidentTimeline } from "@/app/components/IncidentTimeline";
import { LiveEventFeed } from "@/app/components/LiveEventFeed";
import { RadarPanel } from "@/app/components/RadarPanel";
import { SystemStory } from "@/app/components/SystemStory";
import { SecurityEventsProvider } from "@/lib/eventsClient";
import { IncidentSelectionProvider } from "@/lib/incidentSelection";
import radarFixture from "@/public/fixtures/radar-report.json";

// Every panel falls back to bundled fixtures when NEXT_PUBLIC_BACKEND_ORIGIN
// is unset (see README). That fallback used to be invisible: the dashboard
// rendered fabricated events and a fixture Radar score of 74 while the real
// engine computes something else entirely, and nothing on screen said so. A
// viewer — or a judge — had no way to tell a live blocked attack from a
// hardcoded one, which is exactly the kind of unearned trust this project
// exists to argue against. So the connection state is now stated plainly.
const IS_LIVE = Boolean(process.env.NEXT_PUBLIC_BACKEND_ORIGIN);

export default function Home() {
  return (
    <main className="bg-canvas text-hazard min-h-[100dvh]">
      <div className="mx-auto flex min-h-[100dvh] w-full max-w-[1300px] flex-col px-6 py-10 lg:px-12">
        <header className="border-hazard/15 grid gap-8 border-b pb-10 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
          <div>
            <p className="text-mint font-mono text-[0.8rem] font-semibold tracking-[0.18em] uppercase">
              Security command center
            </p>
            <h1 className="font-display mt-4 text-[clamp(3.25rem,11vw,6.7rem)] leading-[0.95] tracking-[0.01em] uppercase">
              Kaaval
            </h1>
            <p className="text-muted mt-5 max-w-lg text-[1.25rem] leading-[1.2] font-light tracking-[0.08em]">
              Deterministic security decisions, in one operational view.
            </p>
          </div>

          {/* Reflects the actual data source. Previously this read "Awaiting
              live data" unconditionally, which stayed on screen even when the
              dashboard was connected — a status indicator that never checked
              its own status. */}
          <div className="border-hazard/25 rounded-cta flex w-fit items-center gap-3 border px-5 py-3 font-mono text-[0.7rem] font-semibold tracking-[0.14em] uppercase">
            <span
              aria-hidden="true"
              className={`size-2 rounded-full ${
                IS_LIVE ? "bg-mint animate-pulse" : "bg-ultraviolet"
              }`}
            />
            {IS_LIVE ? "Live backend" : "Sample data"}
          </div>
        </header>

        {!IS_LIVE && (
          <div
            role="status"
            className="border-ultraviolet rounded-tile mt-8 border p-5"
          >
            <p className="font-mono text-[0.72rem] font-semibold tracking-[0.16em] uppercase">
              Not connected to a live backend
            </p>
            <p className="text-meta mt-2 max-w-2xl text-xs leading-5">
              Every panel below is rendering bundled fixtures, not real security
              decisions. Set{" "}
              <code className="text-mint font-mono">
                NEXT_PUBLIC_BACKEND_ORIGIN
              </code>{" "}
              in{" "}
              <code className="text-mint font-mono">frontend/.env.local</code>{" "}
              and restart to show live data.
            </p>
          </div>
        )}

        <SecurityEventsProvider>
          {/* Two-laptop demo callout — surfaces attacker-driven blocks from the
              same stream the panels use. See AttackAlertBanner (flagged for Sai). */}
          <AttackAlertBanner />
          <DecisionStats />
          {/* The grid deliberately does not take flex-1: letting it absorb
              the leftover column height stretched every panel to fill a tall
              viewport, so a sparsely-populated dashboard rendered as a wall of
              empty boxes. With items-start each panel is as tall as it has
              content for, so a quiet stream reads as a short panel rather than
              a large empty one; the footer takes the slack. */}
          <section
            aria-label="KAAVAL dashboard regions"
            className="grid grid-cols-1 gap-4 py-8 lg:grid-cols-12 lg:items-start"
          >
            <IncidentSelectionProvider>
              <RadarPanel
                initialReport={
                  process.env.NEXT_PUBLIC_BACKEND_ORIGIN ? null : radarFixture
                }
              />
              <LiveEventFeed />
              <IncidentTimeline />
              <ChronicleExplanation />
              <GuardianTrigger />
            </IncidentSelectionProvider>
          </section>
        </SecurityEventsProvider>

        <SystemStory />

        <footer className="border-hazard/15 text-meta mt-auto flex flex-col gap-2 border-t pt-6 font-mono text-[0.65rem] tracking-[0.16em] uppercase sm:flex-row sm:items-center sm:justify-between">
          <p>PulseLock / Radar / Guardian / Chronicle</p>
          <p>Security decisions remain deterministic</p>
        </footer>
      </div>
    </main>
  );
}
