import { AttackAlertBanner } from "@/app/components/AttackAlertBanner";
import { ChronicleExplanation } from "@/app/components/ChronicleExplanation";
import { GuardianTrigger } from "@/app/components/GuardianTrigger";
import { IncidentTimeline } from "@/app/components/IncidentTimeline";
import { LiveEventFeed } from "@/app/components/LiveEventFeed";
import { RadarPanel } from "@/app/components/RadarPanel";
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
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex min-h-screen w-full max-w-[1600px] flex-col px-5 py-6 sm:px-8 lg:px-10">
        {!IS_LIVE && (
          <div
            role="status"
            className="mb-5 flex flex-col gap-1 rounded-xl border border-amber-300/40 bg-amber-300/10 px-4 py-3 text-amber-100"
          >
            <p className="text-sm font-semibold">
              Sample data — not connected to a live backend
            </p>
            <p className="text-xs leading-5 text-amber-200/80">
              Every panel below is rendering bundled fixtures, not real security
              decisions. Set{" "}
              <code className="rounded bg-black/30 px-1 py-0.5 font-mono">
                NEXT_PUBLIC_BACKEND_ORIGIN
              </code>{" "}
              in{" "}
              <code className="rounded bg-black/30 px-1 py-0.5 font-mono">
                frontend/.env.local
              </code>{" "}
              and restart to show live data.
            </p>
          </div>
        )}

        <header className="flex flex-col gap-6 border-b border-white/10 pb-7 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="mb-4 flex items-center gap-3">
              <span
                aria-hidden="true"
                className="grid size-9 place-items-center rounded-xl border border-emerald-300/30 bg-emerald-300/10 text-sm font-black text-emerald-300"
              >
                K
              </span>
              <span className="text-xs font-semibold tracking-[0.28em] text-slate-400 uppercase">
                Security command center
              </span>
            </div>
            <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">
              KAAVAL overview
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
              Deterministic security decisions, visible in one calm operational
              view.
            </p>
          </div>

          {/* Reflects the actual data source. Previously this read "Awaiting
              live data" unconditionally, which stayed on screen even when the
              dashboard was connected — a status indicator that never checked
              its own status. */}
          <div className="flex items-center gap-3 self-start rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs text-slate-300 sm:self-auto">
            <span
              aria-hidden="true"
              className={
                IS_LIVE
                  ? "size-2 rounded-full bg-emerald-300 shadow-[0_0_12px_rgba(110,231,183,0.7)]"
                  : "size-2 rounded-full bg-amber-300 shadow-[0_0_12px_rgba(252,211,77,0.7)]"
              }
            />
            {IS_LIVE ? "Live backend" : "Sample data"}
          </div>
        </header>

        <SecurityEventsProvider>
          {/* Two-laptop demo callout — surfaces attacker-driven blocks from the
              same stream the panels use. See AttackAlertBanner (flagged for Sai). */}
          <AttackAlertBanner />
          <section
            aria-label="KAAVAL dashboard regions"
            className="grid flex-1 grid-cols-1 gap-4 py-6 lg:grid-cols-12"
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

        <footer className="flex flex-col gap-2 border-t border-white/10 pt-4 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <p>PulseLock · Radar · Guardian · Chronicle</p>
          <p>Security decisions remain deterministic.</p>
        </footer>
      </div>
    </main>
  );
}
