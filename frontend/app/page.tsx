import { IncidentTimeline } from "@/app/components/IncidentTimeline";
import { LiveEventFeed } from "@/app/components/LiveEventFeed";
import { RadarPanel } from "@/app/components/RadarPanel";
import { SecurityEventsProvider } from "@/lib/eventsClient";
import radarFixture from "@/public/fixtures/radar-report.json";

const dashboardRegions = [
  {
    id: "chronicle",
    eyebrow: "Post-decision explanation",
    title: "Chronicle",
    description: "Select an incident to generate a grounded explanation.",
    span: "lg:col-span-5",
  },
] as const;

export default function Home() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex min-h-screen w-full max-w-[1600px] flex-col px-5 py-6 sm:px-8 lg:px-10">
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

          <div className="flex items-center gap-3 self-start rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs text-slate-300 sm:self-auto">
            <span
              aria-hidden="true"
              className="size-2 rounded-full bg-amber-300 shadow-[0_0_12px_rgba(252,211,77,0.7)]"
            />
            Awaiting live data
          </div>
        </header>

        <section
          aria-label="KAAVAL dashboard regions"
          className="grid flex-1 grid-cols-1 gap-4 py-6 lg:grid-cols-12"
        >
          <SecurityEventsProvider>
            <RadarPanel
              initialReport={
                process.env.NEXT_PUBLIC_BACKEND_ORIGIN ? null : radarFixture
              }
            />
            <LiveEventFeed />
            <IncidentTimeline />
            {dashboardRegions.map((region) => (
              <section
                key={region.id}
                aria-labelledby={`${region.id}-title`}
                className={`${region.span} flex min-h-72 flex-col rounded-2xl border border-white/10 bg-slate-900/70 p-5 shadow-2xl shadow-black/10 sm:p-6`}
              >
                <div className="flex items-start justify-between gap-4 border-b border-white/10 pb-4">
                  <div>
                    <p className="text-[0.68rem] font-semibold tracking-[0.2em] text-emerald-300 uppercase">
                      {region.eyebrow}
                    </p>
                    <h2
                      id={`${region.id}-title`}
                      className="mt-2 text-xl font-semibold tracking-tight text-white"
                    >
                      {region.title}
                    </h2>
                  </div>
                </div>

                <div className="grid flex-1 place-items-center py-8 text-center">
                  <div className="max-w-xs">
                    <div
                      aria-hidden="true"
                      className="mx-auto mb-4 size-10 rounded-full border border-dashed border-slate-600 bg-slate-950/50"
                    />
                    <p className="text-sm leading-6 text-slate-500">
                      {region.description}
                    </p>
                  </div>
                </div>
              </section>
            ))}
          </SecurityEventsProvider>
        </section>

        <footer className="flex flex-col gap-2 border-t border-white/10 pt-4 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <p>PulseLock · Radar · Guardian · Chronicle</p>
          <p>Security decisions remain deterministic.</p>
        </footer>
      </div>
    </main>
  );
}
