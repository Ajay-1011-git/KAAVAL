// The colour-block story tiles from the design spec, carrying the one thing
// the panels above cannot say for themselves: what each module is and, more
// to the point, what it deliberately refuses to do.
//
// Every claim below is the project's stated ground truth (CLAUDE.md, PRD
// FR-9/FR-11, NFR-1/NFR-2, TRD section 6.1). Nothing here is illustrative
// copy, because a page whose whole argument is "do not trust what you cannot
// verify" cannot afford invented filler.

const TILES = [
  {
    kicker: "PulseLock",
    title: "A stolen cookie proves nothing on its own",
    body: "The browser generates a non-exportable ECDSA P-256 key pair and binds it to the session. Every protected request carries a fresh signature, and the gateway runs seven checks over it in a fixed order. Replay a captured request and the nonce check ends it.",
    fill: "bg-mint text-inverted",
    span: "lg:col-span-7",
    scale: "text-[2rem] leading-[1.1] font-normal tracking-[0.02em]",
  },
  {
    kicker: "Radar",
    title: "Nine checks, and no risk score",
    body: "Every finding names the exact check that produced it. There is no model and no confidence value, so nothing on screen can stand in for a reason an operator is able to trace.",
    fill: "bg-panel border-hazard/25 border",
    span: "lg:col-span-5",
    scale: "text-[1.5rem] leading-none font-bold",
  },
  {
    kicker: "Guardian",
    title: "Device code is denied by default",
    body: "Consent and device-code requests meet deterministic if/else policy. Nothing probabilistic is allowed to approve, deny, or alter an authorization decision.",
    fill: "bg-ultraviolet text-hazard",
    span: "lg:col-span-5",
    scale: "text-[1.5rem] leading-none font-bold",
  },
  {
    kicker: "Chronicle",
    title: "It explains the decision, it never makes it",
    body: "Narration runs only once a decision is already recorded, over redacted event JSON. If the model is unreachable or answers something the events do not support, a deterministic narrative takes its place and the request still succeeds.",
    fill: "bg-hazard text-inverted",
    span: "lg:col-span-7",
    scale: "text-[2rem] leading-[1.1] font-normal tracking-[0.02em]",
  },
] as const;

export function SystemStory() {
  return (
    <section
      aria-labelledby="system-story-title"
      className="border-hazard/15 border-t py-10"
    >
      <h2
        id="system-story-title"
        className="font-mono text-[0.75rem] font-semibold tracking-[0.16em] uppercase"
      >
        What the panels above are doing
      </h2>

      <div className="mt-6 grid gap-4 lg:grid-cols-12">
        {TILES.map((tile) => (
          <article
            key={tile.kicker}
            className={`rounded-feature p-8 sm:p-10 ${tile.fill} ${tile.span}`}
          >
            {/* 80% and not lower: at 60% this kicker measures 3.2:1 against
                the ultraviolet fill, under AA for its size. 80% clears 4.5:1
                on all four fills. */}
            <p className="font-mono text-[0.7rem] font-semibold tracking-[0.16em] uppercase opacity-80">
              {tile.kicker}
            </p>
            <h3 className={`mt-4 ${tile.scale}`}>{tile.title}</h3>
            <p className="mt-4 max-w-[46ch] text-sm leading-6 opacity-80">
              {tile.body}
            </p>
          </article>
        ))}
      </div>
    </section>
  );
}
