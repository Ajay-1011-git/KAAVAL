// Shared presentational primitives for the dashboard, so the Verge tokens are
// declared once rather than re-typed as class strings in seven components.
// Nothing here is stateful or client-only.

import type { ReactNode } from "react";

/**
 * A dashboard panel. The header is a single mono uppercase label rather than
 * the kicker-plus-headline pair the previous design used on every panel: two
 * stacked labels saying the same thing was the largest source of visual noise
 * on this page.
 */
export function Panel({
  id,
  title,
  badge,
  children,
  className = "",
  busy,
}: {
  id: string;
  title: string;
  badge?: ReactNode;
  children: ReactNode;
  className?: string;
  busy?: boolean;
}) {
  return (
    <section
      aria-labelledby={id}
      aria-busy={busy}
      className={`border-hazard/15 bg-canvas rounded-feature flex flex-col border p-5 sm:p-7 ${className}`}
    >
      <div className="border-hazard/10 flex flex-wrap items-center justify-between gap-3 border-b pb-4">
        <h2
          id={id}
          className="font-mono text-[0.75rem] font-semibold tracking-[0.16em] uppercase"
        >
          {title}
        </h2>
        {badge}
      </div>
      {children}
    </section>
  );
}

/** Non-interactive category tag. Spec section 4, "Pill Tag". */
export function Tag({
  children,
  tone = "quiet",
}: {
  children: ReactNode;
  tone?: "quiet" | "mint" | "violet" | "white";
}) {
  const tones = {
    quiet: "border border-hazard/20 text-meta",
    mint: "bg-mint text-inverted",
    violet: "bg-ultraviolet text-hazard",
    white: "bg-hazard text-inverted",
  } as const;

  return (
    <span
      className={`rounded-tile px-2.5 py-1 font-mono text-[0.65rem] font-semibold tracking-[0.16em] uppercase ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

/**
 * Buttons. `mint` is the primary pill, `outline` the tertiary mint outline.
 *
 * Deviation from the spec, recorded deliberately: the spec's hover state is a
 * translucent white fill keeping black text, which measures about 2.3:1 on
 * this canvas and fails WCAG AA. Hover here goes to a solid white fill with
 * black text instead, which preserves the "invert on hover" gesture at 16:1.
 */
const buttonBase =
  "inline-flex min-h-11 cursor-pointer items-center justify-center whitespace-nowrap font-mono text-[0.72rem] font-semibold tracking-[0.14em] uppercase transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-40";

export const buttonStyles = {
  mint: `${buttonBase} rounded-cta bg-mint text-inverted px-6 hover:bg-hazard`,
  outline: `${buttonBase} rounded-cta border border-mint text-mint px-5 hover:bg-mint hover:text-inverted`,
  quiet: `${buttonBase} rounded-cta border border-hazard/25 text-muted px-5 hover:border-hazard hover:bg-hazard hover:text-inverted`,
  violet: `${buttonBase} rounded-cta border border-ultraviolet text-hazard px-5 hover:bg-ultraviolet`,
} as const;

/** Empty and error placeholders, shared so every panel fails the same way. */
export function PanelMessage({
  title,
  body,
  action,
}: {
  title: string;
  body: string;
  action?: ReactNode;
}) {
  return (
    <div className="grid flex-1 place-items-center py-10 text-center">
      <div className="max-w-xs">
        <p className="text-sm font-bold">{title}</p>
        <p className="text-meta mt-2 text-xs leading-5">{body}</p>
        {action ? <div className="mt-5">{action}</div> : null}
      </div>
    </div>
  );
}

export function Spinner({ label }: { label: string }) {
  return (
    <div role="status" className="grid flex-1 place-items-center py-10">
      <div className="text-meta text-center text-xs">
        <span
          aria-hidden="true"
          className="border-hazard/15 border-t-mint mx-auto mb-4 block size-7 animate-spin rounded-full border-2"
        />
        {label}
      </div>
    </div>
  );
}
