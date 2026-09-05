// Every timestamp on the wire is UTC — the SecurityEvent contract, the Radar
// report and the Chronicle explanation all carry ISO-8601 Zulu strings, and
// PulseLock's freshness window is checked against UTC server-side. That does
// not change. This is the display layer only: the demo is run and watched in
// India, so the dashboard renders those instants in IST.
export const IST_TIME_ZONE = "Asia/Kolkata";

// The label shown next to a rendered time, so the two can never drift apart.
export const IST_LABEL = "IST";
