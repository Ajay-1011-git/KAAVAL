import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "KAAVAL | Security Command Center",
  description:
    "Operational visibility for KAAVAL security decisions and incidents.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    // suppressHydrationWarning is scoped to this element's own attributes, one
    // level deep — it does not silence hydration errors inside the app. It is
    // here because browser extensions commonly write attributes onto <html>
    // before React hydrates (a screen recorder adding
    // data-scribe-recorder-ready was the observed case), which React reports
    // as a mismatch the page cannot avoid or fix. Suppressing it keeps a real
    // hydration bug in our own components visible instead of buried under a
    // warning nobody can action.
    <html lang="en" className="h-full antialiased" suppressHydrationWarning>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
