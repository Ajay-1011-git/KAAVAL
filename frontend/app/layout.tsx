import type { Metadata } from "next";
import { Anton, JetBrains_Mono, Space_Grotesk } from "next/font/google";

import "./globals.css";

// Substitutes for the three proprietary faces the design spec names. See the
// comment block in globals.css for the mapping and the line-height correction
// the Anton substitution requires.
const anton = Anton({
  subsets: ["latin"],
  weight: "400",
  variable: "--font-anton",
  display: "swap",
});

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-grotesk",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono-face",
  display: "swap",
});

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
    <html
      lang="en"
      className={`h-full antialiased ${anton.variable} ${spaceGrotesk.variable} ${jetbrainsMono.variable}`}
      suppressHydrationWarning
    >
      <body className="text-hazard flex min-h-full flex-col">
        {children}
      </body>
    </html>
  );
}
