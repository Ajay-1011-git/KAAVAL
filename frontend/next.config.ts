import path from "node:path";
import type { NextConfig } from "next";

// The browser SDK lives in a sibling package (`sdk/`) and is linked into
// node_modules as a symlink by `npm install ../sdk`. Turbopack will not follow
// a symlink that points outside its project root, so the root is widened to
// the repository. Without this, `import ... from "@kaaval/sdk"` in
// app/demo/page.tsx fails to resolve at build time even though Node resolves
// it fine (amendment FIX-1/FIX-2).
const repositoryRoot = path.join(process.cwd(), "..");

const nextConfig: NextConfig = {
  turbopack: {
    root: repositoryRoot,
  },
  // The SDK ships compiled ESM, but it is a linked workspace package rather
  // than a published one, so Next is told explicitly to run it through the
  // same pipeline as first-party code.
  transpilePackages: ["@kaaval/sdk"],
  // Inline the CSS into each page's HTML instead of linking a separate
  // /_next/static/chunks/*.css file. In the two-laptop LAN demo the victim
  // laptop reaches the frontend through the attacker's hand-rolled TLS proxy;
  // the HTML page loaded reliably there, but the separate stylesheet request
  // did not, leaving the page rendered with no styling. Inlining removes that
  // second request entirely: the styles arrive inside the HTML the browser
  // already fetched, so the page can never render unstyled once it loads at
  // all. Trades a slightly larger HTML document for that reliability, which is
  // the right trade for a live demo.
  experimental: {
    inlineCss: true,
  },
};

export default nextConfig;
