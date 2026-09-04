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
};

export default nextConfig;
