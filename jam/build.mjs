// Bundles the page's provers (npm run build). One change to bb.js on the way: its reference
// string (CRS) comes from the page's own origin, /crs/ (the wallet server serves it from a
// local cache), with Aztec's S3 host kept as the fallback. So a demo needs no CDN, and a
// first proof does not wait on a 20 MB download.
import { build } from "esbuild";
import { readFile, copyFile, mkdir } from "node:fs/promises";

const PRIMARY = "const CRS_PRIMARY_HOST = 'https://crs.aztec-cdn.foundation';";
const localCrs = {
  name: "local-crs",
  setup(b) {
    b.onLoad({ filter: /crs[\\/]net_crs\.js$/ }, async (args) => {
      const src = await readFile(args.path, "utf8");
      if (!src.includes(PRIMARY)) throw new Error(`bb.js changed: ${PRIMARY} not in ${args.path}`);
      return { contents: src.replace(PRIMARY, "const CRS_PRIMARY_HOST = self.location.origin + '/crs';"), loader: "js" };
    });
  },
};
const common = { bundle: true, format: "esm", platform: "browser", target: "es2022", logLevel: "warning", plugins: [localCrs] };
const W = "node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm";
await mkdir("dist", { recursive: true });
await build({ ...common, entryPoints: ["src/provers.js"], outfile: "dist/provers.js" });
await build({ ...common, entryPoints: [`${W}/barretenberg_wasm_main/factory/browser/main.worker.js`], outfile: "dist/main.worker.js" });
await build({ ...common, entryPoints: [`${W}/barretenberg_wasm_thread/factory/browser/thread.worker.js`], outfile: "dist/thread.worker.js" });
for (const f of ["node_modules/@noir-lang/acvm_js/web/acvm_js_bg.wasm", "node_modules/@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm"])
  await copyFile(f, "dist/" + f.split("/").pop());
const out = await readFile("dist/provers.js", "utf8");
if (!out.includes("self.location.origin + \"/crs\"") && !out.includes("self.location.origin + '/crs'"))
  throw new Error("the local CRS host is not in dist/provers.js");
