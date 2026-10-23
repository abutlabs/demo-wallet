// The two provers the page needs, bundled once into dist/provers.js (npm run build): noir_js
// computes the witness, bb.js proves it. Everything else in the page is unbundled ES modules.
export { Noir } from "@noir-lang/noir_js";
export { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
