// Cross-language check of the browser wallet's core, in Node: a JS wallet (its own random
// secret) claims a deposit of 100 and pays 40 to the Python client's user B, found through
// B's directory entry. Writes the payload (for the service on lasair's rig) and the chain view
// after it (for B's Python client to scan), and scans that view as the JS wallet itself.
//   node test-core.mjs <out dir> <B's directory entry hex> <transfer.json>
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { readFileSync, writeFileSync } from "node:fs";
import * as W from "./lib/core.js";

const [dir, bEntry, circuitPath] = process.argv.slice(2);
await W.init();
const id = await W.identity(crypto.getRandomValues(new Uint8Array(32)));
const B = W.parseDirectory(bEntry);
const blinding = W.randomField();
const deposit = { kind: "deposit", value: 100n, blinding, leaf: null };
console.log("JS wallet account", id.account.slice(0, 16) + "…, deposit commitment", W.hex32(W.noteHash(id.pk, 100n, blinding)).slice(0, 16) + "…");
const chain = { leaves: [], sealed: [], nullRoot: 0n };
const { inputs, logs } = await W.transferInputs({ id, chain, ins: [deposit, null],
  outs: [{ pk: B.pk, encPub: B.encPub, value: 40n, blinding: W.randomField() },
         { pk: id.pk, encPub: id.enc.pub, value: 60n, blinding: W.randomField() }] });
const circuit = JSON.parse(readFileSync(circuitPath, "utf8"));
let t = performance.now();
const { witness } = await new Noir(circuit).execute(inputs);
const api = await Barretenberg.new();
const { proof, publicInputs } = await new UltraHonkBackend(circuit.bytecode, api).generateProof(witness, { verifierTarget: "evm" });
await api.destroy();
console.log(`witness and proof in ${(performance.now() - t).toFixed(0)} ms; ${publicInputs.length} public inputs`);
const f = W.fields(publicInputs);
if (f[12] !== 100n) throw new Error("the proof should claim a deposit of 100");
writeFileSync(`${dir}/js.hex`, W.hex(W.payload(publicInputs, proof, logs)));
const after = { leaves: [W.hex32(f[7]), W.hex32(f[8])], sealed: [W.hex(logs.slice(0, 88)), W.hex(logs.slice(88))], null_root: W.hex32(f[4]), note_root: W.hex32(f[3]) };
writeFileSync(`${dir}/js-chain.json`, JSON.stringify(after));
// the JS wallet's own view of the chain: its change, not B's payment
const mine = await W.scan(id, after);
if (mine.length !== 1 || mine[0].value !== 60n || mine[0].leaf !== 1) throw new Error("the JS wallet should find exactly its 60 at leaf 1: " + JSON.stringify(mine, (_, v) => typeof v === "bigint" ? v.toString() : v));
// the root the JS tree computes after the insertion equals the proof's new root
if (new W.Tree(after.leaves.map((x) => BigInt("0x" + x))).root() !== f[3]) throw new Error("tree root mismatch");
console.log("JS wallet scan: found its 60 at leaf 1; the JS tree's root equals the proof's new root");
