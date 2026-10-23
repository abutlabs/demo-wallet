// Node check of the browser's proving path: noir_js executes the transfer circuit, bb.js
// proves it for the evm target, and the payload goes to the service exactly as the
// Python client builds it. node test-bbjs.mjs <dir with transfer.json, inputs.json, logs.hex>
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { readFileSync, writeFileSync } from "node:fs";

const dir = process.argv[2];
const circuit = JSON.parse(readFileSync(`${dir}/transfer.json`, "utf8"));
const inputs = JSON.parse(readFileSync(`${dir}/inputs.json`, "utf8"));
const logs = Buffer.from(readFileSync(`${dir}/logs.hex`, "utf8").trim(), "hex");

let t = performance.now();
const { witness } = await new Noir(circuit).execute(inputs);
console.log(`witness in ${(performance.now() - t).toFixed(0)} ms`);
const api = await Barretenberg.new();
const backend = new UltraHonkBackend(circuit.bytecode, api);
t = performance.now();
const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget: "evm" });
console.log(`proof ${proof.length} bytes, ${publicInputs.length} public inputs, in ${(performance.now() - t).toFixed(0)} ms`);
console.log("bb.js verifies its own proof:", await backend.verifyProof({ proof, publicInputs }, { verifierTarget: "evm" }));
const vk = await backend.getVerificationKey({ verifierTarget: "evm" });
writeFileSync(`${dir}/vk-bbjs`, vk);
// the service's payload: [pubs_len u16][pubs][proof_len u16][proof][sealed notes]
const pubs = Buffer.concat(publicInputs.map((x) => Buffer.from(x.replace(/^0x/, "").padStart(64, "0"), "hex")));
const u16 = (n) => Buffer.from([n & 255, n >> 8]);
writeFileSync(`${dir}/bbjs.hex`, Buffer.concat([u16(pubs.length), pubs, u16(proof.length), Buffer.from(proof), logs]).toString("hex"));
await api.destroy();
