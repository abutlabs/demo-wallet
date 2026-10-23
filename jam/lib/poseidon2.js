// Poseidon2 over BN254 (t = 4, 8 full + 56 partial rounds, x^5): the permutation Noir's
// solver runs and noir-lang/poseidon v0.4.0's sponge (rate 3, length * 2^64 as the initial
// capacity). Constants: poseidon2-bn254.json, from Noir v1.0.0-rc.5 (the same file
// jam-privacy-service's client/poseidon2.py reads). Browser and Node; BigInt.
export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let C = null;
export async function load(url = new URL("./poseidon2-bn254.json", import.meta.url)) {
  if (C) return;
  const j = typeof window === "undefined"
    ? JSON.parse(await (await import("node:fs/promises")).readFile(url, "utf8"))
    : await (await fetch(url)).json();
  C = { diag: j.internal_matrix_diagonal.map((x) => BigInt("0x" + x)),
        rc: j.round_constant.map((r) => r.map((x) => BigInt("0x" + x))),
        rf: j.rounds_f, rp: j.rounds_p, vectors: j.permutation_vectors };
}

const mod = (x) => ((x % P) + P) % P;
const pow5 = (x) => { const s = x * x % P; return s * s % P * x % P; };
function mds4(s) {
  const t0 = (s[0] + s[1]) % P, t1 = (s[2] + s[3]) % P;
  const t2 = (2n * s[1] + t1) % P, t3 = (2n * s[3] + t0) % P;
  const t4 = (4n * t1 + t3) % P, t5 = (4n * t0 + t2) % P;
  return [(t3 + t5) % P, t5, (t2 + t4) % P, t4];
}

export function permute(state) {
  if (!C) throw new Error("poseidon2: call load() first");
  let s = mds4(state.map(mod));
  const half = C.rf / 2;
  for (let r = 0; r < half; r++) s = mds4(s.map((x, i) => pow5((x + C.rc[r][i]) % P)));
  for (let r = half; r < half + C.rp; r++) {
    s[0] = pow5((s[0] + C.rc[r][0]) % P);
    const total = (s[0] + s[1] + s[2] + s[3]) % P;
    s = s.map((x, i) => (x * C.diag[i] + total) % P);
  }
  for (let r = half + C.rp; r < C.rf + C.rp; r++) s = mds4(s.map((x, i) => pow5((x + C.rc[r][i]) % P)));
  return s;
}

/** noir-lang/poseidon `Poseidon2::hash(inputs, inputs.len())`. */
export function hash(inputs) {
  const n = inputs.length;
  let state = [0n, 0n, 0n, mod(BigInt(n) << 64n)];
  for (let c = 0; c < Math.floor(n / 3); c++) {
    for (let i = 0; i < 3; i++) state[i] = (state[i] + mod(BigInt(inputs[3 * c + i]))) % P;
    state = permute(state);
  }
  const rem = n % 3;
  for (let j = 0; j < rem; j++) state[j] = (state[j] + mod(BigInt(inputs[n - rem + j]))) % P;
  if (n === 0 || rem) state = permute(state);
  return state[0];
}

/** The same checks as client/poseidon2.py's: the solver's vectors, hash_cli's outputs, the empty tree. */
export function selfTest() {
  for (const v of C.vectors) {
    const out = permute(v.in.map((x) => BigInt("0x" + x)));
    if (out.some((x, i) => x !== BigInt("0x" + v.out[i]))) throw new Error("permutation vector mismatch");
  }
  if (hash([7n, 11n, 13n]) !== 0x1c7467e229cb2aadc6793686c07a90a4b96f2ee7c6b557e3c6ef5d92f1fa253cn) throw new Error("H(7,11,13)");
  if (hash([0n, 0n]) !== 0x0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1n) throw new Error("H(0,0)");
  let z = 0n; for (let i = 0; i < 16; i++) z = hash([z, z]);
  if (z !== 0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3n) throw new Error("empty tree root");
  return true;
}
