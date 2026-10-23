// The browser wallet's core: the same notes, tree, inputs and payload as jam-privacy-service's
// client/privacy.py, with the keys in the browser. Works in the page and in Node (tests).
//   identity: a random 32-byte secret -> spend key (sk, pk = H(sk)), note-encryption key,
//             public account (where unshields pay and what the directory names)
//   a note:   H(owner_pk, value, blinding); its nullifier H(note hash, owner sk); a deposit's
//             nullifier is its commitment
//   a payload [pubs_len u16][pubs][proof_len u16][proof][two sealed notes]
import * as P2 from "./poseidon2.js";
import { blake2b } from "./blake2b.js";
import * as NC from "./notecrypt.js";

export const P = P2.P;
export const DEPTH = 40;        // the note tree (Aztec: 40)
export const NULL_DEPTH = 40;   // the indexed nullifier tree (Aztec: 40)
const c = globalThis.crypto;
const enc = new TextEncoder();
export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s) => Uint8Array.from(s.replace(/^0x/, "").match(/../g) || [], (x) => parseInt(x, 16));
export const hex32 = (n) => BigInt(n).toString(16).padStart(64, "0");
const H = (...xs) => P2.hash(xs.map(BigInt));

async function sha256(...parts) {
  const bytes = new Uint8Array(parts.reduce((a, p) => [...a, ...(typeof p === "string" ? enc.encode(p) : p)], []));
  return new Uint8Array(await c.subtle.digest("SHA-256", bytes));
}
const toField = (b) => BigInt("0x" + hex(b)) % P;

export async function init() { await P2.load(); }

/** Everything the wallet derives from its secret. */
export async function identity(secret) {
  const sk = toField(await sha256("jam-privacy-spend:", secret));
  const encPriv = await sha256("jam-privacy-enc-key", secret);
  const ek = await NC.keyPair(encPriv);
  const acct = await sha256("jam-privacy-account:", secret);
  acct[0] = 0;                                   // a field element, as the circuit needs it
  return { sk, pk: H(sk), enc: ek, account: hex(acct) };
}

/** The directory entry others pay this identity by: encryption key || spend public key. */
export const directoryEntry = (id) => hex(id.enc.pub) + hex32(id.pk);
export const parseDirectory = (h) => ({ encPub: unhex(h.slice(0, 64)), pk: BigInt("0x" + h.slice(64, 128)) });

export const noteHash = (pk, value, blinding) => H(pk, value, blinding);
export const nullifier = (nh, sk) => H(nh, sk);
export const randomField = () => toField(c.getRandomValues(new Uint8Array(32)));

export class Tree {
  constructor(leaves, depth = DEPTH) {
    this.leaves = leaves.map(BigInt);
    this.depth = depth;
    this.memo = new Map();
    this.z = [0n];
    for (let i = 0; i < depth; i++) this.z.push(H(this.z[i], this.z[i]));
  }
  node(level, index) {
    if (level === 0) return index < this.leaves.length ? this.leaves[index] : 0n;
    if (index * 2 ** level >= this.leaves.length) return this.z[level];
    const k = level * 1e9 + index;
    if (!this.memo.has(k)) this.memo.set(k, H(this.node(level - 1, 2 * index), this.node(level - 1, 2 * index + 1)));
    return this.memo.get(k);
  }
  root() { return this.node(this.depth, 0); }
  path(index, fromLevel = 0) {
    const sib = []; let i = index >> fromLevel;
    for (let level = fromLevel; level < this.depth; level++) { sib.push(this.node(level, i ^ 1)); i >>= 1; }
    return sib;
  }
  /** Write leaf `index` (or append it at the end); only its ancestors are rehashed. */
  set(index, leaf) {
    this.leaves[index] = BigInt(leaf);
    for (let level = 1; level <= this.depth; level++) this.memo.delete(level * 1e9 + Math.floor(index / 2 ** level));
  }
}

/** Aztec's indexed Merkle tree of nullifiers (as client/privacy.py's IndexedTree): leaf i =
 *  [value, next_index, next_value], a linked list sorted by value; leaf 0 is the zero leaf. The
 *  list is linked first and hashed once; each insert then rehashes only its two leaves' paths. */
export class IndexedTree {
  constructor(nullifiers = []) {
    this.leaves = [[0n, 0n, 0n]];
    this.values = [0n];                    // every leaf's value, ascending
    this.at = new Map([[0n, 0]]);          // value -> leaf index
    this._tree = null;
    for (const nf of nullifiers) this._link(BigInt(nf), false);
  }
  /** The position of the first value >= nf. */
  rank(nf) {
    let lo = 0, hi = this.values.length;
    while (lo < hi) { const m = (lo + hi) >> 1; if (this.values[m] < nf) lo = m + 1; else hi = m; }
    return lo;
  }
  low(nf) {
    const r = this.rank(nf);
    const best = r ? this.at.get(this.values[r - 1]) : 0;
    const [v, , nv] = this.leaves[best];
    if (v === nf || (nv !== 0n && !(nf < nv))) throw new Error("that nullifier is already in the tree");
    return best;
  }
  tree() {
    if (!this._tree) this._tree = new Tree(this.leaves.map(([v, ni, nv]) => H(v, ni, nv)), NULL_DEPTH);
    return this._tree;
  }
  root() { return this.tree().root(); }
  _set(index, leaf) {
    this.leaves[index] = leaf;
    if (this._tree) this._tree.set(index, H(...leaf));
  }
  _link(nf, witness) {
    const lo = this.low(nf);
    const [v, ni, nv] = this.leaves[lo];
    const low = witness && { value: v.toString(), next_index: ni.toString(), next_value: nv.toString(), index: String(lo), path: this.tree().path(lo).map(String) };
    const fresh = this.leaves.length;
    this._set(lo, [v, BigInt(fresh), nf]);
    const slot = witness && this.tree().path(fresh).map(String);
    this._set(fresh, [nf, ni, nv]);
    this.values.splice(this.rank(nf), 0, nf);
    this.at.set(nf, fresh);
    return { low, slot };
  }
  /** Insert nf; returns the circuit's witness: the low leaf, its path, the new slot's path. */
  insert(nf) { return this._link(nf, true); }
}

/** blake2b-256 of the sealed notes, first byte zeroed: the logs_hash public input. */
export function logsHash(logs) { const h = blake2b(logs, 32); h[0] = 0; return BigInt("0x" + hex(h)); }

/**
 * The transfer's circuit inputs and its sealed notes.
 *   ins:  two of { kind: "tree"|"deposit", value, blinding, leaf } or null (a dummy)
 *   outs: two of { pk, encPub, value, blinding }
 */
export async function transferInputs({ id, chain, ins, outs, unshield = 0n, receiver = 0n, dest = 0n }) {
  const tree = new Tree(chain.leaves.map((x) => BigInt("0x" + x)));
  const insert = tree.leaves.length;
  if (insert % 2) throw new Error(`the tree has an odd number of leaves (${insert})`);
  const logs = new Uint8Array([
    ...await NC.seal(outs[0].encPub, NC.notePlaintext(outs[0].value, outs[0].blinding)),
    ...await NC.seal(outs[1].encPub, NC.notePlaintext(outs[1].value, outs[1].blinding)),
  ]);
  // every nullifier is known before proving: the circuit inserts both into the indexed tree
  const dummy = ins.map((n) => (n === null ? randomField() : null));
  const nfs = ins.map((n, j) => {
    if (n === null) return nullifier(noteHash(id.pk, 0n, dummy[j]), id.sk);
    const nh = noteHash(id.pk, BigInt(n.value), BigInt(n.blinding));
    return n.kind === "deposit" ? nh : nullifier(nh, id.sk);
  });
  const itree = new IndexedTree((chain.nullifiers || []).map((x) => BigInt("0x" + x)));
  const oldNullRoot = itree.root(), nullSize = itree.leaves.length;
  const wit = nfs.map((nf) => itree.insert(nf));
  const inNote = (n, j) => n === null
    ? { owner_sk: id.sk.toString(), value: "0", blinding: dummy[j].toString(), kind: "0", index: "0", path: Array(DEPTH).fill("0") }
    : { owner_sk: id.sk.toString(), value: BigInt(n.value).toString(), blinding: BigInt(n.blinding).toString(),
        kind: n.kind === "deposit" ? "2" : "1", index: String(n.leaf ?? 0),
        path: (n.kind === "deposit" ? Array(DEPTH).fill(0n) : tree.path(n.leaf)).map(String) };
  const inputs = {
    old_note_root: tree.root().toString(),
    old_null_root: oldNullRoot.toString(),
    logs_hash: logsHash(logs).toString(),
    old_null_size: String(nullSize),
    lows: wit.map((w) => w.low),
    null_slot_paths: wit.map((w) => w.slot),
    insert_index1: String(insert / 2),
    insert_path: tree.path(insert, 1).map(String),
    unshield_amount: BigInt(unshield).toString(),
    unshield_receiver: BigInt(receiver).toString(),
    unshield_dest: BigInt(dest).toString(),
    ins: ins.map(inNote),
    outs: outs.map((o) => ({ owner_pk: BigInt(o.pk).toString(), value: BigInt(o.value).toString(), blinding: BigInt(o.blinding).toString() })),
  };
  return { inputs, logs, insert };
}

/** The service's payload from bb.js's proof. */
export function payload(publicInputs, proof, logs) {
  const pubs = unhex(publicInputs.map((x) => x.replace(/^0x/, "").padStart(64, "0")).join(""));
  const u16 = (n) => [n & 255, n >> 8];
  return new Uint8Array([...u16(pubs.length), ...pubs, ...u16(proof.length), ...proof, ...logs]);
}

/** The public inputs as numbers: [old root, old null root, logs hash, old null size, new root,
 *  new null root, nf0, nf1, nh0, nh1, unshield amount, receiver, dest, deposit]. */
export const fields = (publicInputs) => publicInputs.map((x) => BigInt(x));

/** Notes on chain sealed to this identity that hash to their leaf: { leaf, value, blinding, hash }. */
export async function scan(id, chain, fromLeaf = 0) {
  const found = [];
  for (let i = fromLeaf; i < chain.sealed.length; i++) {
    if (!chain.sealed[i]) continue;
    const pt = await NC.open(id.enc.priv, unhex(chain.sealed[i]));
    if (!pt) continue;
    const { value, blinding } = NC.noteFromPlaintext(pt);
    const nh = noteHash(id.pk, value, blinding);
    if (nh !== BigInt("0x" + chain.leaves[i])) continue;      // opens, but not this leaf's note
    found.push({ leaf: i, value, blinding, hash: nh, kind: "tree" });
  }
  return found;
}
