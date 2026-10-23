// The JAM privacy wallet: a self-custodial page. Its secret stays in this browser
// (localStorage, per wallet name); it proves every transfer here (noir_js + bb.js), finds its
// notes by scanning the chain's sealed notes with its own key, and talks to the chain only
// through the indexer's public JIP-2 view. Nothing else knows its keys.
//   ?user=<name>      which wallet in this browser (default "A")
//   ?indexer=<url>    the indexer (default http://localhost:19700)
import * as W from "./lib/core.js";

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const NAME = params.get("user") || "A";
const INDEXER = (params.get("indexer") || "http://localhost:19700").replace(/\/$/, "");
const STORE = `jam-privacy-wallet:${NAME}`;
const WAIT_S = 36, TRIES = 3;               // a package that never lands is sent again (lasair#93)

let id = null, wallet = null, chain = null, busy = false, provers = null, circuit = null;

// ---- persistence: this browser only ------------------------------------------------------
function loadWallet() {
  try {
    const w = JSON.parse(localStorage.getItem(STORE) || "null");
    if (w && w.secret) return w;
  } catch { /* a fresh wallet below */ }
  return { secret: W.hex(crypto.getRandomValues(new Uint8Array(32))), notes: [], deposits: [], scannedTo: 0, chainHead: null };
}
const big = (_, v) => typeof v === "bigint" ? v.toString() : v;
function saveWallet() { localStorage.setItem(STORE, JSON.stringify(wallet, big)); }

// ---- the indexer ------------------------------------------------------------------------
async function get(path) {
  const r = await fetch(INDEXER + path, { cache: "no-store" });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || `indexer ${path}: ${r.status}`);
  return j;
}
async function submit(service, bytes) {
  const r = await fetch(`${INDEXER}/submit/${service}`, { method: "POST", body: W.hex(bytes) });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || `submit: ${r.status}`);
  return j;
}
const u64le = (n) => { const b = new Uint8Array(8); let x = BigInt(n); for (let i = 0; i < 8; i++) { b[i] = Number(x & 255n); x >>= 8n; } return b; };
const u32le = (n) => Uint8Array.from([n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255]);
const cat = (...xs) => new Uint8Array(xs.flatMap((x) => [...x]));

/** Send `bytes` until `done()`; a package not seen landing in WAIT_S is sent again. */
async function submitUntil(service, bytes, done, label, steps) {
  for (let attempt = 1; attempt <= TRIES; attempt++) {
    const t0 = Date.now();
    const r = await submit(service, bytes);
    steps(`${label}: package ${r.package_hash.slice(0, 12)}… on core ${r.core}${attempt > 1 ? ` (resend ${attempt - 1})` : ""}`);
    while (Date.now() - t0 < WAIT_S * 1000) {
      if (await done()) { steps(`${label}: on chain after ${Math.round((Date.now() - t0) / 1000)} s`); return; }
      await new Promise((ok) => setTimeout(ok, 2000));
    }
    steps(`${label}: not on chain after ${WAIT_S} s`);
  }
  throw new Error(`${label}: never reached the chain after ${TRIES} sends`);
}

// ---- the chain, as this wallet sees it ---------------------------------------------------
async function refreshChain() {
  chain = await get("/state");
  const found = await W.scan(id, { leaves: chain.leaves, sealed: chain.sealed }, wallet.scannedTo);
  for (const n of found) {
    if (!wallet.notes.some((m) => m.leaf === n.leaf)) wallet.notes.push({ ...n, spent: false });
  }
  wallet.scannedTo = chain.leaves.length;
  // a note is spent when the chain records its nullifier, whoever spent it
  for (const n of wallet.notes.filter((m) => !m.spent && BigInt(m.value) > 0n)) {
    const nf = W.hex32(W.nullifier(BigInt(n.hash), id.sk));
    if ((await get(`/nullifier/${nf}`)).spent) n.spent = true;
  }
  saveWallet();
}

const unspent = () => wallet.notes.filter((n) => !n.spent && BigInt(n.value) > 0n);
const privateBalance = () => unspent().reduce((s, n) => s + BigInt(n.value), 0n);

async function publicBalance() { return BigInt((await get(`/balance/${id.account}`)).balance); }

/** Two inputs covering `amount`, largest first; an unclaimed deposit only in the first slot. */
function selectInputs(amount) {
  const deps = wallet.deposits.filter((d) => d.landed && !d.claimed).map((d) => ({ ...d, kind: "deposit", leaf: null }));
  const notes = [...deps, ...unspent().sort((a, b) => (BigInt(b.value) > BigInt(a.value) ? 1 : -1))];
  for (const k of [1, 2]) {
    for (let i = 0; i + k <= notes.length; i++) {
      const pick = notes.slice(i, i + k);
      if (k === 2 && pick[1].kind === "deposit") continue;
      if (pick.reduce((s, n) => s + BigInt(n.value), 0n) >= amount) return [...pick, ...Array(2 - k).fill(null)];
    }
  }
  throw new Error(`you hold ${privateBalance()} privately, not ${amount} in two notes`);
}

// ---- proving here ------------------------------------------------------------------------
async function prove(inputs, steps) {
  if (!provers) {
    steps("loading the provers (first proof only)");
    const m = await import("./dist/provers.js");
    provers = { Noir: m.Noir, backend: new m.UltraHonkBackend(circuit.bytecode, await m.Barretenberg.new({ threads: navigator.hardwareConcurrency || 1 })) };
  }
  const t0 = performance.now();
  const { witness } = await new provers.Noir(circuit).execute(inputs);
  const { proof, publicInputs } = await provers.backend.generateProof(witness, { verifierTarget: "evm" });
  steps(`proof of ${proof.length} bytes made in this browser in ${((performance.now() - t0) / 1000).toFixed(1)} s`);
  return { proof, publicInputs };
}

/** Prove a transfer of `ins` into `outs` (+ an unshield), submit it, wait for its root. */
async function transfer(label, ins, outs, extra, steps) {
  await refreshChain();
  const { inputs, logs } = await W.transferInputs({ id, chain: { leaves: chain.leaves, nullifiers: chain.nullifiers || [] }, ins, outs, ...extra });
  const { proof, publicInputs } = await prove(inputs, steps);
  const f = W.fields(publicInputs);
  const root = W.hex32(f[4]);
  await submitUntil(chain.privacy_id, W.payload(publicInputs, proof, logs),
    async () => (await get("/state")).note_root === root, label, steps);
  for (const n of ins.filter(Boolean)) {
    if (n.kind === "deposit") wallet.deposits.find((d) => d.commitment === n.commitment).claimed = true;
    else wallet.notes.find((m) => m.leaf === n.leaf).spent = true;
  }
  saveWallet();
  await refreshChain();                        // finds our outputs by scanning, like anyone would
}

const self = (value) => ({ pk: id.pk, encPub: id.enc.pub, value: BigInt(value), blinding: W.randomField() });

// ---- the moves ----------------------------------------------------------------------------
const ACTIONS = {
  async mint(amount, steps) {
    const before = await publicBalance();
    const p = cat([0], W.unhex(id.account), u64le(amount), crypto.getRandomValues(new Uint8Array(32)));
    await submitUntil(chain.public_id, p, async () => (await publicBalance()) === before + BigInt(amount), "mint", steps);
  },
  async shield(amount, steps) {
    const have = await publicBalance();
    if (have < BigInt(amount)) throw new Error(`you hold ${have} publicly, not ${amount}`);
    const blinding = W.randomField();
    const commitment = W.hex32(W.noteHash(id.pk, BigInt(amount), blinding));
    const dep = { value: String(amount), blinding: blinding.toString(), commitment, landed: false, claimed: false };
    wallet.deposits.push(dep); saveWallet();   // before sending: the opening must not be lost
    steps(`deposit note: commitment ${commitment.slice(0, 12)}…`);
    const p = cat([2], W.unhex(id.account), u64le(amount), u32le(chain.privacy_id), W.unhex(commitment));
    await submitUntil(chain.public_id, p, async () => (await get(`/deposit/${commitment}`)).amount === Number(amount), "shield", steps);
    dep.landed = true; saveWallet();
    await transfer("claim", [{ ...dep, kind: "deposit", leaf: null }, null], [self(amount), self(0)], {}, steps);
  },
  async send(amount, steps, to) {
    if (!/^[0-9a-f]{64}$/.test(to)) throw new Error("the recipient's address is 64 hex characters");
    const entry = (await get(`/key/${to}`)).key;
    if (!entry) throw new Error("that address has not published its keys yet (its wallet does on first load)");
    const r = W.parseDirectory(entry);
    const ins = selectInputs(BigInt(amount));
    const total = ins.filter(Boolean).reduce((s, n) => s + BigInt(n.value), 0n);
    await transfer("send", ins, [{ pk: r.pk, encPub: r.encPub, value: BigInt(amount), blinding: W.randomField() }, self(total - BigInt(amount))], {}, steps);
  },
  async unshield(amount, steps) {
    const ins = selectInputs(BigInt(amount));
    const total = ins.filter(Boolean).reduce((s, n) => s + BigInt(n.value), 0n);
    await transfer("unshield", ins, [self(0), self(total - BigInt(amount))],
      { unshield: BigInt(amount), receiver: BigInt("0x" + id.account), dest: BigInt(chain.public_id) }, steps);
  },
};

// ---- the page -------------------------------------------------------------------------------
function setStatus(kind, text) { const s = $("status"); s.className = "status " + kind; s.textContent = text; }

async function render() {
  $("address").textContent = id.account;
  $("public").textContent = (await publicBalance()).toString();
  $("private").textContent = privateBalance().toString();
  const notes = unspent();
  $("notes-count").textContent = notes.length === 1 ? "in 1 note only you can open" : `in ${notes.length} notes only you can open`;
  $("notes").replaceChildren(...(notes.length ? notes.map((n) => {
    const li = document.createElement("li");
    li.append(Object.assign(document.createElement("span"), { textContent: `note at leaf ${n.leaf}` }),
              Object.assign(document.createElement("strong"), { textContent: String(n.value) }));
    return li;
  }) : [Object.assign(document.createElement("li"), { textContent: "no private notes yet" })]));
  $("c-slot").textContent = chain.slot ?? "–";
  if (chain.net) $("chain-net").textContent = `JAM tiny · ${chain.net}`;
  $("c-root").textContent = chain.note_root ? "0x" + chain.note_root : "(empty tree)";
  $("c-leaves").textContent = chain.leaf_count ?? "–";
  $("c-transfers").textContent = chain.transfers ?? "–";
  $("c-flow").textContent = `${chain.shielded ?? "–"} / ${chain.unshielded ?? "–"}`;
  $("c-services").textContent = `privacy ${chain.privacy_id ?? "–"}, public-balance ${chain.public_id ?? "–"}`;
}

async function refresh() {
  if (busy) return;
  try { await refreshChain(); await render(); } catch (e) { setStatus("error", "error: " + e.message); }
}

async function act(action) {
  const amount = action === "mint" ? 100 : Number($(`amt-${action}`).value);
  const to = $("to-send").value.trim().toLowerCase();
  busy = true;
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
  $("steps").replaceChildren();
  const steps = (s) => $("steps").append(Object.assign(document.createElement("li"), { textContent: s }));
  const t0 = Date.now();
  setStatus("working", `working: ${action} · 0 s`);
  const tick = setInterval(() => setStatus("working", `working: ${action} · ${Math.round((Date.now() - t0) / 1000)} s`), 500);
  try {
    await ACTIONS[action](amount, steps, to);
    busy = false; await refresh();
    setStatus("done", `done: ${action} ${amount}${action === "send" ? " to " + to.slice(0, 8) + "…" : ""} in ${Math.round((Date.now() - t0) / 100) / 10} s`);
  } catch (e) {
    setStatus("error", `error: ${e.message}`);
  } finally {
    clearInterval(tick); busy = false;
    document.querySelectorAll("button").forEach((b) => (b.disabled = false));
  }
}

async function start() {
  $("wallet-name").textContent = `wallet ${NAME}`;
  await W.init();
  wallet = loadWallet(); saveWallet();
  id = await W.identity(W.unhex(wallet.secret));
  circuit = await (await fetch("./circuit/transfer.json")).json();
  await refreshChain();
  // publish how to pay this wallet, once (and again if the chain is new)
  const entry = W.directoryEntry(id);
  if ((await get(`/key/${id.account}`)).key !== entry) {
    setStatus("working", "publishing your address…");
    await submitUntil(chain.public_id, cat([3], W.unhex(id.account), W.unhex(entry)),
      async () => (await get(`/key/${id.account}`)).key === entry, "address", () => {});
  }
  $("key-status").textContent = "keys stay in this browser; your address is published";
  setStatus("idle", "idle");
  await render();
  document.querySelectorAll("button[data-action]").forEach((b) => b.addEventListener("click", () => act(b.dataset.action)));
  $("btn-copy").addEventListener("click", () => navigator.clipboard?.writeText(id.account));
  setInterval(refresh, 4000);
  document.title = `JAM Privacy Wallet · ${NAME}`;
  document.body.dataset.ready = "1";
}

start().catch((e) => setStatus("error", "error: " + e.message));
