// The JAM privacy wallet: a self-custodial page. It proves every transfer here (noir_js +
// bb.js), finds its notes by scanning the chain's sealed notes with its own key, and talks to
// the chain only through the indexer's public JIP-2 view.
//   ?user=<name>      which wallet (default "alice"). A JAM dev account's name (alice, bob,
//                     carol, david, eve, fergie) opens that account: its secret is its public
//                     JIP-5 seed, the same in every browser. Any other name is a wallet of this
//                     browser's own: a random secret in localStorage that nothing else knows.
//   ?indexer=<url>    the indexer (default http://localhost:19700)
import * as W from "./lib/core.js";

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const NAME = params.get("user") || "alice";
const DEV = W.devIndex(NAME);                 // -1: a wallet of this browser's own
const STORE = `jam-privacy-wallet:${DEV >= 0 ? NAME.toLowerCase() : NAME}`;
const INDEXER = (params.get("indexer") || "http://localhost:19700").replace(/\/$/, "");

const WAIT_S = 36, TRIES = 3;               // a package that never lands is sent again (lasair#93)

let id = null, wallet = null, chain = null, busy = false, provers = null, circuit = null;
let known = [];                               // the dev accounts: { name, account }

// ---- persistence: this browser only ------------------------------------------------------
function loadWallet() {
  try {
    const w = JSON.parse(localStorage.getItem(STORE) || "null");
    if (w && w.secret && (DEV < 0 || w.secret === W.hex(W.devSecret(DEV)))) return w;
  } catch { /* a fresh wallet below */ }
  const secret = DEV >= 0 ? W.devSecret(DEV) : crypto.getRandomValues(new Uint8Array(32));
  return { secret: W.hex(secret), notes: [], deposits: [], scannedTo: 0 };
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

/** Send `bytes` until `done()`; a package not seen landing in WAIT_S is sent again. With
 *  `stale()`, a send whose bytes can no longer land stops early: returns "stale", else "done". */
async function submitUntil(service, bytes, done, label, steps, stale = async () => false) {
  for (let attempt = 1; attempt <= TRIES; attempt++) {
    const t0 = Date.now();
    const r = await submit(service, bytes);
    steps(`${label}: package ${r.package_hash.slice(0, 12)}… on core ${r.core}${attempt > 1 ? ` (resend ${attempt - 1})` : ""}`);
    while (Date.now() - t0 < WAIT_S * 1000) {
      if (await done()) { steps(`${label}: on chain after ${Math.round((Date.now() - t0) / 1000)} s`); return "done"; }
      if (await stale()) return "stale";
      await new Promise((ok) => setTimeout(ok, 2000));
    }
    steps(`${label}: not on chain after ${WAIT_S} s`);
  }
  throw new Error(`${label}: never reached the chain after ${TRIES} sends`);
}

// ---- the chain, as this wallet sees it ---------------------------------------------------
async function refreshChain() {
  chain = await get("/state");
  if (!chain.ok) throw new Error(chain.error || "the indexer has not read the chain yet");
  // the tree is append-only: a chain without this wallet's notes where it found them is another
  // chain (the net was restarted or switched), and what the wallet knew of the old one is void
  const elsewhere = wallet.notes.some((n) => chain.leaves[n.leaf] !== W.hex32(BigInt(n.hash)));
  if (elsewhere || chain.leaves.length < wallet.scannedTo) {
    Object.assign(wallet, { notes: [], deposits: [], scannedTo: 0 });
  }
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

/** Prove a transfer of `ins` into `outs` (+ an unshield), submit it, wait until it lands.
 *  A proof starts from the chain's trees as this wallet saw them; once another transfer lands
 *  first, accumulate refuses it (the old roots are no longer the chain's) and resending the
 *  same bytes can never land, so the wallet proves again from the new trees. */
async function transfer(label, ins, outs, extra, steps) {
  for (let round = 1; round <= TRIES; round++) {
    await refreshChain();
    const size = chain.leaves.length;           // the tree this proof starts from
    const { inputs, logs } = await W.transferInputs({ id, chain: { leaves: chain.leaves, nullifiers: chain.nullifiers || [] }, ins, outs, ...extra });
    const { proof, publicInputs } = await prove(inputs, steps);
    const nf = W.hex32(W.fields(publicInputs)[6]);   // the first input's nullifier: never a dummy
    // one snapshot answers both: landed (our nullifier is the chain's) or stale (the tree grew without it)
    let view = null;
    const look = async () => (view = await get("/state"));
    const landed = async () => (await look()).nullifiers.includes(nf);
    const moved = async () => view.leaf_count !== size;
    const outcome = await submitUntil(chain.privacy_id, W.payload(publicInputs, proof, logs), landed, label, steps, moved);
    if (outcome === "done") {
      for (const n of ins.filter(Boolean)) {
        if (n.kind === "deposit") wallet.deposits.find((d) => d.commitment === n.commitment).claimed = true;
        else wallet.notes.find((m) => m.leaf === n.leaf).spent = true;
      }
      saveWallet();
      await refreshChain();                      // finds our outputs by scanning, like anyone would
      return;
    }
    steps(`${label}: another transfer landed first (${size} → ${view.leaf_count} leaves); this proof is stale, proving again`);
  }
  throw new Error(`${label}: the tree kept moving; ${TRIES} proofs were stale before they landed`);
}

/** A recipient typed as an address or a dev account's name. */
function recipient(to) {
  const k = known.find((a) => a.name.toLowerCase() === to.trim().toLowerCase());
  const addr = (k ? k.account : to).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(addr)) throw new Error("the recipient is a 64-hex-character address or a dev account's name");
  return addr;
}

const self = (value) => ({ pk: id.pk, encPub: id.enc.pub, value: BigInt(value), blinding: W.randomField() });

// ---- the moves ----------------------------------------------------------------------------
const ACTIONS = {
  async mint(amount, steps) {
    const before = await publicBalance();
    await submitUntil(chain.public_id, W.opMint(id.account, amount), async () => (await publicBalance()) === before + BigInt(amount), "mint", steps);
  },
  async pay(amount, steps, to) {
    to = recipient(to);
    if (to === id.account) throw new Error("that is your own address");
    const before = await publicBalance();
    if (before < BigInt(amount)) throw new Error(`you hold ${before} publicly, not ${amount}`);
    await submitUntil(chain.public_id, W.opTransfer(id.account, to, amount),
      async () => (await publicBalance()) === before - BigInt(amount), "pay", steps);
  },
  async shield(amount, steps) {
    const have = await publicBalance();
    if (have < BigInt(amount)) throw new Error(`you hold ${have} publicly, not ${amount}`);
    const blinding = W.randomField();
    const commitment = W.hex32(W.noteHash(id.pk, BigInt(amount), blinding));
    const dep = { value: String(amount), blinding: blinding.toString(), commitment, landed: false, claimed: false };
    wallet.deposits.push(dep); saveWallet();   // before sending: the opening must not be lost
    steps(`deposit note: commitment ${commitment.slice(0, 12)}…`);
    await submitUntil(chain.public_id, W.opShield(id.account, amount, chain.privacy_id, commitment), async () => (await get(`/deposit/${commitment}`)).amount === Number(amount), "shield", steps);
    dep.landed = true; saveWallet();
    await transfer("claim", [{ ...dep, kind: "deposit", leaf: null }, null], [self(amount), self(0)], {}, steps);
  },
  async send(amount, steps, to) {
    to = recipient(to);
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
  $("notes-count").textContent = notes.length === 0 ? "shield some to start; only you can open your notes"
    : notes.length === 1 ? "in 1 note only you can open" : `in ${notes.length} notes only you can open`;
  $("notes").replaceChildren(...(notes.length ? notes.map((n) => {
    const li = document.createElement("li");
    li.append(Object.assign(document.createElement("span"), { textContent: `note at leaf ${n.leaf}` }),
              Object.assign(document.createElement("strong"), { textContent: String(n.value) }));
    return li;
  }) : [Object.assign(document.createElement("li"), { textContent: "no private notes yet" })]));
  $("c-slot").textContent = chain.slot ?? "–";
  if (chain.net) $("chain-net").textContent = `JAM tiny · ${chain.net}`;
  $("viewing-key").textContent = W.viewingKey(id);
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
  const to = action === "pay" ? $("to-pay").value : $("to-send").value;
  busy = true;
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
  $("steps").replaceChildren();
  const steps = (s) => { const li = document.createElement("li"); li.append(s); $("steps").append(li); };
  const t0 = Date.now();
  setStatus("working", `working: ${action} · 0 s`);
  const tick = setInterval(() => setStatus("working", `working: ${action} · ${Math.round((Date.now() - t0) / 1000)} s`), 500);
  try {
    await ACTIONS[action](amount, steps, to);
    busy = false; await refresh();
    const whom = (action === "send" || action === "pay") ? " to " + nameOf(recipient(to)) : "";
    setStatus("done", `done: ${action} ${amount}${whom} in ${Math.round((Date.now() - t0) / 100) / 10} s`);
    steps(Object.assign(document.createElement("a"), { href: explorerLink(), textContent: "see what the chain now shows about this address", target: "_blank" }));
  } catch (e) {
    setStatus("error", `error: ${e.message}`);
  } finally {
    clearInterval(tick); busy = false;
    document.querySelectorAll("button").forEach((b) => (b.disabled = false));
  }
}

const nameOf = (account) => (known.find((a) => a.account === account) || {}).name || account.slice(0, 8) + "…";
const explorerLink = (withKey = false) => `explorer.html?address=${id.account}${withKey ? "#vk=" + W.viewingKey(id) : ""}`;

/** The account menu: the dev accounts, then a wallet of this browser's own. */
function accountMenu() {
  const sel = $("who");
  const opts = [...W.DEV_ACCOUNTS.map((n) => [n.toLowerCase(), `${n} · dev account`]),
                ...(DEV < 0 && NAME !== "me" ? [[NAME, `${NAME} · this browser's own`]] : []), ["me", "My wallet · this browser's own"]];
  sel.replaceChildren(...opts.map(([v, t]) => Object.assign(document.createElement("option"), { value: v, textContent: t, selected: v === NAME.toLowerCase() || v === NAME })));
  sel.addEventListener("change", () => { const u = new URL(location.href); u.searchParams.set("user", sel.value); location.href = u.toString(); });
  $("key-kind").textContent = DEV >= 0
    ? `${W.DEV_ACCOUNTS[DEV]} is a JAM dev account: its secret is a public seed, so any browser opens it. Use it to demo, never for value.`
    : "This wallet's secret was made in this browser and never leaves it.";
}

async function start() {
  await W.init();
  wallet = loadWallet(); saveWallet();
  id = await W.identity(W.unhex(wallet.secret));
  known = await Promise.all(W.DEV_ACCOUNTS.map(async (name, i) => ({ name, account: (await W.identity(W.devSecret(i))).account })));
  $("known").replaceChildren(...known.map((a) => Object.assign(document.createElement("option"), { value: a.name, label: a.account })));
  accountMenu();
  circuit = await (await fetch("./circuit/transfer.json")).json();
  await refreshChain();
  // publish how to pay this wallet, once (and again if the chain is new)
  const entry = W.directoryEntry(id);
  if ((await get(`/key/${id.account}`)).key !== entry) {
    setStatus("working", "publishing your address…");
    await submitUntil(chain.public_id, W.opKey(id.account, entry),
      async () => (await get(`/key/${id.account}`)).key === entry, "address", () => {});
  }
  $("key-status").textContent = "keys stay in this browser; your address is published";
  setStatus("idle", "idle");
  await render();
  document.querySelectorAll("button[data-action]").forEach((b) => b.addEventListener("click", () => act(b.dataset.action)));
  $("btn-copy").addEventListener("click", () => navigator.clipboard?.writeText(id.account));
  $("btn-copy-vk").addEventListener("click", () => navigator.clipboard?.writeText(W.viewingKey(id)));
  $("link-explorer").href = explorerLink();
  $("link-explorer-vk").href = explorerLink(true);
  setInterval(refresh, 4000);
  document.title = `JAM Rebel Wallet · ${DEV >= 0 ? W.DEV_ACCOUNTS[DEV] : NAME}`;
  document.body.dataset.ready = "1";
}

start().catch((e) => setStatus("error", "error: " + e.message));
