// The explorer: what the chain records, read through the indexer's public JIP-2 view, and what a
// key can read inside it. It holds no secrets of its own: a dev account's keys are public seeds,
// a wallet of this browser's own is read from this origin's localStorage, and a pasted viewing
// key stays in this tab (it travels in the URL's #fragment, which no server sees).
//   explorer.html?address=<hex or dev name>#vk=<viewing key>      ?indexer=<url> (http://localhost:19700)
import * as W from "./lib/core.js";

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const INDEXER = (params.get("indexer") || "http://localhost:19700").replace(/\/$/, "");
const KINDS = { mint: "Faucet mint", burn: "Burn", shield: "Shield", key: "Address published", transfer: "Public payment", received: "Unshield payout" };

let hist = null, known = [], address = null, reader = null, sight = null, balance = null;

const get = async (path) => { const r = await fetch(INDEXER + path, { cache: "no-store" }); const j = await r.json(); if (!r.ok) throw new Error(j.error || `${path}: ${r.status}`); return j; };
const el = (tag, cls, ...kids) => { const e = document.createElement(tag); if (cls) e.className = cls; e.append(...kids.filter((k) => k !== null && k !== undefined)); return e; };
const nameOf = (acct) => (known.find((a) => a.account === acct) || {}).name;
function who(acct) {                                   // an address, named when it is a dev account's
  const n = nameOf(acct);
  const a = el("a", "who-link", n || acct.slice(0, 10) + "…");
  a.href = `?address=${acct}${location.hash}`; a.title = acct;
  a.addEventListener("click", (ev) => { ev.preventDefault(); show(acct); });
  return a;
}
const hexEl = (h, label) => { const c = el("code", "hex", (label ? label + " " : "") + "0x" + h.slice(0, 10) + "…" + h.slice(-6)); c.title = "0x" + h + " (click to copy)"; c.addEventListener("click", () => navigator.clipboard?.writeText(h)); return c; };
const amt = (n) => el("b", "amt", String(n));
const line = (...kids) => el("div", "line", ...kids);

// ---- reading with a key ---------------------------------------------------------------------
/** What `reader` can read: the notes it opens (by leaf), and with the spend key, its spends. */
async function look() {
  if (!reader || !hist) return null;
  const leaves = hist.transfers.flatMap((t) => t.commitments), sealed = hist.transfers.flatMap((t) => t.sealed);
  const found = await W.scan(reader.id, { leaves, sealed });
  const opens = new Map(found.map((n) => [n.leaf, n]));
  const spends = new Map();
  if (reader.id.sk !== undefined) for (const n of found) spends.set(W.hex32(W.nullifier(n.hash, reader.id.sk)), n);
  return { opens, spends, full: reader.id.sk !== undefined };
}

async function chooseKey(value) {
  reader = null;
  $("vk-row").hidden = value !== "vk";
  if (value.startsWith("dev:")) {
    const i = Number(value.slice(4));
    reader = { name: W.DEV_ACCOUNTS[i], by: `${W.DEV_ACCOUNTS[i]}'s keys`, id: await W.identity(W.devSecret(i)), note: `${W.DEV_ACCOUNTS[i]}'s full keys: their seed is public, so this page derives them. It reads ${W.DEV_ACCOUNTS[i]}'s notes and sees which ones were spent.` };
  } else if (value.startsWith("local:")) {
    const w = JSON.parse(localStorage.getItem(value.slice(6)));
    const name = value.slice(6 + "jam-privacy-wallet:".length);
    reader = { name, by: `${name}'s keys`, id: await W.identity(W.unhex(w.secret)), note: "A wallet of this browser's own: its secret is in this browser's storage, so this page reads its notes and its spends." };
  } else if (value === "vk") {
    const vk = $("vk").value.trim();
    if (vk) {
      reader = { name: "this viewing key", by: "this viewing key", id: await W.viewer(vk), note: "A viewing key opens the notes sealed to it and proves each one is its owner's leaf. It cannot spend them, and it cannot tell which were spent: a nullifier needs the spend key." };
      history.replaceState(null, "", `${location.pathname}${location.search}#vk=${vk}`);
    }
  }
  if (value !== "vk" && location.hash) history.replaceState(null, "", location.pathname + location.search);
  $("key-note").textContent = reader ? reader.note : "No key: only what the chain shows to everyone.";
  sight = await look();
  render();
}

// ---- the feed --------------------------------------------------------------------------------
function links() {
  const shieldOf = new Map(), claimOf = new Map(), payout = new Map();
  for (const e of hist.events) {
    if (e.kind === "shield") shieldOf.set(e.commitment, e);
    if (e.kind === "received" && e.from_service === hist.privacy_id) payout.set(e.slot, [...(payout.get(e.slot) || []), e]);
  }
  for (const t of hist.transfers) for (const nf of t.nullifiers) if (shieldOf.has(nf)) claimOf.set(nf, t);
  return { shieldOf, claimOf, payout };
}

function publicCard(e, L) {
  const body = [];
  if (e.kind === "mint") body.push(line("The faucet minted ", amt(e.amount), " to ", who(e.account), "."));
  if (e.kind === "burn") body.push(line(who(e.account), " burned ", amt(e.amount), "."));
  if (e.kind === "transfer") body.push(line(who(e.account), " paid ", who(e.to), " ", amt(e.amount), "."));
  if (e.kind === "key") body.push(line(who(e.account), " published how to pay it privately: an encryption key and a spend key."));
  if (e.kind === "received") body.push(line("The privacy service paid ", who(e.account), " ", amt(e.amount), ": an unshield. Which notes paid for it is not on chain."));
  if (e.kind === "shield") {
    const t = L.claimOf.get(e.commitment);
    body.push(line(who(e.account), " shielded ", amt(e.amount), ". The amount is public; the note it became is not."));
    body.push(line("Note commitment ", hexEl(e.commitment), t ? ` · claimed by private transfer #${t.index}` : " · not yet claimed"));
  }
  return card(e.slot, "public", KINDS[e.kind] || e.kind, body, "Public: every field above is on chain.");
}

function privateCard(t, L) {
  const body = [];
  const inputs = el("div", "io", el("div", "io-h", "Spent: two nullifiers"));
  t.nullifiers.forEach((nf, j) => {
    const dep = L.shieldOf.get(nf), mine = sight && sight.spends.get(nf);
    inputs.append(el("div", "io-row", hexEl(nf),
      dep ? el("span", "link", " = the note commitment ", who(dep.account), " shielded (", amt(dep.amount), ")") : null,
      mine ? el("span", "reveal", ` spends ${reader.name}'s note at leaf ${mine.leaf}: ${mine.value}`) : null,
      !dep && !mine && j === 1 ? el("span", "muted", " (a second input, or a dummy: nobody can tell which)") : null));
  });
  const outputs = el("div", "io", el("div", "io-h", "Created: two notes"));
  t.commitments.forEach((c, j) => {
    const leaf = t.leaves[j], mine = sight && sight.opens.get(leaf);
    outputs.append(el("div", "io-row", el("span", "muted", `leaf ${leaf} `), hexEl(c, "commitment"), " ", hexEl(t.sealed[j], "sealed"),
      mine ? el("span", "reveal", ` opens to ${reader.name}: ${mine.value}${mine.value === 0n ? " (a zero-value note)" : ""}`) : null));
  });
  body.push(inputs, outputs);
  const paid = t.slot !== null ? L.payout.get(t.slot) || [] : [];
  for (const e of paid) body.push(line("In the same block the privacy service paid ", who(e.account), " ", amt(e.amount), " publicly: this transfer unshields."));
  const hidden = sight && (t.nullifiers.some((nf) => sight.spends.has(nf)) || t.leaves.some((l) => sight.opens.has(l)))
    ? `With ${reader.by}: the highlighted values. The chain alone shows none of them.`
    : "Hidden: who sent it, who received it and how much. The proof showed the rules were kept; it did not show these.";
  return card(t.slot, "private", `Private transfer #${t.index}`, body, hidden);
}

function card(slot, kind, title, body, foot) {
  return el("li", `item ${kind}`,
    el("div", "item-h", el("span", `badge ${kind}`, kind === "private" ? "private" : "public"), el("span", "item-title", title),
      el("span", "item-slot", slot === null ? "slot before the indexer" : `slot ${slot}`)),
    ...body, el("div", `foot ${kind}`, foot));
}

function involves(t, L, addr) {                     // a private transfer the chain itself ties to addr
  return t.nullifiers.some((nf) => L.shieldOf.get(nf)?.account === addr)
    || (t.slot !== null && (L.payout.get(t.slot) || []).some((e) => e.account === addr));
}
const keyTouches = (t) => sight && (t.nullifiers.some((nf) => sight.spends.has(nf)) || t.leaves.some((l) => sight.opens.has(l)));

function render() {
  if (!hist) return;
  const L = links();
  let events = hist.events, txs = hist.transfers;
  const tied = txs.filter((t) => address && involves(t, L, address));
  if (address) {
    events = events.filter((e) => e.account === address || e.to === address);
    txs = txs.filter((t) => involves(t, L, address) || keyTouches(t));
  }
  const items = [...events.map((e) => ({ slot: e.slot, tie: 1, n: e.n, node: publicCard(e, L) })),
                 ...txs.map((t) => ({ slot: t.slot ?? -1, tie: 0, n: t.index, node: privateCard(t, L) }))];
  items.sort((a, b) => b.slot - a.slot || a.tie - b.tie || b.n - a.n);
  $("feed").replaceChildren(...(items.length ? items.map((i) => i.node) : [el("li", "empty", "Nothing yet.")]));
  $("feed-title").textContent = address ? `Activity of ${nameOf(address) || address.slice(0, 12) + "…"}` : "All activity";
  const nPriv = hist.transfers.length;
  $("feed-note").textContent = address
    ? `${nPriv} private transfer${nPriv === 1 ? "" : "s"} on chain. ${tied.length} ${tied.length === 1 ? "is" : "are"} tied to this address by a public shield or unshield; the chain ties no address to the rest.`
      + (sight ? ` With ${reader.by}, ${txs.length - tied.length} more show up here.` : "")
    : `${hist.events.length} public event${hist.events.length === 1 ? "" : "s"}, ${nPriv} private transfer${nPriv === 1 ? "" : "s"}.`;
  summary();
}

function summary() {
  const s = $("summary");
  if (!address && !sight) { s.hidden = true; return; }
  const rows = [];
  if (address) {
    rows.push(el("div", "sum-h", nameOf(address) ? `${nameOf(address)} · a JAM dev account` : "Address"), el("code", "hex full", address));
    rows.push(el("div", "sum-grid",
      el("div", "stat", el("div", "label", "Public balance"), el("div", "big", balance === null ? "…" : String(balance)), el("div", "sub", "anyone can read it")),
      el("div", "stat priv", el("div", "label", "Private balance"),
        el("div", "big", sight ? String(privateTotal()) : "hidden"),
        el("div", "sub", sight ? (sight.full ? `read with ${reader.by}` : "received, read with a viewing key: spends need the spend key") : "the chain does not record it"))));
  } else if (sight) {
    rows.push(el("div", "sum-h", `Read with ${reader.by}`),
      el("div", "sum-grid", el("div", "stat priv", el("div", "label", sight.full ? "Unspent" : "Received"), el("div", "big", String(privateTotal())), el("div", "sub", `${sight.opens.size} note${sight.opens.size === 1 ? "" : "s"} open to this key`))));
  }
  s.replaceChildren(...rows); s.hidden = false;
}
function privateTotal() {
  const spentLeaves = new Set([...sight.spends].filter(([nf]) => hist.transfers.some((t) => t.nullifiers.includes(nf))).map(([, n]) => n.leaf));
  return [...sight.opens.values()].filter((n) => !sight.full || !spentLeaves.has(n.leaf)).reduce((s, n) => s + n.value, 0n);
}

// ---- the page ----------------------------------------------------------------------------------
async function show(q) {
  const v = (q || "").trim().toLowerCase();
  const k = known.find((a) => a.name.toLowerCase() === v);
  address = k ? k.account : /^[0-9a-f]{64}$/.test(v) ? v : null;
  if (v && !address) { $("status").textContent = "An address is 64 hex characters, or a dev account's name."; return; }
  $("status").textContent = "";
  $("q").value = address ? (nameOf(address) || address) : "";
  history.replaceState(null, "", `${location.pathname}${address ? "?address=" + address : ""}${location.hash}`);
  balance = null; render();
  if (address) { balance = (await get(`/balance/${address}`)).balance; render(); }
}

async function load() {
  try {
    const before = hist && hist.events.length + ":" + hist.transfers.length + ":" + hist.transfers.map((t) => t.slot).join();
    hist = await get("/history");
    $("net").textContent = `JAM tiny · ${hist.net}`; $("slot").textContent = `slot ${hist.slot}`;
    if (before !== hist.events.length + ":" + hist.transfers.length + ":" + hist.transfers.map((t) => t.slot).join()) {
      sight = await look();
      if (address) balance = (await get(`/balance/${address}`)).balance;
      render();
    }
    $("status").textContent = "";
  } catch (e) { $("status").textContent = "indexer: " + e.message; }
}

async function start() {
  await W.init();
  known = await Promise.all(W.DEV_ACCOUNTS.map(async (name, i) => ({ name, account: (await W.identity(W.devSecret(i))).account })));
  $("known").replaceChildren(...known.map((a) => Object.assign(document.createElement("option"), { value: a.name, label: a.account })));
  const sel = $("key");
  const local = Object.keys(localStorage).filter((k) => k.startsWith("jam-privacy-wallet:")).filter((k) => W.devIndex(k.slice(19)) < 0);
  sel.append(...W.DEV_ACCOUNTS.map((n, i) => Object.assign(document.createElement("option"), { value: `dev:${i}`, textContent: `${n}'s keys (a dev account)` })),
    ...local.map((k) => Object.assign(document.createElement("option"), { value: `local:${k}`, textContent: `${k.slice(19)}: a wallet in this browser` })),
    Object.assign(document.createElement("option"), { value: "vk", textContent: "A viewing key…" }));
  sel.addEventListener("change", () => chooseKey(sel.value));
  $("btn-vk").addEventListener("click", () => chooseKey("vk").catch((e) => { $("key-note").textContent = e.message; }));
  $("btn-q").addEventListener("click", () => show($("q").value));
  $("q").addEventListener("keydown", (e) => { if (e.key === "Enter") show($("q").value); });
  $("btn-all").addEventListener("click", () => show(""));
  await load();
  const vk = location.hash.match(/vk=([0-9a-fA-F]{128})/);
  if (vk) { sel.value = "vk"; $("vk").value = vk[1]; await chooseKey("vk").catch((e) => { $("key-note").textContent = e.message; }); }
  else await chooseKey("");
  await show(params.get("address") || "");
  setInterval(load, 6000);
  document.body.dataset.ready = "1";
}
start().catch((e) => { $("status").textContent = "error: " + e.message; });
