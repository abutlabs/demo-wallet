// The JAM privacy wallet page. Talks to client/wallet.py in jam-privacy-service: GET
// /api/state?user=, POST /api/{mint,shield,send,unshield}. No build step, no dependencies.
"use strict";
const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
let user = params.get("user") || "A";
let busy = false;

function setStatus(kind, text) {
  const s = $("status");
  s.className = "status " + kind;
  s.textContent = text;
}

function render(st) {
  $("public").textContent = st.public;
  $("private").textContent = st.private;
  $("notes-count").textContent = st.notes.length === 1 ? "in 1 note only you can open"
    : `in ${st.notes.length} notes only you can open`;
  const ul = $("notes");
  ul.replaceChildren(...(st.notes.length ? st.notes.map((n) => {
    const li = document.createElement("li");
    const a = document.createElement("span");
    a.textContent = n.kind === "deposit" ? `deposit ${n.id} (unclaimed)` : `note ${n.id} · leaf ${n.leaf}`;
    const b = document.createElement("strong");
    b.textContent = n.value;
    li.append(a, b);
    return li;
  }) : [Object.assign(document.createElement("li"), { textContent: "no private notes yet" })]));
  const c = st.chain || {};
  $("c-slot").textContent = c.slot ?? "–";
  if (c.net) $("chain-net").textContent = `JAM tiny · ${c.net}`;
  $("c-root").textContent = c.note_root ? "0x" + c.note_root : "(empty tree)";
  $("c-leaves").textContent = c.leaf_count ?? "–";
  $("c-transfers").textContent = c.transfers ?? "–";
  $("c-flow").textContent = `${c.shielded ?? "–"} / ${c.unshielded ?? "–"}`;
  $("c-services").textContent = `privacy ${c.privacy_id ?? "–"}, public-balance ${c.public_id ?? "–"}`;
  for (const o of $("to-send").options) o.disabled = o.value === user;
  if ($("to-send").value === user) $("to-send").value = [...$("to-send").options].find((o) => !o.disabled).value;
}

async function refresh() {
  if (busy) return;
  try {
    const r = await fetch(`/api/state?user=${encodeURIComponent(user)}`, { cache: "no-store" });
    const st = await r.json();
    if (!r.ok) throw new Error(st.error || r.statusText);
    render(st);
  } catch (e) {
    setStatus("error", "error: " + e.message);
  }
}

async function act(action) {
  const body = { user };
  if (action === "mint") body.amount = 100;
  if (action === "shield") body.amount = Number($("amt-shield").value);
  if (action === "send") { body.amount = Number($("amt-send").value); body.to = $("to-send").value; }
  if (action === "unshield") body.amount = Number($("amt-unshield").value);
  busy = true;
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
  $("steps").replaceChildren();
  const t0 = Date.now();
  setStatus("working", `working: ${action} · 0 s`);
  const tick = setInterval(() => setStatus("working", `working: ${action} · ${Math.round((Date.now() - t0) / 1000)} s`), 500);
  try {
    const r = await fetch(`/api/${action}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const out = await r.json();
    (out.steps || []).forEach((s) => $("steps").append(Object.assign(document.createElement("li"), { textContent: s })));
    if (!r.ok || !out.ok) throw new Error(out.error || r.statusText);
    render(out);
    setStatus("done", `done: ${action} ${body.amount}${body.to ? " to " + body.to : ""} in ${out.seconds} s`);
  } catch (e) {
    setStatus("error", `error: ${e.message}`);
  } finally {
    clearInterval(tick);
    busy = false;
    document.querySelectorAll("button").forEach((b) => (b.disabled = false));
  }
}

$("user").value = user;
$("user").addEventListener("change", (e) => {
  user = e.target.value;
  params.set("user", user);
  history.replaceState(null, "", "?" + params);
  setStatus("idle", "idle");
  $("steps").replaceChildren();
  refresh();
});
document.querySelectorAll("button[data-action]").forEach((b) => b.addEventListener("click", () => act(b.dataset.action)));
refresh();
setInterval(refresh, 3000);
