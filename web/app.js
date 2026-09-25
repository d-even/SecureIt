// Every function here calls a real endpoint on the Phase 5 API (same
// origin, since FastAPI serves this file itself). Nothing in this file
// is sample/mock data — every list, every result comes from a live
// fetch() response.

const API = ""; // same-origin

// ---------- small helpers ----------

function $(id) { return document.getElementById(id); }

function showResult(el, ok, data) {
  el.className = "result " + (ok ? "ok" : "err");
  el.innerHTML = "<pre>" + JSON.stringify(data, null, 2) + "</pre>";
}

async function api(path, options) {
  const res = await fetch(API + path, options);
  let body;
  try { body = await res.json(); } catch { body = null; }
  if (!res.ok) {
    const err = new Error((body && body.detail) || res.statusText);
    err.body = body;
    err.status = res.status;
    throw err;
  }
  return body;
}

// ---------- tabs ----------

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $("tab-" + btn.dataset.tab).classList.add("active");
  });
});

// ---------- data loading (shared across tabs) ----------

async function loadRecipients() {
  const data = await api("/recipients");
  const ids = data.recipients;

  // sender tab: checkboxes
  const checksEl = $("sender-recipient-checks");
  checksEl.innerHTML = "";
  if (ids.length === 0) {
    checksEl.innerHTML = '<span class="muted">No recipients yet — add one on the right.</span>';
  }
  ids.forEach((id) => {
    const label = document.createElement("label");
    label.innerHTML = `<input type="checkbox" value="${id}"> ${id}`;
    checksEl.appendChild(label);
  });

  // recipient tab: dropdown
  const selectEl = $("recipient-id-select");
  selectEl.innerHTML = "";
  ids.forEach((id) => {
    const opt = document.createElement("option");
    opt.value = id;
    opt.textContent = id;
    selectEl.appendChild(opt);
  });
}

async function loadDocuments() {
  const data = await api("/documents");
  const docs = data.documents;

  // sender tab: table
  const tbody = document.querySelector("#documents-table tbody");
  tbody.innerHTML = "";
  docs.forEach((d) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${d.document_id}</td><td>${d.recipients.join(", ")}</td>`;
    tbody.appendChild(tr);
  });

  // recipient tab: dropdown
  const selectEl = $("recipient-doc-select");
  selectEl.innerHTML = "";
  docs.forEach((d) => {
    const opt = document.createElement("option");
    opt.value = d.document_id;
    opt.textContent = `${d.document_id.slice(0, 12)}...  (${d.recipients.join(", ")})`;
    selectEl.appendChild(opt);
  });
}

async function refreshAll() {
  await Promise.all([loadRecipients(), loadDocuments()]);
}

// ---------- Sender tab ----------

$("add-recipient-btn").addEventListener("click", async () => {
  const id = $("new-recipient-id").value.trim();
  const resultEl = $("add-recipient-result");
  if (!id) { showResult(resultEl, false, { error: "enter a recipient id" }); return; }
  try {
    const data = await api(`/recipients/${encodeURIComponent(id)}`, { method: "POST" });
    showResult(resultEl, true, data);
    $("new-recipient-id").value = "";
    await loadRecipients();
  } catch (e) {
    showResult(resultEl, false, e.body || { error: e.message });
  }
});

$("sender-distribute-btn").addEventListener("click", async () => {
  const resultEl = $("sender-result");
  const fileInput = $("sender-file");
  const checked = Array.from(document.querySelectorAll("#sender-recipient-checks input:checked")).map((c) => c.value);

  if (!fileInput.files.length) { showResult(resultEl, false, { error: "choose a file" }); return; }
  if (checked.length === 0) { showResult(resultEl, false, { error: "pick at least one recipient" }); return; }

  const form = new FormData();
  form.append("file", fileInput.files[0]);
  checked.forEach((id) => form.append("recipient_ids", id));

  try {
    const data = await api("/documents", { method: "POST", body: form });
    showResult(resultEl, true, data);
    await loadDocuments();
  } catch (e) {
    showResult(resultEl, false, e.body || { error: e.message });
  }
});

$("refresh-documents-btn").addEventListener("click", loadDocuments);

// ---------- Recipient tab ----------

$("decrypt-btn").addEventListener("click", refreshAll);

$("decrypt-submit-btn").addEventListener("click", async () => {
  const resultEl = $("decrypt-result");
  const docId = $("recipient-doc-select").value;
  const recipientId = $("recipient-id-select").value;
  if (!docId || !recipientId) { showResult(resultEl, false, { error: "no document/recipient selected — click Refresh lists" }); return; }

  try {
    const data = await api(
      `/documents/${docId}/decrypt?recipient_id=${encodeURIComponent(recipientId)}`,
      { method: "POST" }
    );
    data.download = `${location.origin}${data.download_url}`;
    showResult(resultEl, true, data);
  } catch (e) {
    showResult(resultEl, false, e.body || { error: e.message });
  }
});

// ---------- Trace tab ----------

$("trace-btn").addEventListener("click", async () => {
  const resultEl = $("trace-result");
  const fileInput = $("trace-file");
  if (!fileInput.files.length) { showResult(resultEl, false, { error: "choose the leaked file" }); return; }

  const form = new FormData();
  form.append("leaked_file", fileInput.files[0]);

  try {
    const data = await api("/trace", { method: "POST", body: form });
    showResult(resultEl, data.attributable === true, data);
  } catch (e) {
    showResult(resultEl, false, e.body || { error: e.message });
  }
});

$("verify-chain-btn").addEventListener("click", async () => {
  const resultEl = $("verify-result");
  try {
    const data = await api("/ledger/verify");
    showResult(resultEl, data.valid === true, data);
  } catch (e) {
    showResult(resultEl, false, e.body || { error: e.message });
  }
});

// ---------- boot ----------

refreshAll();