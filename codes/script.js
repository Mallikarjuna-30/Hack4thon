
const $ = id => document.getElementById(id);

function nowISO() {
  return new Date().toISOString();
}

function formatShort(ts) {
  const d = new Date(ts);
  return d.toLocaleString();
}

function saveHistory(history) {
  try { localStorage.setItem("phish_history_v1", JSON.stringify(history)); } catch {}
}
function loadHistory() {
  try {
    const raw = localStorage.getItem("phish_history_v1");
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}


function checkPhishing(inputUrl) {
  const reasons = [];
  if (!inputUrl || typeof inputUrl !== "string") {
    reasons.push("No URL provided");
    return { isPhishing: true, reasons };
  }

  let url = inputUrl.trim();

  // Add scheme if missing
  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    reasons.push("Invalid URL format");
    return { isPhishing: true, reasons };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullLower = url.toLowerCase();

  // 1. Suspicious keywords (domain + path)
  const suspiciousWords = ["free", "win", "bonus", "money", "gift", "offer", "prize", "urgent"];
  suspiciousWords.forEach(w => {
    if (fullLower.includes(w)) {
      reasons.push(`Suspicious keyword found: "${w}"`);
    }
  });

  // 2. Very long URL
  if (url.length > 90) {
    reasons.push("URL is unusually long");
  }

  
  if (fullLower.includes("@")) {
    reasons.push("Contains '@' symbol — may mask real domain");
  }

  // 4. No HTTPS
  if (parsed.protocol !== "https:") {
    reasons.push("Connection is not secure (HTTPS missing)");
  }

  // 5. IP address host
  const ipHostPattern = /^\d{1,3}(\.\d{1,3}){3}$/;
  if (ipHostPattern.test(hostname)) {
    reasons.push("Uses an IP address instead of a domain");
  }

  // 6. Too many subdomains (evaluate hostname parts, allow country-code like co.uk)
  const hp = hostname.split(".");
  if (hp.length >= 5) {
    reasons.push("Many subdomains — suspicious structure");
  }

  // 7. Risky TLDs
  const riskyTLDs = [".xyz", ".click", ".gift", ".top", ".loan", ".work", ".pw", ".club"];
  riskyTLDs.forEach(tld => {
    if (hostname.endsWith(tld)) reasons.push(`Risky top-level domain detected (${tld})`);
  });

  // 8. Mixed letters & numbers in domain (some legit sites have it — keep as suspicion, not definitive)
  if (/[a-zA-Z]+\d+[a-zA-Z]+/.test(hostname)) {
    reasons.push("Unusual letter-number patterns in domain");
  }

  // 9. Encoded URL sequences (%XX)
  if (/%[0-9A-F]{2}/i.test(url)) {
    reasons.push("URL contains encoded characters");
  }

  // 10. Repeated characters
  if (/(.)\1\1/.test(hostname)) {
    reasons.push("Domain contains repeated characters (spam-like)");
  }

  // 11. Suspicious path with many query params
  if ((parsed.search && parsed.search.length > 40) || (parsed.searchParams && Array.from(parsed.searchParams).length > 6)) {
    reasons.push("Many/long query parameters — could be tracking or obfuscation");
  }

  return {
    isPhishing: reasons.length > 0,
    reasons
  };
}

// -------------------- UI FLOW --------------------
const urlInput = $("urlInput");
const analyzeBtn = $("analyzeBtn");
const resultDiv = $("result");
const historyList = $("historyList");
const copyBtn = $("copyBtn");
const clearBtn = $("clearBtn");
const toggleMode = $("toggleMode");

let history = loadHistory();
renderHistory();

// Debounce helper for live-check
function debounce(fn, ms=300){
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(()=>fn(...args), ms); };
}

// Display analysis result
function showResult(input, analysis) {
  const safeHtml = `<div class="safe">✔️ This URL appears safe</div>`;
  const dangerHtml = `
    <div class="danger">⚠️ Potential Phishing Detected</div>
    <ul>${analysis.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
  `;
  if (analysis.isPhishing) {
    resultDiv.innerHTML = dangerHtml;
  } else {
    resultDiv.innerHTML = safeHtml;
  }
}

// Escape helper (very small)
function escapeHtml(str){
  return String(str).replace(/[&<>"']/g, s => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  })[s]);
}

// Run analysis and record
function analyzeAndRecord(rawUrl, options={record:true}) {
  if (!rawUrl || !rawUrl.trim()) {
    resultDiv.innerHTML = `<div class="danger">⚠️ Please enter a URL.</div>`;
    return;
  }
  const result = checkPhishing(rawUrl);
  showResult(rawUrl, result);
  if (options.record) {
    const item = {
      id: Date.now(),
      url: rawUrl,
      ts: nowISO(),
      result: result,
    };
    history.unshift(item);
    // keep last 25 items
    history = history.slice(0,25);
    saveHistory(history);
    renderHistory();
  }
}

// Render history list
function renderHistory() {
  historyList.innerHTML = "";
  if (!history.length) {
    historyList.innerHTML = `<li class="history-item" aria-hidden="true" style="opacity:0.6">No history yet — analyze a URL to store it here.</li>`;
    return;
  }
  for (const it of history) {
    const li = document.createElement("li");
    li.className = "history-item";
    const meta = document.createElement("div");
    meta.className = "meta";
    const short = document.createElement("div");
    short.className = "short-url";
    short.textContent = it.url.length > 60 ? it.url.slice(0,58) + "…" : it.url;
    const time = document.createElement("time");
    time.textContent = formatShort(it.ts);
    meta.appendChild(short);
    meta.appendChild(time);

    const side = document.createElement("div");
    side.className = "meta-actions";

    const badge = document.createElement("span");
    badge.textContent = it.result.isPhishing ? "⚠️" : "✔️";
    badge.title = it.result.isPhishing ? "Potential phishing" : "Looks safe";
    badge.style.marginRight = "8px";

    const btnRecheck = document.createElement("button");
    btnRecheck.className = "small-btn";
    btnRecheck.textContent = "Recheck";
    btnRecheck.addEventListener("click", () => analyzeAndRecord(it.url, {record:false}));

    const btnCopy = document.createElement("button");
    btnCopy.className = "small-btn";
    btnCopy.textContent = "Copy";
    btnCopy.addEventListener("click", () => {
      try { navigator.clipboard.writeText(it.url); } catch {}
    });

    side.appendChild(badge);
    side.appendChild(btnRecheck);
    side.appendChild(btnCopy);

    li.appendChild(meta);
    li.appendChild(side);
    historyList.appendChild(li);
  }
}

// Copy latest result (text)
copyBtn.addEventListener("click", () => {
  if (!history.length) return;
  const latest = history[0];
  const text = `${latest.url} — ${latest.result.isPhishing ? "Potential phishing: " + latest.result.reasons.join("; ") : "Looks safe"}`;
  try {
    navigator.clipboard.writeText(text);
    copyBtn.textContent = "Copied!";
    setTimeout(()=> copyBtn.textContent = "Copy Result", 1200);
  } catch {
    copyBtn.textContent = "Failed";
    setTimeout(()=> copyBtn.textContent = "Copy Result", 1200);
  }
});

// Clear history
clearBtn.addEventListener("click", () => {
  if (!confirm("Clear analysis history? This cannot be undone.")) return;
  history = [];
  saveHistory(history);
  renderHistory();
});

// Analyze button + Enter key
analyzeBtn.addEventListener("click", () => analyzeAndRecord(urlInput.value));
urlInput.addEventListener("keyup", (e) => {
  if (e.key === "Enter") { analyzeAndRecord(urlInput.value); }
});

// Live check while typing (debounced) — does not record into history
const liveCheck = debounce((val) => {
  if (!val || !val.trim()) { resultDiv.innerHTML = ""; return; }
  const r = checkPhishing(val);
  showResult(val, r);
}, 300);

urlInput.addEventListener("input", (e) => liveCheck(e.target.value));

// Toggle light mode
if (toggleMode) {
  toggleMode.addEventListener("click", () => {
    document.body.classList.toggle("light");
    const on = document.body.classList.contains("light");
    toggleMode.textContent = on ? "🌙" : "☀️";
    toggleMode.setAttribute("aria-pressed", !!on);
  });
}

// initialize last saved history result in result area
if (history.length) {
  const last = history[0];
  // show last result but don't record
  showResult(last.url, last.result);
}
