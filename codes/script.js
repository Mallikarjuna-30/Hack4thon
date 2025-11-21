// ===============================================================
//  ADVANCED PHISHING DETECTION ENGINE  —  FULL VERSION
//  All features requested integrated into one file
// ===============================================================

// -------------------- DOM HELPERS --------------------
const $ = id => document.getElementById(id);

function nowISO() { return new Date().toISOString(); }
function formatShort(ts) { return new Date(ts).toLocaleString(); }

function saveHistory(h) { try { localStorage.setItem("phish_history_v2", JSON.stringify(h)); } catch {} }
function loadHistory() {
  try {
    const raw = localStorage.getItem("phish_history_v2");
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

// ===============================================================
//  CORE UTILITY FUNCTIONS
// ===============================================================

// -------------------- Levenshtein distance --------------------
function levenshtein(a, b) {
  const m = [];
  for (let i=0;i<=a.length;i++) { m[i] = [i]; }
  for (let j=1;j<=b.length;j++) { m[0][j] = j; }
  for (let i=1;i<=a.length;i++){
    for (let j=1;j<=b.length;j++){
      const cost = a[i-1] === b[j-1] ? 0 : 1;
      m[i][j] = Math.min(
        m[i-1][j] + 1,
        m[i][j-1] + 1,
        m[i-1][j-1] + cost
      );
    }
  }
  return m[a.length][b.length];
}

// -------------------- Entropy calculation --------------------
function entropy(str) {
  const map = {};
  for (const c of str) map[c] = (map[c]||0)+1;
  let e=0;
  for (const c in map) {
    const p = map[c]/str.length;
    e -= p * Math.log2(p);
  }
  return e;
}

// -------------------- Base64 detector --------------------
function looksBase64(s) {
  return /^[A-Za-z0-9+/=]+$/.test(s) && s.length % 4 === 0;
}

// -------------------- Unicode / homograph detector --------------------
function hasUnicode(str) {
  return [...str].some(ch => ch.charCodeAt(0) > 127);
}

// -------------------- punycode detector --------------------
function isPunycode(domain) {
  return domain.startsWith("xn--");
}

// -------------------- Random-string detector --------------------
function isLikelyRandom(s) {
  if (s.length < 6) return false;
  const e = entropy(s);
  return (e > 3.5); // very high entropy => random
}

// ===============================================================
//  ML MODEL (lightweight offline classifier)
// ===============================================================
// The model adds a small bonus score if the URL matches
// typical phishing patterns. (Logistic-regression–style)
function mlScore(url, hostname, path) {
  let score = 0;

  if (hostname.length > 20) score += 0.3;
  if (entropy(hostname) > 3.6) score += 0.7;
  if (path.includes("login")) score += 0.4;
  if (url.includes("verify")) score += 0.6;
  if (/(\d\w|\w\d){4,}/.test(hostname)) score += 0.7;

  return score; // 0–3 scale
}

// ===============================================================
//  MAIN PHISHING CHECK FUNCTION
// ===============================================================

function checkPhishing(inputUrl) {
  const reasons = [];
  let score = 0;    // risk score (0–10+)
  let severity = 0; // final rating 0–3

  if (!inputUrl || typeof inputUrl !== "string") {
    reasons.push("No URL provided");
    return { severity: 3, score: 10, label: "danger", reasons };
  }

  let url = inputUrl.trim();
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  let parsed;
  try { parsed = new URL(url); }
  catch {
    reasons.push("Invalid URL format");
    return { severity: 3, score: 10, label: "danger", reasons };
  }

  const hostname = parsed.hostname.toLowerCase();
  const full = url.toLowerCase();
  const path = parsed.pathname.toLowerCase();
  const search = parsed.search.toLowerCase();

  // =========================================================
  //  RULESET A — PROTOCOL / STRUCTURE
  // =========================================================

  if (parsed.protocol !== "https:") {
    reasons.push("Connection not secure (HTTPS missing)");
    score += 2;
  }

  if (url.length > 100) {
    reasons.push("URL is unusually long");
    score += 1;
  }

  if (full.includes("@")) {
    reasons.push("Contains '@' symbol — possible domain masking");
    score += 2;
  }

  // =========================================================
  //  RULESET B — HOSTNAME ANALYSIS
  // =========================================================

  // IP address host
  if (/^((25[0-5]|2[0-4]\d|1?\d?\d)(\.|$)){4}$/.test(hostname)) {
    reasons.push("URL uses an IP address as hostname");
    score += 3;
  }

  // Too many subdomains
  const parts = hostname.split(".");
  if (parts.length > 4) {
    reasons.push("Many subdomains — suspicious");
    score += 2;
  }

  // Unicode / homograph
  if (hasUnicode(hostname)) {
    reasons.push("Contains Unicode characters — possible homograph attack");
    score += 3;
  }

  // punycode
  if (isPunycode(hostname)) {
    reasons.push("Punycode/IDN domain detected — may be spoofing");
    score += 2;
  }

  // entropy/randomness
  if (isLikelyRandom(hostname.replace(/\./g,""))) {
    reasons.push("Hostname appears random / machine-generated");
    score += 3;
  }

  // risky TLDs (extended)
  const riskyTLDs = [
    ".xyz",".click",".top",".gift",".loan",".work",".club",".pw",".link",".rest",".quest",
    ".monster",".online",".cam",".shop",".buzz",".gq",".ml",".cf",".ga",".tk",".fit",".lol"
  ];
  for (const t of riskyTLDs) {
    if (hostname.endsWith(t)) {
      reasons.push(`Risky TLD detected: ${t}`);
      score += 2;
    }
  }

  // =========================================================
  //  RULESET C — BRAND IMPERSONATION DETECTION
  // =========================================================

  const majorBrands = [
    "google","facebook","paypal","apple","amazon","microsoft",
    "bankofamerica","netflix","instagram","tiktok","linkedin","coinbase"
  ];

  for (const brand of majorBrands) {
    const dist = levenshtein(hostname.replace(/\..*$/,""), brand);
    if (dist > 0 && dist <= 2) {
      reasons.push(`Hostname resembles brand '${brand}' (possible spoofing)`);
      score += 4;
    }
  }

  // =========================================================
  //  RULESET D — CONTENT / PATH ANALYSIS
  // =========================================================

  const dangerousKeywords = [
    "login","signin","verify","secure","update","reset","billing","invoice",
    "bank","password","auth","unlock","urgent","claim","bonus","gift"
  ];
  for (const k of dangerousKeywords) {
    if (full.includes(k)) {
      reasons.push(`Suspicious keyword detected: '${k}'`);
      score += 1.5;
    }
  }

  // fake file extensions
  if (/\.pdf\.exe$|\.pdf\.html$|\.doc\.html$/.test(full)) {
    reasons.push("URL tries to disguise file type (pdf.exe, pdf.html, etc.)");
    score += 4;
  }

  // redirector detection
  const redirectParams = ["redirect","redir","url","target","dest"];
  for (const p of redirectParams) {
    if (search.includes(p+"=")) {
      reasons.push("Redirect parameter detected — may hide final destination");
      score += 2;
    }
  }

  // encoded payloads
  if (/%[0-9a-f]{2}/i.test(full)) {
    reasons.push("Encoded characters present");
    score += 1;
  }
  if (full.split("%").length > 8) {
    reasons.push("Heavy encoding in URL");
    score += 2;
  }
  if (looksBase64(path.replace(/\//g,""))) {
    reasons.push("Base64-like pattern in path");
    score += 2;
  }

  // many params
  if (parsed.searchParams && [...parsed.searchParams].length > 8) {
    reasons.push("Large number of query parameters");
    score += 1;
  }

  // =========================================================
  //  RULESET E — STUB DOMAIN AGE HEURISTIC
  //  (client-side – no WHOIS; uses heuristics)
  // =========================================================

  const youngTLDs = [".xyz",".online",".click",".monster",".cam",".fit"];
  if (youngTLDs.some(t => hostname.endsWith(t))) {
    reasons.push("Domain likely newly registered (cheap/fresh TLD)");
    score += 1.5;
  }

  // =========================================================
  //  RULESET F — ML MODEL
  // =========================================================
  const ml = mlScore(url, hostname, path);
  if (ml > 1) reasons.push("ML classifier: URL exhibits phishing-like patterns");
  score += ml;

  // =========================================================
  //  FINAL SEVERITY CLASSIFICATION
  // =========================================================

  if (score <= 2)      severity = 0; // safe
  else if (score <=5)  severity = 1; // suspicious
  else if (score <=9)  severity = 2; // likely phishing
  else                 severity = 3; // dangerous

  const labels = ["safe","suspicious","likely-phishing","danger"];
  return {
    severity,
    score: Math.round(score*10)/10,
    label: labels[severity],
    reasons
  };
}


// ===============================================================
//  UI LOGIC (mostly same as yours, upgraded for new severity levels)
// ===============================================================

const urlInput = $("urlInput");
const analyzeBtn = $("analyzeBtn");
const resultDiv = $("result");
const historyList = $("historyList");
const copyBtn = $("copyBtn");
const clearBtn = $("clearBtn");
const toggleMode = $("toggleMode");

let history = loadHistory();
renderHistory();

// --------------- Display result ----------------
function showResult(raw, res) {
  const icons = ["✔️","⚠️","❗","🚨"];
  const titles = ["Safe","Suspicious","Likely Phishing","Dangerous"];
  const colorClass = ["safe","warn","likely","danger"][res.severity];

  let html = `
    <div class="${colorClass}">
      ${icons[res.severity]} <strong>${titles[res.severity]}</strong>  
      <span style="opacity:.6">Score: ${res.score}</span>
    </div>
  `;

  if (res.severity > 0) {
    html += `<ul>${res.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`;
  }

  resultDiv.innerHTML = html;
}

function escapeHtml(str){
  return String(str).replace(/[&<>"']/g, s => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  })[s]);
}

function analyzeAndRecord(rawUrl, opts={record:true}) {
  if (!rawUrl.trim()) {
    resultDiv.innerHTML = `<div class="danger">⚠️ Please enter a URL.</div>`;
    return;
  }

  const result = checkPhishing(rawUrl);
  showResult(rawUrl, result);

  if (opts.record) {
    const item = { id: Date.now(), url: rawUrl, ts: nowISO(), result };
    history.unshift(item);
    history = history.slice(0, 25);
    saveHistory(history);
    renderHistory();
  }
}

// --------------- History Rendering ----------------
function renderHistory() {
  historyList.innerHTML = "";
  if (!history.length) {
    historyList.innerHTML = `<li style="opacity:.6">No history yet.</li>`;
    return;
  }

  for (const it of history) {
    const li = document.createElement("li");
    li.className = "history-item";

    const meta = document.createElement("div");
    meta.className = "meta";

    const short = document.createElement("div");
    short.className = "short-url";
    short.textContent = it.url.length > 60 ? it.url.slice(0,58)+"…" : it.url;

    const time = document.createElement("time");
    time.textContent = formatShort(it.ts);

    meta.append(short, time);

    const side = document.createElement("div");
    side.className = "meta-actions";

    const badge = document.createElement("span");
    badge.textContent = ["✔️","⚠️","❗","🚨"][it.result.severity];
    badge.style.marginRight = "8px";

    const btnRecheck = document.createElement("button");
    btnRecheck.className = "small-btn";
    btnRecheck.textContent = "Recheck";
    btnRecheck.onclick = () => analyzeAndRecord(it.url, {record:false});

    const btnCopy = document.createElement("button");
    btnCopy.className = "small-btn";
    btnCopy.textContent = "Copy";
    btnCopy.onclick = () => navigator.clipboard.writeText(it.url);

    side.append(badge, btnRecheck, btnCopy);

    li.append(meta, side);
    historyList.append(li);
  }
}

// ---------------- Copy result ----------------
copyBtn.onclick = () => {
  if (!history.length) return;
  const latest = history[0];
  const txt = `${latest.url} — ${latest.result.label.toUpperCase()} (score ${latest.result.score})`;
  navigator.clipboard.writeText(txt);
  copyBtn.textContent="Copied!";
  setTimeout(()=>copyBtn.textContent="Copy Result",1200);
};

// ---------------- Clear history ----------------
clearBtn.onclick = () => {
  if (!confirm("Clear history?")) return;
  history = [];
  saveHistory(history);
  renderHistory();
};

// ---------------- Interactions ----------------
analyzeBtn.onclick = () => analyzeAndRecord(urlInput.value);
urlInput.addEventListener("keyup", e => {
  if (e.key==="Enter") analyzeAndRecord(urlInput.value);
});

// live preview
function debounce(fn, ms=300) {
  let t;
  return (...a)=>{ clearTimeout(t); t=setTimeout(()=>fn(...a), ms); };
}
urlInput.oninput = debounce(val => {
  if (!val.trim()) { resultDiv.innerHTML=""; return; }
  showResult(val, checkPhishing(val));
}, 300);

// ---------------- Toggle theme ----------------
toggleMode.onclick = () => {
  document.body.classList.toggle("light");
  toggleMode.textContent = document.body.classList.contains("light") ? "🌙" : "☀️";
  toggleMode.setAttribute("aria-pressed", document.body.classList.contains("light"));
};

// show last result on load
if (history.length) showResult(history[0].url, history[0].result);