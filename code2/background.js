// background.js
// Listeners watch tab updates and run risk checks then send result to content script and popup.

const popularDomains = [
  "google.com",
  "facebook.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "github.com",
  "linkedin.com",
  "twitter.com",
  "instagram.com"
];

// small known-bad sample list (demo). Replace / extend with real feeds in production.
const knownBad = [
  "malicious-example.test",
  "phishingsite.example"
];

const suspiciousTLDs = [
  "zip","country","tk","ml","gq","cf" // demo
];

function hostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (e) {
    return url.toLowerCase();
  }
}

// Simple Levenshtein distance
function lev(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({length: m+1}, (_,i)=>Array(n+1).fill(0));
  for (let i=0;i<=m;i++) dp[i][0]=i;
  for (let j=0;j<=n;j++) dp[0][j]=j;
  for (let i=1;i<=m;i++){
    for (let j=1;j<=n;j++){
      dp[i][j] = Math.min(
        dp[i-1][j]+1,
        dp[i][j-1]+1,
        dp[i-1][j-1] + (a[i-1]===b[j-1] ? 0 : 1)
      );
    }
  }
  return dp[m][n];
}

function topDomain(h) {
  // strip subdomains, basic: take last two labels unless ccTLDs (simplified)
  const parts = h.split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  return parts.slice(-2).join(".");
}

function tldOf(h) {
  const parts = h.split(".");
  return parts.length>1 ? parts[parts.length-1] : "";
}

function containsIP(url) {
  try {
    const u = new URL(url);
    const host = u.hostname;
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  } catch (e) {
    return false;
  }
}

function riskScore(url) {
  let score = 0;
  const h = hostname(url);
  const td = topDomain(h);

  // Known bad
  if (knownBad.includes(h) || knownBad.includes(td)) {
    score += 70;
  }

  // IP in URL
  if (containsIP(url)) score += 40;

  // '@' in url (common trick)
  if (url.includes("@")) score += 30;

  // long path
  try {
    const u = new URL(url);
    if ((u.pathname + u.search).length > 80) score += 10;
  } catch(e){}

  // suspicious TLDs
  const tld = tldOf(h);
  if (suspiciousTLDs.includes(tld)) score += 20;

  // typosquatting check vs popular domains
  for (const pd of popularDomains) {
    const dist = lev(td, pd);
    const len = Math.max(td.length, pd.length);
    const rel = dist / len;
    // if small relative distance (typo) and not equal
    if (rel <= 0.25 && td !== pd) {
      score += Math.max(15, Math.floor((1 - rel) * 30)); // up to +30
    }
  }

  // normalize to 0-100
  if (score > 100) score = 100;
  return score;
}

// Send message to content script of the tab
async function notifyTab(tabId, payload) {
  try {
    await chrome.tabs.sendMessage(tabId, payload);
  } catch (e) {
    // content script might not be ready; that's okay for demo
  }
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // act when URL changes or completed
  if (changeInfo.url || changeInfo.status === "complete") {
    const url = changeInfo.url || tab.url;
    if (!url) return;
    const score = riskScore(url);
    const verdict = score >= 50 ? "danger" : (score >= 25 ? "suspicious" : "safe");
    const payload = { action: "risk_check", url, score, verdict };
    notifyTab(tabId, payload);
    // store last check for popup
    chrome.storage.local.set({ lastCheck: payload });
  }
});

// also handle popup requests
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.request === "lastCheck") {
    chrome.storage.local.get("lastCheck", data => sendResponse(data.lastCheck || null));
    return true; // async
  }
});
