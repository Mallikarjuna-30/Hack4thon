// content_script.js
let bannerId = "quickphish-warning-banner";

function removeBanner() {
  const el = document.getElementById(bannerId);
  if (el) el.remove();
}

function showBanner(payload) {
  removeBanner();
  const { score, verdict, url } = payload;
  const container = document.createElement("div");
  container.id = bannerId;
  container.style.position = "fixed";
  container.style.left = "12px";
  container.style.right = "12px";
  container.style.top = "12px";
  container.style.zIndex = 2147483647;
  container.style.padding = "12px";
  container.style.borderRadius = "10px";
  container.style.boxShadow = "0 6px 18px rgba(0,0,0,0.2)";
  container.style.fontFamily = "Inter, Arial, sans-serif";
  container.style.backdropFilter = "blur(6px)";
  container.style.color = "#111";
  // basic color by verdict
  if (verdict === "danger") {
    container.style.background = "linear-gradient(90deg,#ffd2d2,#ffbfbf)";
  } else if (verdict === "suspicious") {
    container.style.background = "linear-gradient(90deg,#fff4cc,#fff1b8)";
  } else {
    container.style.background = "linear-gradient(90deg,#d8f7d8,#c9f0c9)";
  }

  container.innerHTML = `
    <div style="display:flex;gap:12px;align-items:center;">
      <div style="flex:1">
        <strong style="font-size:15px">QuickPhish</strong>
        <div style="font-size:13px;margin-top:4px">Risk score: <strong>${score}</strong> — ${verdict.toUpperCase()}</div>
        <div style="font-size:12px;margin-top:6px;opacity:0.9">URL: ${url}</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <button id="qp-ignore" style="padding:8px 10px;border-radius:8px;border:0;cursor:pointer">Ignore</button>
        <button id="qp-leave" style="padding:8px 10px;border-radius:8px;border:0;cursor:pointer">Leave</button>
      </div>
    </div>
  `;

  document.documentElement.appendChild(container);
  document.getElementById("qp-ignore").addEventListener("click", () => removeBanner());
  document.getElementById("qp-leave").addEventListener("click", () => {
    // try to go back or open about:blank
    try { window.location.href = "about:blank"; } catch (e) { window.history.back(); }
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.action === "risk_check") {
    // only show if score is suspicious or danger
    if (msg.score >= 25) {
      showBanner(msg);
    } else {
      removeBanner();
    }
  }
});

// When loaded, ask background for last check to show immediate state
chrome.runtime.sendMessage({ request: "lastCheck" }, (resp) => {
  if (resp && resp.score >= 25) {
    showBanner(resp);
  }
});
