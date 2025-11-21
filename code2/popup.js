// popup.js
document.addEventListener("DOMContentLoaded", async () => {
  const status = document.getElementById("status");
  const details = document.getElementById("details");

  chrome.runtime.sendMessage({ request: "lastCheck" }, (resp) => {
    if (!resp) {
      status.textContent = "No recent checks yet.";
      details.innerHTML = "";
      return;
    }
    status.innerHTML = `URL: <strong>${resp.url}</strong>`;
    details.innerHTML = `
      <div>Verdict: <strong>${resp.verdict}</strong></div>
      <div>Score: <strong>${resp.score}</strong></div>
    `;
  });

  document.getElementById("open-settings").addEventListener("click", () => {
    // open a simple settings page or instruct user
    alert("Settings are demo-only. For production: allow custom blocklists & live threat feeds.");
  });
});
