// -------------------- PHISHING CHECK FUNCTION --------------------
function checkPhishing(inputUrl) {
    let reasons = [];
    let url = inputUrl.trim();

    // Auto-add HTTPS if missing
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        url = "https://" + url;
    }

    let hostname = "";
    try {
        hostname = new URL(url).hostname.toLowerCase();
    } catch {
        reasons.push("Invalid URL format");
        return { isPhishing: true, reasons };
    }

    url = url.toLowerCase();

    // 1. Suspicious keywords
    const suspiciousWords = ["free", "win", "bonus", "money", "gift", "offer"];
    suspiciousWords.forEach(word => {
        if (url.includes(word)) {
            reasons.push(`Suspicious keyword detected: "${word}"`);
        }
    });

    // 2. Very long URL
    if (url.length > 70) {
        reasons.push("URL is unusually long");
    }

    // 3. Contains '@'
    if (url.includes("@")) {
        reasons.push("Contains '@' symbol — often used to hide real domain");
    }

    // 4. No HTTPS
    if (!url.startsWith("https://")) {
        reasons.push("Connection is not secure (HTTPS missing)");
    }

    // 5. IP address instead of domain
    const ipPattern = /^\d{1,3}(\.\d{1,3}){3}$/;
    if (ipPattern.test(hostname)) {
        reasons.push("URL uses an IP address instead of domain name");
    }

    // 6. Too many subdomains
    const domainParts = hostname.split(".");
    if (domainParts.length > 4) {
        reasons.push("Too many subdomains — suspicious structure");
    }

    // 7. Suspicious TLDs
    const riskyTLDs = [".xyz", ".click", ".gift", ".top", ".loan", ".work"];
    riskyTLDs.forEach(tld => {
        if (hostname.endsWith(tld)) {
            reasons.push(`Suspicious domain extension detected: ${tld}`);
        }
    });

    // 8. Strange number-letter mix in hostname
    if (/[a-zA-Z]+\d+[a-zA-Z]+/.test(hostname)) {
        reasons.push("Unusual number patterns found in domain");
    }

    // 9. Encoded (%XX) characters
    if (/%[0-9A-F]{2}/i.test(url)) {
        reasons.push("Contains encoded characters in URL");
    }

    // 10. Repeated characters (aaa)
    if (/(.)\1\1/.test(hostname)) {
        reasons.push("Contains repeated characters (spam-like behavior)");
    }

    return {
        isPhishing: reasons.length > 0,
        reasons
    };
}

// -------------------- URL CHECK BUTTON --------------------
function analyzeURL() {
    const url = document.getElementById("urlInput").value.trim();
    const resultDiv = document.getElementById("result");

    if (!url) {
        resultDiv.innerHTML = `<p class="danger">⚠️ Please enter a valid URL!</p>`;
        return;
    }

    const analysis = checkPhishing(url);

    if (analysis.isPhishing) {
        resultDiv.innerHTML = `
            <p class="danger">⚠️ Potential Phishing Detected!</p>
            <ul>${analysis.reasons.map(reason => `<li>${reason}</li>`).join("")}</ul>
        `;
    } else {
        resultDiv.innerHTML = `<p class="safe">✔️ This URL appears safe!</p>`;
    }
}

// -------------------- DARK MODE TOGGLE --------------------
const toggleButton = document.getElementById("toggleMode");

if (toggleButton) {
    toggleButton.addEventListener("click", () => {
        document.body.classList.toggle("light-mode");

        toggleButton.textContent = document.body.classList.contains("light-mode")
            ? "🌙 Dark Mode"
            : "☀️ Light Mode";
    });
}
