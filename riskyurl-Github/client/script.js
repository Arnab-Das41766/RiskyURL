// === Dynamic Placeholder Shuffling ===
const input = document.getElementById("url-input");

const examples = [
  "https://example.com",
  "https://myportfolio.dev",
  "https://vulnerable.site",
  "https://riskyweb.net",
  "https://hackme.org",
];

let index = 0;
let intervalId = null;

function startShuffle() {
  stopShuffle();
  intervalId = setInterval(() => {
    if (input.value === "") {
      input.placeholder = examples[index];
      index = (index + 1) % examples.length;
    }
  }, 1000);
}

function stopShuffle() {
  clearInterval(intervalId);
}

startShuffle();

input.addEventListener("input", () => {
  if (input.value === "") {
    startShuffle();
  } else {
    stopShuffle();
  }
});

// === Typewriter Effect ===
const text = "Scan any URL for hidden threats — XSS, SQLi & more, instantly!";
const typedTextSpan = document.getElementById("typed-text");
let charIndex = 0;

function type() {
  if (charIndex < text.length) {
    typedTextSpan.textContent += text.charAt(charIndex);
    charIndex++;
    setTimeout(type, 40);
  } else {
    setTimeout(() => {
      typedTextSpan.textContent = "";
      charIndex = 0;
      type();
    }, 2000);
  }
}

window.onload = type;

// === Scanner Logic ===
document.addEventListener('DOMContentLoaded', () => {
  const checkButton = document.getElementById('check-button');
  const urlInput = document.getElementById('url-input');
  const loadingText = document.getElementById('loading-text');
  const checklistItems = document.querySelectorAll('#checklist li input');

  const vulnerabilities = [
    "Error-Based SQLi",
    "Boolean-Based SQLi",
    "Time-Based SQLi",
    "Union-Based SQLi",
    "Reflected XSS",
    "Stored XSS",
    "DOM-Based XSS",
    "CSRF",
    "Header check",
    "ssltls check",
    "Directory Fuzzing"
  ];

  async function checkURL() {
    const url = urlInput.value;
    if (!url) {
      alert("Please enter a valid URL.");
      return;
    }

    console.log(url);

    checklistItems.forEach(cb => {
      if (cb) {
        cb.checked = false;
        cb.parentNode.classList.remove("safe", "vulnerable");
      }
    });

    loadingText.textContent = "Analyzing vulnerabilities...";

    try {
      const response = await fetch('http://localhost:5000/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url })
      });

      const result = await response.json();

      for (let i = 0; i < vulnerabilities.length; i++) {
        const vulnerability = vulnerabilities[i];
        loadingText.textContent = `Checking ${vulnerability}...`;
        await new Promise(resolve => setTimeout(resolve, 1000));

        let isVulnerable = false;

        if (vulnerability === "Error-Based SQLi") {
          isVulnerable = result.sql_injection_check?.error_based;
        } else if (vulnerability === "Boolean-Based SQLi") {
          isVulnerable = result.sql_injection_check?.boolean_based;
        } else if (vulnerability === "Time-Based SQLi") {
          isVulnerable = result.sql_injection_check?.time_based;
        } else if (vulnerability === "Union-Based SQLi") {
          isVulnerable = result.sql_injection_check?.union_based;
        } else if (vulnerability === "Reflected XSS") {
          isVulnerable = result.xss_check?.reflected?.length > 0;
        } else if (vulnerability === "Stored XSS") {
          isVulnerable = result.xss_check?.stored?.length > 0;
        } else if (vulnerability === "DOM-Based XSS") {
          isVulnerable = result.xss_check?.dom?.length > 0;
        } else if (vulnerability === "CSRF") {
          isVulnerable = result.csrf_check ? result.csrf_check.vulnerable : false;
        } else if (vulnerability === "Header check") {
          const headers = result.header_check;
          isVulnerable = headers && Object.values(headers).some(v => v === false);
        } else if (vulnerability === "ssltls check") {
          const ssl = result.ssltls_check;
          isVulnerable = ssl && (
            (!ssl.tls_1_2_supported && !ssl.tls_1_3_supported) ||
            !ssl.certificate_valid ||
            !ssl.connection_secure
          );
        } else if (vulnerability === "Directory Fuzzing") {
          isVulnerable = result.directory_fuzzing ? result.directory_fuzzing.vulnerable : false;
        }

        // Update checklist item
        if (checklistItems[i]) {
          checklistItems[i].checked = true;
          checklistItems[i].parentNode.classList.remove("safe", "vulnerable");
          checklistItems[i].parentNode.classList.add(isVulnerable ? "vulnerable" : "safe");
        }
      }

      loadingText.textContent = "Scan Complete ✅";

    } catch (error) {
      console.error("Scan failed:", error);
      loadingText.textContent = `Error: ${error.message || error}`;
    }
  }

  checkButton.addEventListener('click', checkURL);
});
