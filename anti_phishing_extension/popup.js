const openDashBtn = document.getElementById("open-dashboard-btn");
const resultEl = document.getElementById("result");
const btn1 = document.getElementById("scan-url-1");
const btn2 = document.getElementById("scan-url-2");
const input1 = document.getElementById("test-url-1");
const input2 = document.getElementById("test-url-2");

function render(msg) {
  if (!resultEl) return;
  const time = new Date().toLocaleTimeString();
  const prev = resultEl.textContent || "";
  resultEl.textContent = `${prev}${prev ? "\n\n" : ""}[${time}] ${msg}`;
}

async function scanUrl(url, label) {
  try {
    render(`${label}: scanning ${url}`);
    console.log("[POPUP] Sending SCAN_URL", { url, label });
    const resp = await chrome.runtime.sendMessage({ type: "SCAN_URL", url });
    console.log("[POPUP] SCAN_URL response", resp);
    if (!resp) {
      render(`${label}: No response from background.`);
      return;
    }
    const { virusTotal, localAI, combinedVerdict, reasons, error } = resp;
    if (error) {
      render(`${label}: Error - ${error}`);
      return;
    }
    render(
      `${label}: combined=${combinedVerdict}\nVT: ${
        virusTotal?.ok ? JSON.stringify(virusTotal?.stats) : virusTotal?.error || "n/a"
      }\nLocal: ${
        localAI?.ok ? JSON.stringify({ verdict: localAI.verdict, reasons: localAI.reasons?.slice(0,3) }) : localAI?.error || "n/a"
      }\nReasons: ${Array.isArray(reasons) ? reasons.join(" | ") : "-"}`
    );
  } catch (e) {
    console.error("[POPUP] SCAN_URL failed", e);
    render(`${label}: Exception - ${e?.message || e}`);
  }
}

if (openDashBtn) {
  openDashBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs && tabs[0] && tabs[0].url ? tabs[0].url : "";
      chrome.runtime
        .sendMessage({ type: "OPEN_DASHBOARD", url })
        .catch((e) => {
          console.warn("[POPUP] OPEN_DASHBOARD failed", e);
        });
    });
  });
}

if (btn1 && input1) {
  btn1.addEventListener("click", () => scanUrl(input1.value.trim(), "URL 1"));
}

if (btn2 && input2) {
  btn2.addEventListener("click", () => scanUrl(input2.value.trim(), "URL 2"));
}
