chrome.runtime.onInstalled.addListener(() => {
  // chrome.storage.local.set({ mySetting: true }, () => {
  // local store the key locally while sync store syncs it across devices
  chrome.storage.sync.get(
    ["mySetting", "blockedDomains", "showBannerWarnings"],
    (result) => {
      if (!result.mySetting) {
        chrome.tabs.create({ url: "options.html" });
      }

      // Initialize default warning settings if not present
      const updates = {};
      if (!Array.isArray(result.blockedDomains)) {
        updates.blockedDomains = ["bad-phish.example"];
      }
      if (typeof result.showBannerWarnings !== "boolean") {
        updates.showBannerWarnings = true;
      }
      if (Object.keys(updates).length) {
        chrome.storage.sync.set(updates);
      }
    }
  );
});

// Alert when a declarativeNetRequest rule matches (requires
// "declarativeNetRequestFeedback" + "notifications" permissions in manifest)
if (
  chrome.declarativeNetRequest &&
  chrome.declarativeNetRequest.onRuleMatchedDebug
) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    (async () => {
      const url = info?.request?.url || "";
      const hostname = (() => {
        try {
          return new URL(url).hostname;
        } catch (e) {
          return url;
        }
      })();

      const ruleId = info?.rule?.ruleId ?? "?";
      const type = info?.request?.type ?? "request";

      const cached = await getCachedReasons(url);
      const extra = cached?.reasons?.[0]
        ? `\nReason: ${cached.reasons[0]}`
        : "";
      const nid = "phish-" + Date.now();
      lastNotificationUrlMap[nid] = url;
      chrome.notifications.create(nid, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "Blocked suspicious request",
        message: `Rule ${ruleId} matched on ${hostname}${extra}`,
        contextMessage: url,
        priority: 2,
      });
    })().catch(() => {});
  });
}

// Note: Removed webRequest blocking listener for MV3 compatibility.
// We rely on cached verdict + tabs.onUpdated to redirect.

// As a fallback, react to tab updates to redirect quickly based on cached verdict
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (!changeInfo.url && changeInfo.status !== "loading") return;
  const url = (changeInfo.url || tab.url || "").toString();
  if (!/^https?:\/\//i.test(url)) return;
  try {
    const verdict = await getCachedVerdict(url);
    if (verdict === "malicious") {
      const warn =
        chrome.runtime.getURL("warning.html") +
        `?url=${encodeURIComponent(url)}`;
      try { await chrome.tabs.update(tabId, { url: warn }); } catch (e) {}
    }
    // Start or refresh background scan so subsequent attempts can be blocked immediately
    const { virusTotalApiKey, localApiKey } = await chrome.storage.sync.get([
      "virusTotalApiKey",
      "localApiKey",
    ]);
    try {
      const [vt, local] = await Promise.all([
        vtScanUrl(url, virusTotalApiKey),
        localPredict(url, localApiKey),
      ]);
      const combined = combineVerdict(
        vt?.ok ? vt : null,
        local?.ok ? local : null
      );
      const reasons = [];
      if (vt?.ok)
        reasons.push(
          `VT: malicious=${vt.stats?.malicious || 0}, suspicious=${
            vt.stats?.suspicious || 0
          }`
        );
      if (local?.ok && Array.isArray(local.reasons) && local.reasons.length) {
        reasons.push(`AI: ${local.reasons.slice(0, 3).join("; ")}`);
      }
      await cacheReasons(url, reasons);
      await setCachedVerdict(url, combined);
      if (combined === "malicious") {
        const warn =
          chrome.runtime.getURL("warning.html") +
          `?url=${encodeURIComponent(url)}`;
        try { await chrome.tabs.update(tabId, { url: warn }); } catch (e) {}
      }
    } catch {}
  } catch {}
});

// --- Helpers ---
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function safeUrl(u) {
  try {
    return new URL(u).toString();
  } catch {
    return null;
  }
}
function getDomain(u) {
  try {
    return new URL(u).hostname;
  } catch {
    return "";
  }
}

// --- VirusTotal scanning ---
async function vtScanUrl(url, apiKey) {
  if (!apiKey) return { ok: false, error: "Missing VirusTotal API key" };
  try {
    const form = new URLSearchParams();
    form.set("url", url);
    const submit = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: form.toString(),
    });
    const submitJson = await submit.json();
    const analysisId = submitJson?.data?.id;
    if (!analysisId) return { ok: false, error: "No analysis ID" };

    // Poll the analysis endpoint a few times
    let analysis = null;
    for (let i = 0; i < 6; i++) {
      const res = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
          headers: { "x-apikey": apiKey },
        }
      );
      const j = await res.json();
      const status = j?.data?.attributes?.status;
      if (status === "completed") {
        analysis = j;
        break;
      }
      await sleep(1000);
    }
    if (!analysis) return { ok: false, error: "Analysis not ready" };

    const stats =
      analysis?.data?.attributes?.stats ||
      analysis?.data?.attributes?.results ||
      analysis?.data?.attributes?.last_analysis_stats ||
      {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const verdict = malicious > 0 || suspicious > 0 ? "malicious" : "harmless";

    return { ok: true, verdict, stats, analysisId, raw: analysis };
  } catch (e) {
    return { ok: false, error: String(e?.message || e) };
  }
}

// --- Local AI prediction ---
async function localPredict(url, apiKey) {
  try {
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["X-API-Key"] = apiKey;
    const res = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers,
      body: JSON.stringify({ url, user_id: "chrome-extension" }),
    });
    const json = await res.json();
    // Expected shape example:
    // { url, verdict: 'Phishing'|'Benign'|..., confidence: number, reasons: string[] }
    const verdict = /phish/i.test(json?.verdict || "")
      ? "malicious"
      : /benign|harmless|clean/i.test(json?.verdict || "")
      ? "harmless"
      : "unknown";
    const reasons = Array.isArray(json?.reasons) ? json.reasons : [];
    return { ok: true, verdict, raw: json, reasons };
  } catch (e) {
    return { ok: false, error: String(e?.message || e) };
  }
}

function combineVerdict(vt, local) {
  const vtVerdict = vt?.verdict;
  const localVerdict = local?.verdict;
  // Block only when BOTH VT and Local say malicious/phishing
  if (vtVerdict === "malicious" && localVerdict === "malicious")
    return "malicious";
  if (vtVerdict === "harmless" && localVerdict === "harmless")
    return "harmless";
  return "unknown";
}

// Cache reasons per URL for notifications
async function cacheReasons(url, reasons) {
  try {
    const key = "reasonsCache";
    const current = await chrome.storage.local.get([key]);
    const map = current[key] || {};
    map[url] = { reasons, ts: Date.now() };
    await chrome.storage.local.set({ [key]: map });
  } catch {}
}

async function getCachedReasons(url) {
  try {
    const key = "reasonsCache";
    const current = await chrome.storage.local.get([key]);
    return current[key]?.[url] || null;
  } catch {
    return null;
  }
}

// --- Messages from popup ---
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message?.type === "SCAN_URL") {
      const url = safeUrl(message.url);
      console.log("[BG] SCAN_URL received", { url });
      if (!url) return sendResponse({ error: "Invalid URL" });
      const { virusTotalApiKey, localApiKey } = await chrome.storage.sync.get([
        "virusTotalApiKey",
        "localApiKey",
      ]);

      const [vt, local] = await Promise.all([
        vtScanUrl(url, virusTotalApiKey),
        localPredict(url, localApiKey),
      ]);
      console.log("[BG] SCAN_URL results", { vt, local });

      const combinedVerdict = combineVerdict(
        vt?.ok ? vt : null,
        local?.ok ? local : null
      );
      const reasons = [];
      if (vt?.ok)
        reasons.push(
          `VT: malicious=${vt.stats?.malicious || 0}, suspicious=${
            vt.stats?.suspicious || 0
          }`
        );
      if (local?.ok && Array.isArray(local.reasons) && local.reasons.length) {
        reasons.push(`AI: ${local.reasons.slice(0, 3).join("; ")}`);
      }
      await cacheReasons(url, reasons);
      await setCachedVerdict(url, combinedVerdict);

      sendResponse({
        virusTotal: vt,
        localAI: local,
        combinedVerdict,
        reasons,
      });
    } else if (message?.type === "SCAN_PAGE_LINKS") {
      const urls = Array.isArray(message.urls) ? message.urls.slice(0, 50) : [];
      const { virusTotalApiKey, localApiKey } = await chrome.storage.sync.get([
        "virusTotalApiKey",
        "localApiKey",
      ]);
      const unsafe = [];
      // Light concurrency
      const queue = urls.slice();
      const workers = Array.from({ length: 5 }).map(async () => {
        while (queue.length) {
          const u = queue.shift();
          try {
            const [vt, local] = await Promise.all([
              vtScanUrl(u, virusTotalApiKey),
              localPredict(u, localApiKey),
            ]);
            const verdict = combineVerdict(
              vt?.ok ? vt : null,
              local?.ok ? local : null
            );
            const reasons = [];
            if (vt?.ok)
              reasons.push(
                `VT: malicious=${vt.stats?.malicious || 0}, suspicious=${
                  vt.stats?.suspicious || 0
                }`
              );
            if (
              local?.ok &&
              Array.isArray(local.reasons) &&
              local.reasons.length
            ) {
              reasons.push(`AI: ${local.reasons.slice(0, 3).join("; ")}`);
            }
            await cacheReasons(u, reasons);
            await setCachedVerdict(u, verdict);
            if (verdict === "malicious") unsafe.push(u);
          } catch {}
          await sleep(150);
        }
      });
      await Promise.all(workers);
      sendResponse({ unsafe });
    } else if (message?.type === "ADD_BLOCK_RULE") {
      const domain = message.domain;
      if (!domain) return sendResponse(false);
      try {
        const id = Math.floor(Math.random() * 1e9);
        await chrome.declarativeNetRequest.updateDynamicRules({
          addRules: [
            {
              id,
              priority: 1,
              action: { type: "block" },
              condition: {
                domains: [domain],
                resourceTypes: ["main_frame", "sub_frame"],
              },
            },
          ],
        });
        sendResponse(true);
      } catch (e) {
        console.error("Failed to add dynamic rule", e);
        sendResponse(false);
      }
    } else if (message?.type === "OPEN_DASHBOARD") {
      const url = message.url;
      const target = buildDashboardUrl(url || "");
      try { await chrome.tabs.create({ url: target }); } catch (e) {}
      sendResponse(true);
    } else if (message?.type === "REDIRECT_WARNING") {
      const url = message.url || "";
      const warn =
        chrome.runtime.getURL("warning.html") +
        `?url=${encodeURIComponent(url)}`;
      if (sender?.tab?.id) {
        try { await chrome.tabs.update(sender.tab.id, { url: warn }); } catch (e) {}
        sendResponse(true);
      } else {
        sendResponse(false);
      }
    }
  })();
  return true; // keep channel open for async
});

// Click notifications to open dashboard with context
chrome.notifications.onClicked.addListener((notificationId) => {
  const url =
    notificationId?.startsWith("phish-") &&
    lastNotificationUrlMap[notificationId];
  const target = buildDashboardUrl(url || "");
  chrome.tabs.create({ url: target }).catch?.(() => {});
});

const lastNotificationUrlMap = {};

// --- Dashboard helpers ---
function buildDashboardUrl(url, vt, local) {
  const base = "http://localhost:3000/scan"; // adjust for prod
  const params = new URLSearchParams();
  if (url) params.set("url", url);
  if (vt) {
    try { params.set("vt", btoa(JSON.stringify(vt))); } catch (e) {}
  }
  if (local) {
    try { params.set("local", btoa(JSON.stringify(local))); } catch (e) {}
  }
  const qs = params.toString();
  return qs ? `${base}?${qs}` : base;
}

// --- Automatic blocking on navigation using cache ---
// If we have both-VT-and-Local malicious verdict cached for a URL, redirect to warning page.
function shouldBlockFromCache(url) {
  // For now, rely on reasons presence pattern; more robust would be a dedicated cache entry
  // We'll compute a simple flag from reasonsCache: if both sources present and VT malicious>0 or AI reasons exist
  // but combineVerdict was used when caching, so keep a separate map soon. Here we just allow if we cached reasons and verdict was malicious via SCAN_* flow.
  // To make it explicit, store a separate map verdictCache in storage.local.
  return false; // placeholder, replaced at runtime via async helper below
}

async function getCachedVerdict(url) {
  const key = "verdictCache";
  const current = await chrome.storage.local.get([key]);
  return current[key]?.[url] || "unknown";
}

async function setCachedVerdict(url, verdict) {
  const key = "verdictCache";
  const current = await chrome.storage.local.get([key]);
  const map = current[key] || {};
  map[url] = verdict;
  await chrome.storage.local.set({ [key]: map });
}
