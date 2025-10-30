function getArticleText() {
  const article = document.querySelector("article");
  if (article) return article.innerText;

  const paragraphs = Array.from(document.getElementsByTagName("p"));
  if (paragraphs.length > 0) {
    return paragraphs.map((p) => p.innerText).join("\n\n");
  }
}

chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  if (request && request.type === "GET_ARTICLE_TEXT") {
    const selectedText = getArticleText();
    sendResponse({ text: selectedText });
  }
});

// Scripting text extraction logic for contentScript.js

// Lightweight in-page warning banner if current hostname is unsafe
(function injectWarningBanner() {
  try {
    chrome.storage && chrome.storage.sync.get(["blockedDomains", "showBannerWarnings"], (res) => {
      const show = res?.showBannerWarnings !== false;
      const domains = Array.isArray(res?.blockedDomains) ? res.blockedDomains : [];
      if (!show || domains.length === 0) return;

      const host = location.hostname || "";
      const isUnsafe = domains.some((d) => host === d || host.endsWith("." + d));
      if (!isUnsafe) return;

      const banner = document.createElement("div");
      banner.setAttribute("role", "alert");
      banner.style.position = "fixed";
      banner.style.top = "0";
      banner.style.left = "0";
      banner.style.right = "0";
      banner.style.zIndex = "2147483647";
      banner.style.padding = "12px 16px";
      banner.style.background = "#b00020";
      banner.style.color = "#fff";
      banner.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, sans-serif";
      banner.style.fontSize = "14px";
      banner.style.boxShadow = "0 2px 6px rgba(0,0,0,0.3)";
      banner.style.display = "flex";
      banner.style.alignItems = "center";
      banner.style.gap = "12px";

      const strong = document.createElement("strong");
      strong.textContent = "Warning:";
      const text = document.createElement("span");
      text.textContent = ` This site ("${host}") is flagged as unsafe.`;

      const btn = document.createElement("button");
      btn.textContent = "Dismiss";
      btn.style.marginLeft = "auto";
      btn.style.background = "#fff";
      btn.style.color = "#b00020";
      btn.style.border = "none";
      btn.style.borderRadius = "4px";
      btn.style.padding = "6px 10px";
      btn.style.cursor = "pointer";
      btn.addEventListener("click", () => banner.remove());

      banner.appendChild(strong);
      banner.appendChild(text);
      banner.appendChild(btn);
      document.documentElement.appendChild(banner);
      document.documentElement.style.scrollMarginTop = "48px";
    });
  } catch (e) {
    // no-op
  }
})();

// Automatically scan links on the page and annotate unsafe ones.
(function scanPageLinks() {
  const unsafeSet = new Set();
  try {
    const anchors = Array.from(document.querySelectorAll('a[href]'))
      .map(a => a.href)
      .filter(h => /^https?:\/\//i.test(h));
    if (!anchors.length) return;
    const unique = Array.from(new Set(anchors)).slice(0, 50);
    chrome.runtime.sendMessage({ type: 'SCAN_PAGE_LINKS', urls: unique }, (resp) => {
      if (!resp || !resp.unsafe) return;
      const bad = new Set(resp.unsafe);
      resp.unsafe.forEach(u => unsafeSet.add(u));
      document.querySelectorAll('a[href]').forEach(a => {
        const href = a.href;
        if (bad.has(href)) {
          a.style.outline = '2px solid #b00020';
          a.style.backgroundColor = 'rgba(176,0,32,0.08)';
          a.title = 'Potential phishing link (blocked if clicked)';
        }
      });
    });
    // Intercept clicks on unsafe links to show warning immediately
    document.addEventListener('click', (e) => {
      const a = e.target && (e.target.closest ? e.target.closest('a[href]') : null);
      if (!a) return;
      const href = a.href;
      if (unsafeSet.has(href)) {
        e.preventDefault();
        chrome.runtime.sendMessage({ type: 'REDIRECT_WARNING', url: href });
      }
    }, true);
  } catch (e) {
    // no-op
  }
})();
