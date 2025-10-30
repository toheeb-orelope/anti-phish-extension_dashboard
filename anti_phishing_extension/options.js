document.addEventListener("DOMContentLoaded", () => {
  const vtInput = document.getElementById("vt-api-key");
  const localInput = document.getElementById("local-api-key");
  const saveBtn = document.getElementById("save-btn");
  const successMessage = document.getElementById("success-message");

  // Load any saved values (with backward compat for legacy key `mySetting`)
  if (chrome?.storage?.sync) {
    chrome.storage.sync.get(
      ["virusTotalApiKey", "localApiKey", "mySetting"],
      ({ virusTotalApiKey, localApiKey, mySetting }) => {
        const local = localApiKey || mySetting; // prefer new key, fallback to legacy
        if (
          vtInput instanceof HTMLInputElement &&
          typeof virusTotalApiKey === "string"
        ) {
          vtInput.value = virusTotalApiKey;
        }
        if (
          localInput instanceof HTMLInputElement &&
          typeof local === "string"
        ) {
          localInput.value = local;
        }
      }
    );
  }

  // Toggle show/hide for API key inputs
  document.querySelectorAll(".toggle-visibility").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      if (!targetId) return;
      const field = document.getElementById(targetId);
      if (!(field instanceof HTMLInputElement)) return;
      const showing = field.type === "text";
      field.type = showing ? "password" : "text";
      btn.textContent = showing ? "Show" : "Hide";
    });
  });

  // Save both keys
  if (
    saveBtn instanceof HTMLElement &&
    vtInput instanceof HTMLInputElement &&
    localInput instanceof HTMLInputElement
  ) {
    saveBtn.addEventListener("click", () => {
      const vtKey = vtInput.value.trim();
      const localKey = localInput.value.trim();

      if (!chrome?.storage?.sync) {
        console.warn("chrome.storage.sync not available in this context");
        return;
      }

      const payload = {
        virusTotalApiKey: vtKey || "",
        localApiKey: localKey || "",
        // Backward compatibility: keep `mySetting` in sync with local key
        mySetting: localKey || "",
      };

      chrome.storage.sync.set(payload, () => {
        if (successMessage instanceof HTMLElement) {
          successMessage.style.display = "block";
        }
        setTimeout(() => window.close(), 900);
      });
    });
  }
});
