function getParam(name) {
  const m = new URL(location.href).searchParams.get(name);
  return m || '';
}

async function getReasons(url) {
  try {
    const key = 'reasonsCache';
    const data = await chrome.storage.local.get([key]);
    const entry = data[key]?.[url];
    return entry?.reasons || [];
  } catch { return []; }
}

document.addEventListener('DOMContentLoaded', async () => {
  const url = getParam('url');
  document.getElementById('target').textContent = `Blocked URL: ${url}`;
  const reasons = await getReasons(url);
  const pre = document.getElementById('reasons');
  pre.textContent = reasons.length ? reasons.join('\n') : 'No details available.';

  document.getElementById('open-dashboard').addEventListener('click', () => {
    const target = `http://localhost:3000/?url=${encodeURIComponent(url)}`;
    window.open(target, '_blank');
  });
  document.getElementById('go-back').addEventListener('click', () => {
    history.back();
  });
});

