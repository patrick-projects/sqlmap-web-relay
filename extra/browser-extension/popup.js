import { runScan } from './scanner.js';

const urlInput = document.getElementById('url');
const techniqueSelect = document.getElementById('technique');
const scanBtn = document.getElementById('scanBtn');
const useCurrentBtn = document.getElementById('useCurrent');
const logEl = document.getElementById('log');
const findingsEl = document.getElementById('findings');

function log(msg, type = '') {
  logEl.style.display = 'block';
  const span = document.createElement('div');
  span.className = type;
  span.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  logEl.appendChild(span);
  logEl.scrollTop = logEl.scrollHeight;
}

function clearLog() {
  logEl.innerHTML = '';
  logEl.style.display = 'none';
}

useCurrentBtn.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    urlInput.value = tab.url;
    log('Loaded URL from current tab', 'ok');
  } else {
    log('Could not get current tab URL', 'err');
  }
});

scanBtn.addEventListener('click', async () => {
  const url = urlInput.value.trim();
  if (!url) {
    log('Enter a target URL', 'err');
    return;
  }

  scanBtn.disabled = true;
  clearLog();
  findingsEl.innerHTML = '';

  try {
    const postData = document.getElementById('postData').value.trim() || null;
    log('Starting scan (requests originate from your browser)...', 'ok');
    const result = await runScan(url, {
      technique: techniqueSelect.value,
      postData,
    }, (p) => {
      if (p.param) log(`Testing parameter: ${p.param}`, 'warn');
      if (p.phase) log(`  ${p.phase}...`, '');
    });

    log('Scan complete.', 'ok');

    for (const f of result.findings) {
      const div = document.createElement('div');
      div.className = `finding ${f.suspect ? 'suspect' : 'ok'}`;
      let html = `<span class="param">${f.param}</span>: `;
      if (f.suspect) {
        html += '⚠ Possible SQL injection detected. ';
        const suspectResults = f.results.filter(r => r.suspect);
        html += suspectResults.map(r => {
          if (r.technique === 'boolean') return `Boolean (len diff: ${Math.abs(r.lenTrue - r.lenFalse)})`;
          if (r.technique === 'time') return `Time-based (${r.elapsed}ms, ${r.dbms})`;
          if (r.technique === 'error') return 'Error-based';
          return r.technique;
        }).join(', ');
      } else {
        html += 'No indication of injection.';
      }
      div.innerHTML = html;
      findingsEl.appendChild(div);
    }

    if (result.findings.every(f => !f.suspect)) {
      log('No vulnerabilities detected. Try other parameters or techniques.', 'warn');
    }
  } catch (err) {
    log(err.message || 'Scan failed', 'err');
  } finally {
    scanBtn.disabled = false;
  }
});
