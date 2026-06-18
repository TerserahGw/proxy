const fs = require("fs");
const path = require("path");
const axios = require("axios");
const { HttpProxyAgent } = require("http-proxy-agent");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { SocksProxyAgent } = require("socks-proxy-agent");

const MODE = process.argv[2] || "scan";

const ROOT = path.join(__dirname, "..");
const OUT_TXT = path.join(ROOT, "verified-proxies.txt");
const OUT_JSON = path.join(ROOT, "verified-proxies.json");
const FAIL_LOG = path.join(ROOT, "fail.text");

const TEST_URL = process.env.TEST_URL || "https://api.ipify.org?format=json";
const TIMEOUT = Number(process.env.TIMEOUT || 8000);
const CONCURRENCY = Number(process.env.CONCURRENCY || 250);
const MAX_SCAN_TEST = Number(process.env.MAX_SCAN_TEST || 3000);

const SOURCES = [
  {
    name: "proxyscrape-all",
    type: "auto",
    fallbackScheme: "http",
    url: "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.json"
  },
  {
    name: "databay-http",
    type: "http",
    fallbackScheme: "http",
    url: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/http.txt"
  },
  {
    name: "databay-socks4",
    type: "socks4",
    fallbackScheme: "socks4",
    url: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks4.txt"
  },
  {
    name: "databay-socks5",
    type: "socks5",
    fallbackScheme: "socks5",
    url: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks5.txt"
  },
  {
    name: "hideip-connect",
    type: "connect",
    fallbackScheme: "http",
    url: "https://github.com/zloi-user/hideip.me/raw/refs/heads/main/connect.txt"
  },
  {
    name: "hideip-socks5",
    type: "socks5",
    fallbackScheme: "socks5",
    url: "https://github.com/zloi-user/hideip.me/raw/refs/heads/main/socks5.txt"
  },
  {
    name: "hideip-socks4",
    type: "socks4",
    fallbackScheme: "socks4",
    url: "https://github.com/zloi-user/hideip.me/raw/refs/heads/main/socks4.txt"
  },
  {
    name: "hideip-https",
    type: "https",
    fallbackScheme: "http",
    url: "https://github.com/zloi-user/hideip.me/raw/refs/heads/main/https.txt"
  },
  {
    name: "hideip-http",
    type: "http",
    fallbackScheme: "http",
    url: "https://github.com/zloi-user/hideip.me/raw/refs/heads/main/http.txt"
  }
];

function nowIso() {
  return new Date().toISOString();
}

function ensureFile(file, value = "") {
  if (!fs.existsSync(file)) fs.writeFileSync(file, value, "utf8");
}

function ensureOutputFiles() {
  ensureFile(OUT_TXT, "");
  ensureFile(OUT_JSON, "[]\n");
  ensureFile(FAIL_LOG, "TOTAL_PROXY=0\nTOTAL_VALID=0\nTOTAL_FAIL=0\n");
}

function normalizeScheme(scheme, fallback = "http") {
  scheme = String(scheme || fallback || "http").toLowerCase().trim();

  if (scheme === "https") return "http";
  if (scheme === "connect") return "http";
  if (scheme === "socks") return "socks5";

  if (["http", "socks4", "socks5"].includes(scheme)) return scheme;

  return fallback || "http";
}

function normalizeProxy(input, fallbackScheme = "http", meta = {}) {
  if (!input) return null;

  let raw = String(input).trim();
  if (!raw || raw.startsWith("#")) return null;

  raw = raw.replace(/\s+/g, " ");

  const match = raw.match(/(?:(https?|socks4|socks5|connect):\/\/)?([a-zA-Z0-9.-]+):(\d{1,5})/i);
  if (!match) return null;

  const scheme = normalizeScheme(match[1], fallbackScheme);
  const host = match[2];
  const port = Number(match[3]);

  if (!host || !port || port < 1 || port > 65535) return null;

  return {
    proxy: `${scheme}://${host}:${port}`,
    scheme,
    host,
    port,
    ...meta
  };
}

function extractFromJson(value, source, output = []) {
  if (!value) return output;

  if (typeof value === "string") {
    const p = normalizeProxy(value, source.fallbackScheme, {
      sourceName: source.name,
      sourceUrl: source.url,
      sourceType: source.type
    });

    if (p) output.push(p);
    return output;
  }

  if (Array.isArray(value)) {
    for (const item of value) extractFromJson(item, source, output);
    return output;
  }

  if (typeof value === "object") {
    const host =
      value.ip ||
      value.host ||
      value.hostname ||
      value.address ||
      value.proxyAddress ||
      value.proxy_host;

    const port =
      value.port ||
      value.proxyPort ||
      value.proxy_port;

    let proto =
      value.protocol ||
      value.scheme ||
      value.type ||
      value.proxyType ||
      value.proxy_type;

    if (Array.isArray(proto)) proto = proto[0];

    if (host && port) {
      const p = normalizeProxy(`${host}:${port}`, normalizeScheme(proto, source.fallbackScheme), {
        sourceName: source.name,
        sourceUrl: source.url,
        sourceType: source.type
      });

      if (p) output.push(p);
    }

    for (const key of Object.keys(value)) {
      const v = value[key];
      if (typeof v === "object" || Array.isArray(v) || typeof v === "string") {
        extractFromJson(v, source, output);
      }
    }

    return output;
  }

  return output;
}

function extractPlainText(text, source) {
  const output = [];
  const rawText = String(text || "");
  const lines = rawText.split(/\r?\n/);

  for (const line of lines) {
    const p = normalizeProxy(line, source.fallbackScheme, {
      sourceName: source.name,
      sourceUrl: source.url,
      sourceType: source.type
    });

    if (p) output.push(p);
  }

  const regex = /(?:(https?|socks4|socks5|connect):\/\/)?([a-zA-Z0-9.-]+):(\d{1,5})/gi;
  let match;

  while ((match = regex.exec(rawText))) {
    const raw = `${match[1] ? match[1] + "://" : ""}${match[2]}:${match[3]}`;

    const p = normalizeProxy(raw, source.fallbackScheme, {
      sourceName: source.name,
      sourceUrl: source.url,
      sourceType: source.type
    });

    if (p) output.push(p);
  }

  return output;
}

async function fetchSource(source) {
  try {
    const res = await axios.get(source.url, {
      timeout: 30000,
      responseType: "text",
      validateStatus: s => s >= 200 && s < 300,
      headers: {
        "user-agent": "Mozilla/5.0 ProxyAutoChecker/1.0",
        accept: "application/json,text/plain,*/*"
      }
    });

    const raw = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
    let proxies = [];

    try {
      const json = JSON.parse(raw);
      proxies = extractFromJson(json, source);
    } catch {
      proxies = extractPlainText(raw, source);
    }

    const map = new Map();
    for (const p of proxies) {
      if (!map.has(p.proxy)) map.set(p.proxy, p);
    }

    const result = [...map.values()];
    console.log(`[FETCH] ${source.name}: ${result.length}`);
    return result;
  } catch (err) {
    console.log(`[FETCH ERROR] ${source.name}: ${err.code || err.message}`);
    return [];
  }
}

function readVerifiedTxt() {
  ensureFile(OUT_TXT);

  return fs.readFileSync(OUT_TXT, "utf8")
    .split(/\r?\n/)
    .map(x => normalizeProxy(x, "http"))
    .filter(Boolean);
}

function readVerifiedJson() {
  try {
    if (!fs.existsSync(OUT_JSON)) return [];
    const json = JSON.parse(fs.readFileSync(OUT_JSON, "utf8"));
    return Array.isArray(json) ? json : [];
  } catch {
    return [];
  }
}

function writeVerified(items) {
  const map = new Map();

  for (const item of items) {
    const p = normalizeProxy(item.proxy || item, item.scheme || "http", item);
    if (!p) continue;

    map.set(p.proxy, {
      ...item,
      ...p,
      proxy: p.proxy,
      scheme: p.scheme,
      host: p.host,
      port: p.port
    });
  }

  const arr = [...map.values()].sort((a, b) => {
    const pa = Number(a.ping || 999999);
    const pb = Number(b.ping || 999999);
    return pa - pb || a.proxy.localeCompare(b.proxy);
  });

  const txt = arr.map(x => x.proxy).join("\n");

  fs.writeFileSync(OUT_TXT, txt ? txt + "\n" : "", "utf8");
  fs.writeFileSync(OUT_JSON, JSON.stringify(arr, null, 2) + "\n", "utf8");

  return arr;
}

function makeAgents(proxyUrl) {
  if (proxyUrl.startsWith("socks4://") || proxyUrl.startsWith("socks5://")) {
    const agent = new SocksProxyAgent(proxyUrl);
    return {
      httpAgent: agent,
      httpsAgent: agent
    };
  }

  return {
    httpAgent: new HttpProxyAgent(proxyUrl),
    httpsAgent: new HttpsProxyAgent(proxyUrl)
  };
}

async function testProxy(item) {
  const proxyUrl = typeof item === "string" ? item : item.proxy;
  const started = Date.now();

  try {
    const agents = makeAgents(proxyUrl);

    const res = await axios.get(TEST_URL, {
      timeout: TIMEOUT,
      proxy: false,
      httpAgent: agents.httpAgent,
      httpsAgent: agents.httpsAgent,
      validateStatus: s => s >= 200 && s < 400,
      headers: {
        "user-agent": "Mozilla/5.0 ProxyAutoChecker/1.0",
        accept: "application/json,text/plain,*/*"
      }
    });

    if (!res.data) {
      return {
        ok: false,
        proxy: proxyUrl,
        reason: "EMPTY_RESPONSE"
      };
    }

    return {
      ok: true,
      proxy: proxyUrl,
      ping: Date.now() - started
    };
  } catch (err) {
    return {
      ok: false,
      proxy: proxyUrl,
      reason: err.code || err.message || "UNKNOWN_ERROR"
    };
  }
}

async function runPool(items, workerFn, concurrency) {
  let index = 0;
  let done = 0;
  const results = [];

  async function worker() {
    while (index < items.length) {
      const currentIndex = index++;
      const item = items[currentIndex];

      const result = await workerFn(item);
      results.push(result);
      done++;

      if (result && result.ok) {
        console.log(`[OK] ${done}/${items.length} ${result.proxy} ${result.ping}ms`);
      } else if (result) {
        console.log(`[FAIL] ${done}/${items.length} ${result.proxy} ${result.reason}`);
      }

      if (done % 100 === 0 || done === items.length) {
        const ok = results.filter(x => x && x.ok).length;
        const fail = results.filter(x => x && !x.ok).length;
        console.log(`[PROGRESS] ${done}/${items.length} | valid=${ok} fail=${fail}`);
      }
    }
  }

  const totalWorkers = Math.min(concurrency, items.length || 1);
  await Promise.all(Array.from({ length: totalWorkers }, () => worker()));

  return results;
}

async function scanNewProxies() {
  console.log("[MODE] scan new proxies");

  const oldTxt = readVerifiedTxt();
  const oldJson = readVerifiedJson();

  const oldMap = new Map();

  for (const item of oldJson) {
    const p = normalizeProxy(item.proxy, item.scheme || "http", item);
    if (p) oldMap.set(p.proxy, { ...item, ...p });
  }

  for (const item of oldTxt) {
    if (!oldMap.has(item.proxy)) {
      oldMap.set(item.proxy, {
        ...item,
        addedAt: nowIso(),
        lastCheckedAt: nowIso()
      });
    }
  }

  const fetched = (await Promise.all(SOURCES.map(fetchSource))).flat();

  const candidateMap = new Map();

  for (const item of fetched) {
    if (oldMap.has(item.proxy)) continue;
    if (!candidateMap.has(item.proxy)) candidateMap.set(item.proxy, item);
  }

  let candidates = [...candidateMap.values()];

  if (candidates.length > MAX_SCAN_TEST) {
    candidates = candidates.slice(0, MAX_SCAN_TEST);
  }

  console.log(`[EXISTING] ${oldMap.size}`);
  console.log(`[NEW CANDIDATE] ${candidateMap.size}`);
  console.log(`[TESTING] ${candidates.length}`);

  if (!candidates.length) {
    writeVerified([...oldMap.values()]);
    console.log("[DONE] no new proxy");
    return;
  }

  const results = await runPool(candidates, testProxy, CONCURRENCY);

  let added = 0;

  for (const result of results) {
    if (!result || !result.ok) continue;

    const base = candidateMap.get(result.proxy) || {};
    const parsed = normalizeProxy(result.proxy);

    oldMap.set(result.proxy, {
      ...base,
      proxy: result.proxy,
      scheme: parsed.scheme,
      host: parsed.host,
      port: parsed.port,
      ping: result.ping,
      addedAt: nowIso(),
      lastCheckedAt: nowIso()
    });

    added++;
  }

  const finalItems = writeVerified([...oldMap.values()]);

  console.log(`[DONE] added=${added}`);
  console.log(`[TOTAL VERIFIED] ${finalItems.length}`);
}

async function cleanInvalidProxies() {
  console.log("[MODE] clean invalid proxies");

  const txt = readVerifiedTxt();
  const json = readVerifiedJson();

  const jsonMap = new Map();

  for (const item of json) {
    const p = normalizeProxy(item.proxy, item.scheme || "http", item);
    if (p) jsonMap.set(p.proxy, { ...item, ...p });
  }

  const current = [];

  for (const item of txt) {
    current.push(jsonMap.get(item.proxy) || {
      ...item,
      addedAt: nowIso()
    });
  }

  const map = new Map();
  for (const item of current) {
    if (!map.has(item.proxy)) map.set(item.proxy, item);
  }

  const list = [...map.values()];

  console.log(`[CHECK EXISTING] ${list.length}`);

  if (!list.length) {
    writeVerified([]);
    fs.writeFileSync(FAIL_LOG, "TOTAL_PROXY=0\nTOTAL_VALID=0\nTOTAL_FAIL=0\n", "utf8");
    console.log("[DONE] empty repo");
    return;
  }

  const results = await runPool(list, testProxy, CONCURRENCY);

  const resultMap = new Map();
  for (const r of results) {
    if (r) resultMap.set(r.proxy, r);
  }

  const keep = [];
  const fail = [];

  for (const item of list) {
    const result = resultMap.get(item.proxy);

    if (result && result.ok) {
      keep.push({
        ...item,
        ping: result.ping,
        lastCheckedAt: nowIso()
      });
    } else {
      fail.push({
        proxy: item.proxy,
        reason: result ? result.reason : "NO_RESULT"
      });
    }
  }

  const finalItems = writeVerified(keep);

  const failText = [
    `TOTAL_PROXY=${list.length}`,
    `TOTAL_VALID=${keep.length}`,
    `TOTAL_FAIL=${fail.length}`,
    `CHECKED_AT=${nowIso()}`,
    "",
    ...fail.map((x, i) => `${i + 1}. ${x.proxy} | ${x.reason}`)
  ].join("\n");

  fs.writeFileSync(FAIL_LOG, failText + "\n", "utf8");

  console.log(`[DONE] valid=${keep.length} fail=${fail.length}`);
  console.log(`[TOTAL VERIFIED] ${finalItems.length}`);
}

async function main() {
  ensureOutputFiles();

  if (MODE === "scan") {
    await scanNewProxies();
    return;
  }

  if (MODE === "clean") {
    await cleanInvalidProxies();
    return;
  }

  throw new Error(`Unknown mode: ${MODE}`);
}

main().catch(err => {
  console.error("[FATAL]", err);
  process.exit(1);
});
