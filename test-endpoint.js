const autocannon = require('autocannon');

const url = 'http://localhost:5232/api/auth/test-waf';

// WAF reads User-Agent (and Accept / Accept-Encoding for fingerprint). Match FirewallOptions lists:
// - Whitelist substrings (e.g. Googlebot) → trusted bot, no Redis rate-limit counter
// - Blacklist → block; empty UA → higher risk score
const ua = {
  chrome:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  googlebot: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
};

const defaults = {
  url,
  connections: 10,
  duration: 20,
  pipelining: 1,
};

function logNumericSummary(label, result) {
  const codes = result.statusCodeStats
    ? Object.entries(result.statusCodeStats)
        .map(([code, s]) => `${code}:${s.count}`)
        .join(' ')
    : 'n/a';

  console.log(`\n--- ${label} — summary ---`);
  console.log(
    `  errors: ${result.errors}  timeouts: ${result.timeouts}  mismatches: ${result.mismatches}  non2xx: ${result.non2xx}`
  );
  console.log(
    `  by class: 1xx=${result['1xx']} 2xx=${result['2xx']} 3xx=${result['3xx']} 4xx=${result['4xx']} 5xx=${result['5xx']}`
  );
  console.log(`  statusCodeStats: ${codes}`);
}

/**
 * Runs autocannon, prints full tables (incl. per-status counts), logs once when errors start.
 */
async function runScenario(label, overrides = {}) {
  const opts = { ...defaults, ...overrides };
  const instance = autocannon(opts);

  let benchT0 = Date.now();
  let firstHttpErrorLogged = false;
  let firstReqErrorLogged = false;

  instance.on('start', () => {
    benchT0 = Date.now();
  });

  instance.on('response', (_client, statusCode) => {
    if (statusCode < 400 || firstHttpErrorLogged) return;
    firstHttpErrorLogged = true;
    const ms = Date.now() - benchT0;
    console.error(`\n>>> [${label}] first HTTP error: ${statusCode} (~${ms}ms after benchmark start)`);
    if (statusCode === 403) console.error('    hint: WAF block / Forbidden');
    if (statusCode === 429) console.error('    hint: WAF throttle / Too Many Requests');
  });

  instance.on('reqError', (err) => {
    if (firstReqErrorLogged) return;
    firstReqErrorLogged = true;
    console.error(`\n>>> [${label}] first request error (socket/timeout): ${err.message}`);
  });

  const result = await instance;

  console.log(`\n${'='.repeat(64)}\n  ${label}\n${'='.repeat(64)}`);
  process.stdout.write(
    autocannon.printResult(result, {
      renderStatusCodes: true,
      outputStream: process.stdout,
    })
  );
  logNumericSummary(label, result);

  return result;
}

/** Browser-like UA — normal path: Redis rate limit + fingerprint use this UA string. */
async function baseline() {
  return runScenario('baseline', {
    headers: { 'user-agent': ua.chrome },
  });
}

/** Matches whitelist (e.g. Googlebot) — WAF treats as trusted crawler: no rate-limit INCR. */
async function asTrustedCrawler() {
  return runScenario('asTrustedCrawler', {
    headers: { 'user-agent': ua.googlebot },
  });
}

/** Empty User-Agent — WAF scores empty_user_agent (+30 risk; still under default block threshold unless other rules hit). */
async function emptyUserAgent() {
  return runScenario('emptyUserAgent', {
    headers: { 'user-agent': '' },
  });
}

async function highConcurrency() {
  return runScenario('highConcurrency', {
    connections: 50,
    headers: { 'user-agent': ua.chrome },
  });
}

async function pipelined() {
  return runScenario('pipelined', {
    pipelining: 10,
    headers: { 'user-agent': ua.chrome },
  });
}

async function shortBurst() {
  return runScenario('shortBurst', {
    duration: 5,
    connections: 20,
    headers: { 'user-agent': ua.chrome },
  });
}

async function runAll() {
  await baseline();
  await asTrustedCrawler();
  await emptyUserAgent();
  await highConcurrency();
  await pipelined();
  await shortBurst();
}

// Uncomment one:
//baseline();
// asTrustedCrawler();
//emptyUserAgent();
// runAll();
