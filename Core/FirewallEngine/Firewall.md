# Firewall (WAF)

**What it does:** `WAFMiddleware` and `FirewallService` decide each request: run the pipeline, return **403**, or return **429**. Behavior is driven by **`FirewallOptions`** (bound from the **`Firewall`** section in `appsettings.json`).

**At a glance:** exempt paths skip everything. Everyone else gets a risk score (0–100), then Redis blocklist, trusted-bot short-circuit, score threshold, and tiered rate limits. **Blocks and throttles only** run enforcement logging: a **`FirewallAuditRecord`** is assembled for structured logs, an **`AccessLog`** row is written when the database succeeds, and a warning is always emitted. Allows do not hit this path.

---

## Request path

| Stage | Outcome |
|--------|---------|
| Exempt prefix | `ExemptPathPrefixes` → middleware calls `next` only; no scoring, no Redis. Empty or whitespace entries in the list are skipped. Prefix match uses `PathString.StartsWithSegments` (case-insensitive). |
| Build context | `FirewallRequestDto`: path string from `Request.Path.Value` (or `""` if null), IP from `Connection.RemoteIpAddress`, first non-empty segment for `User-Agent` / `Accept` / `Accept-Encoding`, **`IsPartner`** when the configured partner header (trimmed) exactly equals a non-empty trimmed entry in `PartnerApiKeys`. |
| Decision | `GetImmediateDecisionAsync` respects **`CancellationToken`** (`ThrowIfCancellationRequested` at entry). **Allow** → `await next(context)`; rejections **never** call `next` (auth, controllers, and later middleware do not run). |

**Fingerprint** (`GenerateFingerprint`): concatenate **`{RemoteIp}|{UserAgent}|{Accept}|{AcceptEncoding}`** (same field order as the DTO; a null `RemoteIp` contributes an **empty** segment—C# string interpolation does not emit `"null"`). UTF-8 bytes → **SHA-256** → **`Convert.ToHexString`** (64 hex chars). Path and partner flag are **not** inputs. Block keys use this value; rate keys append **`:p`** or **`:a`**.

---

## Scoring (`FirewallScoringEngine`)

Evaluation is a single pass over options lists; **order matters**.

1. **Blacklist** (`BotUserAgentBlacklistSubstrings`): first **non-empty** substring that the UA contains (case-insensitive) → score **100**, not trusted, factor `blacklisted_bot:{substring}` → return immediately.
2. **Whitelist** (`BotUserAgentWhitelistSubstrings`): same rule, first match → score **0**, **`TrustedBot: true`**, factor `whitelisted_bot:{substring}` → return.
3. **Heuristic branch:** start at **0**. If UA is null/whitespace → **+30**, factor `empty_user_agent`. If **`IsPartner`** → factor `partner_api_key`, score becomes **`max(0, score - 25)`**. Final score **`Clamp(0, 100)`**.

So a blacklisted UA never consults the whitelist; whitelist wins only when no blacklist rule matched.

**Threshold block** (`RiskScoreBlockThreshold`, default **75**): if score ≥ threshold, block reason is **`blacklisted_bot`** when **any** factor starts with **`blacklisted_bot:`** (ordinal); otherwise **`risk_score`**.

---

## Decision order (`FirewallService.GetImmediateDecisionAsync`)

The first step that commits an outcome wins; later steps are skipped.

1. Compute **`FirewallScoreSnapshot`** once (drives threshold, reasons, and audit fields).
2. Compute fingerprint string.
3. **`waf:block:{fingerprint}`** exists → **403**, **`redis_blocklist`**, enforcement log. **Runs before trusted-bot bypass** so operations can block a fingerprint even if the UA would qualify as a trusted crawler.
4. **`TrustedBot`** → **Allow**; **no** Redis rate counter increment.
5. Score ≥ **`RiskScoreBlockThreshold`** → **403**, enforcement log (reason as above).
6. Rate limit: resolve cap from **`MaxRequestsPerWindowPartner`** vs **`MaxRequestsPerWindowAnonymous`** using **`IsPartner`**. **`INCR`** the tier key; window length is **`RateWindow`** if it is **> 0**, else **1 minute**. After increment, if count **`>`** cap (strictly greater) → **429**, reason **`rate_limited`**, enforcement log, retry-after from **`ThrottleRetryAfterSeconds`**. Otherwise **Allow**.

**Redis counter TTL:** on **`StringIncrementAsync`**, expiry is applied **only when the new value is 1** and the chosen window is **> 0**—that establishes the sliding window anchor on the first hit in a new key lifetime.

---

## Redis keys

| Key | Effect |
|-----|--------|
| `waf:block:{fingerprint}` | Key exists → **403** (`redis_blocklist`). Value is irrelevant; presence is the signal. |
| `waf:rl:{fingerprint}:a` | Anonymous tier string counter; **429** when count **>** **`MaxRequestsPerWindowAnonymous`**. |
| `waf:rl:{fingerprint}:p` | Partner tier; **429** when count **>** **`MaxRequestsPerWindowPartner`**. |

---

## Enforcement logging (blocks and throttles)

For **`redis_blocklist`**, score-based blocks, and **`rate_limited`**:

- Build **`FirewallAuditRecord`** (timestamp UTC, kind `Block` / `Throttle`, IP, path, reason, risk score, UA, factors).
- **Persist:** insert **`AccessLog`** (factors stored as JSON via **`JsonSerializer.Serialize`** on the factor list, **`SignatureHash`** = fingerprint). DB errors are caught, **`LogError`** is called, and the HTTP decision is **unchanged**.
- **Always** emit a structured **`LogWarning`** with the audit fields.

Allows skip this entire block.

---

## HTTP responses (middleware)

| Action | Status | Body | Notes |
|--------|--------|------|--------|
| Block | **403** | `Forbidden` | **`ContentLength`** 9 (ASCII byte count). |
| Throttle | **429** | `Too Many Requests` | **`ContentLength`** 17; **`Retry-After`** header set to **`ThrottleRetryAfterSeconds`** as a string. |

---

## Configuration

See **`FirewallOptions`** and **`appsettings.json` → `Firewall`**: exempt paths, partner header name and keys, rate limits, **`ThrottleRetryAfterSeconds`**, threshold, whitelist/blacklist substrings. Defaults for exempt prefixes and crawler whitelist exist in code if not overridden.

---

## Operations

**Proxies:** the IP in the DTO should reflect the real client; if you terminate TLS or sit behind a proxy, forwarded headers must be applied *before* this middleware or fingerprints and blocks will not line up with clients.

**Fingerprint changes:** any change to the raw string format, field order, or hashing in **`GenerateFingerprint`** changes all derived Redis keys until TTL expiry or manual deletion. Tier suffixes **`:p`** / **`:a`** are fixed in code.

**Partner keys:** comparison is trimmed, exact, and case-sensitive against non-empty trimmed entries in **`PartnerApiKeys`**.

**Pipeline placement:** `WAFMiddleware` is registered early (before auth and endpoints in **`Program.cs`**); that is what makes exempt paths cheap and rejections invisible to application code.
