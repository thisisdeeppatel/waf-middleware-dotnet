# Firewall (WAF) — how it works

`WAFMiddleware` plus `FirewallService` decide per request: **continue the pipeline** or **403 / 429**. Tunables live in **`FirewallOptions`** (config section **`Firewall`** in `appsettings.json`).

---

## 1. Big picture

1. If the path matches an **exempt prefix** (`ExemptPathPrefixes`) → **firewall skipped**, `next` runs.
2. Otherwise middleware builds **`FirewallRequestDto`** (path, IP, UA, headers, **partner flag** from API key header).
3. **`FirewallScoringEngine`** returns a **risk score 0–100** and whether the client is a **trusted bot** (whitelist UA substring match).
4. **`FirewallService`** uses fingerprint → **Redis block** → **trusted-bot bypass** (no rate limit) → **score threshold block** → **Redis rate limit** (separate counters for **partner** vs **anonymous** caps).
5. On **Block** or **Throttle**, a structured **`FirewallAuditRecord`** is logged (IP, path, reason, score, factors) — ready to map to a DB row later.

---

## 2. Middleware (`WAFMiddleware`)

| Step | What happens |
|------|----------------|
| 1 | **Exempt paths** — prefix match (`StartsWithSegments`), case-insensitive → `next` only. |
| 2 | **DTO** — path, IP, `User-Agent`, `Accept`, `Accept-Encoding`, **`IsPartner`** if the partner header value (trimmed) exactly matches a **non-empty** entry in `PartnerApiKeys` (each entry trimmed). |
| 3 | **`GetImmediateDecisionAsync`** — if **Allow**, `next`; else write small 403/429 body (**no `next`**). |

**Fingerprint hashing** (`GenerateFingerprint`) uses **only** IP + `User-Agent` + `Accept` + `Accept-Encoding` (not path, not partner flag). **Blocklist** keys use that hash alone. **Rate-limit** keys add a tier suffix (`:p` / `:a`) so partner and anonymous traffic do not share the same counter.

---

## 3. Scoring (`FirewallScoringEngine`)

- **Blacklist** UA substring (from options) → **risk 100** (blocked if ≥ threshold unless handled earlier by Redis — see service order).
- **Whitelist** UA substring (e.g. Google/OpenAI crawlers) → **trusted bot**, **risk 0**, no rate-limit increments.
- Otherwise: **empty UA** adds risk; **partner API key** reduces risk. Result clamped **0–100**.

Threshold **`RiskScoreBlockThreshold`** (default **75**) triggers a **block** with reason **`risk_score`** or **`blacklisted_bot`** (when the factor comes from the UA blacklist).

---

## 4. Service order (`FirewallService.GetImmediateDecisionAsync`)

1. Evaluate score (once).
2. Fingerprint for Redis keys.
3. **Redis `waf:block:{fingerprint}`** → block, reason **`redis_blocklist`**, **log**.
4. **Trusted bot** → **Allow** (no Redis rate increment).
5. **Risk ≥ threshold** → block, **log**.
6. **`INCR` `waf:rl:{fingerprint}:p`** or **`waf:rl:{fingerprint}:a`** with **`RateWindow`** TTL on first hit (TTL applied only if the window is **> 0**; if `RateWindow` is invalid, expiry uses **1 minute**). Compare count to **`MaxRequestsPerWindowPartner`** or **`MaxRequestsPerWindowAnonymous`** → throttle when over cap, **log**.

---

## 5. Redis keys

| Key | Role |
|-----|------|
| `waf:block:{fingerprint}` | Exists → **403** (`redis_blocklist`). |
| `waf:rl:{fingerprint}:a` | Anonymous tier: counter + TTL window → **429** when over **`MaxRequestsPerWindowAnonymous`**. |
| `waf:rl:{fingerprint}:p` | Partner tier: same, cap **`MaxRequestsPerWindowPartner`**. |

---

## 6. Configuration

See **`FirewallOptions`** and **`appsettings.json` → `Firewall`**: exempt paths, partner header name and keys, rate limits, retry-after, threshold, whitelist/blacklist substrings.

---

## 7. Operational notes

- **Proxies:** real client IP may need forwarded headers before fingerprint matches reality.
- **Fingerprint contract:** changing DTO fields used in **`GenerateFingerprint`** changes **blocklist** keys and the base of **rate** keys. Tier suffixes (`:p` / `:a`) are fixed in code.
- **Partner key:** header value is **trimmed** and must **exactly match** a **non-empty** `PartnerApiKeys` entry after trim (case-sensitive).
