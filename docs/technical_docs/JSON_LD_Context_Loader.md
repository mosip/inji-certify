# JSON-LD Context Loader 

This module provides a Spring Boot–managed JSON-LD `DocumentLoader` used to resolve JSON-LD `@context` IRIs during VC processing. It supports:

- **Configured context registry** (map context IRI → resource)
- Loading contexts from **classpath / file / http(s)**
- Optional remote resolution for **unknown** context IRIs
- Optional **host allowlist** for remote fetching
- **Startup preload** of configured contexts
- In-memory **cache** with TTL + max entry limit

---

## Feature Design

### Problem
JSON-LD processing frequently requires fetching remote `@context` documents (e.g., W3C VC contexts). Fetching contexts at runtime introduces:

- latency and dependency on external services
- reliability issues (external downtime, DNS, network)
- security risk (untrusted remote contexts → outbound calls / SSRF-style risks)

### Design Goals
1. Prefer **local (classpath) contexts** for standard well-known IRIs.
2. Allow **explicit opt-in** for remote contexts.
3. Support **unknown context IRIs** only when explicitly enabled.
4. Provide **host allowlisting** for remote access in production.
5. Improve runtime performance via **preload + caching**.
6. Avoid startup failure if preload fails (warn + continue).

### Resolution Flow (High-level)
When JSON-LD asks for a context IRI:

1. **Cache lookup** — return immediately if cached (and cache is enabled)
2. **Configured context** — if IRI is present in `mosip.certify.jsonld.contexts`:
    - load its configured `resource` (classpath, file, or remote URL)
    - cache it if enabled
3. **Unmapped context** — IRI not in the registry:
    - if `remote.enabled=false` → **reject** (remote fetching disabled entirely)
    - if host is in `allowedHosts` → **allow** (trusted host, regardless of `allowUnknown`)
    - if `allowUnknown=true` → **allow** (open mode, any host)
    - otherwise → **reject** (host not trusted and unknown contexts not allowed)
    - result is cached if cache is enabled

---

## Configuration

All configuration is under:

`mosip.certify.jsonld.*`

### Cache

| Property | Default | Description |
|---|---:|---|
| `mosip.certify.jsonld.cache.enabled` | `true` | Enable in-memory cache |
| `mosip.certify.jsonld.cache.maxEntries` | `256` | Max cached entries (0 = unlimited) |
| `mosip.certify.jsonld.cache.ttl` | `24h` | Cache TTL (0 = never expires) |

Example:
```properties
mosip.certify.jsonld.cache.enabled=true
mosip.certify.jsonld.cache.maxEntries=512
mosip.certify.jsonld.cache.ttl=24h
```

### Remote fetching

| Property | Default | Description |
|---|---:|---|
| `mosip.certify.jsonld.remote.enabled` | `true` | Enable HTTP(S) remote fetching |
| `mosip.certify.jsonld.remote.allowUnknown` | `false` | Allow unknown context IRIs (not in registry) |
| `mosip.certify.jsonld.remote.maxRedirects` | `5` | Maximum number of HTTP redirects to follow (0 = no redirects allowed) |

### Host allowlist (recommended for production)

The allowlist serves two roles:

1. **Unmapped context gating** — a host listed in `allowedHosts` is treated as trusted. Unmapped contexts from that host are allowed even when `allowUnknown=false`.
2. **Redirect validation** — during remote fetching, each redirect hop is validated against `allowedHosts`. This check is **not** bypassed by `allowUnknown=true`; it always applies when `allowedHosts` is non-empty. This prevents SSRF via open redirects.

If `allowedHosts` is empty, it provides no positive trust signal for unmapped contexts, and no redirect restriction is applied.

| Property | Default | Description |
|---|---:|---|
| `mosip.certify.jsonld.remote.allowedHosts[...]` | empty | Trusted remote hosts. If non-empty: unmapped contexts from listed hosts are allowed, and redirect hops are restricted to listed hosts. If empty: no host-level trust signal for unmapped contexts, and no redirect restriction. |

Example:
```properties
mosip.certify.jsonld.remote.allowedHosts[0]=www.w3.org
mosip.certify.jsonld.remote.allowedHosts[1]=w3id.org
```

> **Important:** Setting `allowedHosts` is strongly recommended for production.
> It lets you allow specific partner domains without opening up to all hosts via `allowUnknown=true`.

---

## Context Registry (`contexts[]`)

Each configured context maps an IRI to:

- `resource` (classpath/file/http(s))
- `preload` (load at startup)
- `cache` (per-entry cache enable)

Example:
```properties
# VC Data Model context (local)
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].resource=classpath:/contexts/credentials-v1.jsonld
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].preload=true
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].cache=true

# Ed25519Signature2020 context (local)
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].resource=classpath:/contexts/security-v1.jsonld
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].preload=true
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].cache=true

# Custom context (remote, from inji-config)
mosip.certify.jsonld.contexts[https\://inji.github.io/inji-config/contexts/farmer-context.json].resource=https://inji.github.io/inji-config/contexts/farmer-context.json
mosip.certify.jsonld.contexts[https\://inji.github.io/inji-config/contexts/farmer-context.json].preload=false
mosip.certify.jsonld.contexts[https\://inji.github.io/inji-config/contexts/farmer-context.json].cache=true
```

---

## Behavior (Detailed)

### Preload
- Any context entry with `preload=true` is loaded at startup.
- Preload errors are logged at WARN and do **not** stop application startup.

### Caching
Caching occurs only if:
- `cache.enabled=true` AND
- entry has `cache=true` (for unknown remote contexts, caching is always enabled when cache is enabled)

Cache TTL behavior:
- `ttl=0` ⇒ no expiry
- `ttl>0` ⇒ expires after TTL, and will reload on next request

Cache maxEntries behavior:
- If `maxEntries > 0` and cache is full, new IRIs are **not added** (existing cached IRIs still served)

### Remote unknown contexts
If a VC references a context IRI not present in `contexts[]`:
- Host in `allowedHosts` → **allowed** regardless of `allowUnknown` setting
- `allowUnknown=true` → **allowed** for any host (open mode; `allowedHosts` is irrelevant for initial request gating)
- `allowUnknown=false` + host NOT in `allowedHosts` → **rejected**

Note: Redirect hops during remote fetching are **always** validated against `allowedHosts` (when non-empty), regardless of the `allowUnknown` setting. See the [Decision Matrix](#decision-matrix) for details.

---

## Decision Matrix

How `remote.enabled`, `allowedHosts`, and `allowUnknown` interact for **unmapped context IRIs** (not in the `contexts[]` registry):

| `remote.enabled` | Host in `allowedHosts` | `allowUnknown` | Result |
|:-:|:-:|:-:|---|
| `false` | * | * | **REJECT** — remote fetching disabled |
| `true` | yes | `false` | **ALLOW** — host is trusted |
| `true` | yes | `true` | **ALLOW** — host is trusted (and open mode) |
| `true` | no | `true` | **ALLOW** — open mode trusts all hosts |
| `true` | no | `false` | **REJECT** — host not trusted, unknown not allowed |

For **redirect hops** during remote fetching (applies to both configured and unmapped contexts).
`allowUnknown` has **no effect** on redirect validation — redirects are always checked against `allowedHosts`:

| `allowedHosts` | Host in list | Result |
|:-:|:-:|---|
| empty | * | **ALLOW** — no restriction configured |
| non-empty | yes | **ALLOW** — host is listed |
| non-empty | no | **REJECT** — redirect to untrusted host |

---

## Edge Cases and Notes

### 1) IRI exact match required
The loader matches context IRI keys exactly as strings (after `URI.normalize()`).
If you see unexpected "No configured mapping", check:
- trailing slash differences
- fragment (`#`) presence
- http vs https

> If needed, implement canonicalization (strip fragment, trailing slash normalization).

### 2) Interaction between `allowUnknown` and `allowedHosts`
These two settings work together, not independently:
- `allowUnknown=false` + `allowedHosts=[X,Y]` → only hosts X and Y are allowed for unmapped contexts
- `allowUnknown=false` + `allowedHosts=[]` (empty) → NO unmapped contexts allowed (most restrictive)
- `allowUnknown=true` → ALL hosts allowed for unmapped contexts; `allowedHosts` has no gating effect on the initial request
- **Redirect hops** are always validated against `allowedHosts` when the list is non-empty — `allowUnknown` does **not** bypass redirect checks. This prevents SSRF via open redirects even in "open mode".

### 3) Remote resource in `contexts[]`
If a configured context uses a remote `resource=https://...`, it will still be subject to `remote.enabled` and allowlist constraints.

---

## Production Guide

### Recommended production setup (secure + stable)

1) Prefer local copies of well-known contexts:
- `https://www.w3.org/2018/credentials/v1`
- `https://w3id.org/security/suites/ed25519-2020/v1`

2) Keep unknown contexts disabled unless necessary:
```properties
mosip.certify.jsonld.remote.allowUnknown=false
```

3) If partner/custom contexts need remote fetching (preferred approach):
- Keep `allowUnknown=false` (don't open to all hosts)
- Add partner domains to `allowedHosts`
- Redirect hops are always validated against `allowedHosts` (SSRF protection)
```properties
mosip.certify.jsonld.remote.enabled=true
mosip.certify.jsonld.remote.allowUnknown=false
mosip.certify.jsonld.remote.maxRedirects=5
mosip.certify.jsonld.remote.allowedHosts[0]=www.w3.org
mosip.certify.jsonld.remote.allowedHosts[1]=w3id.org
mosip.certify.jsonld.remote.allowedHosts[2]=<partner-domain>
```

4) If you truly need open mode (development/testing only):
```properties
mosip.certify.jsonld.remote.allowUnknown=true
# allowedHosts is irrelevant for initial request gating in this mode.
# However, redirect hops are STILL checked against allowedHosts if configured.
```

5) Cache + preload critical contexts:
```properties
mosip.certify.jsonld.cache.enabled=true
mosip.certify.jsonld.cache.ttl=24h

mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].preload=true
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].preload=true
```

### Security considerations
Allowing unknown remote contexts from arbitrary domains can enable:
- outbound request abuse (SSRF-style patterns)
- performance degradation due to large/slow responses
- external dependency fragility

**Always prefer allowlisted hosts** and explicit registry entries.

### Observability
- Preload failures log at WARN
- Cache-full events log at WARN

---

## Testing

Unit tests cover:
- configured local contexts
- configured remote contexts
- unknown context resolution allowed/blocked
- allowlist allow/deny behavior (including `allowUnknown=false` + host in `allowedHosts`)
- **redirect validation**: redirect to allowed host, redirect to blocked host, redirect blocked even with `allowUnknown=true`
- **`maxRedirects`**: configurable limit respected, zero means no redirects allowed
- caching: hit/miss/TTL/maxEntries
- preload success/failure
- invalid JSON, missing resources, IO exceptions

Run:
```bash
mvn clean test -pl certify-service -am -Dtest="StaticContextLoaderTest" -Dsurefire.failIfNoSpecifiedTests=false -Dgpg.skip=true
```

---

## Example Full Configuration (Reference)

```properties
# Cache
mosip.certify.jsonld.cache.enabled=true
mosip.certify.jsonld.cache.maxEntries=512
mosip.certify.jsonld.cache.ttl=24h

# Remote context resolution
mosip.certify.jsonld.remote.enabled=true
# Keep allowUnknown=false in production; use allowedHosts to trust specific domains
mosip.certify.jsonld.remote.allowUnknown=false
mosip.certify.jsonld.remote.maxRedirects=5
mosip.certify.jsonld.remote.allowedHosts[0]=www.w3.org
mosip.certify.jsonld.remote.allowedHosts[1]=w3id.org
mosip.certify.jsonld.remote.allowedHosts[2]=inji.github.io

# Context registry
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].resource=classpath:/contexts/credentials-v1.jsonld
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].preload=true
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].cache=true

mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].resource=classpath:/contexts/security-v1.jsonld
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].preload=true
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].cache=true

# Remote context — registered explicitly so it can be preloaded/cached independently
mosip.certify.jsonld.contexts[https\://inji.github.io/inji-config/contexts/farmer-context.json].resource=https://inji.github.io/inji-config/contexts/farmer-context.json
mosip.certify.jsonld.contexts[https\://inji.github.io/inji-config/contexts/farmer-context.json].preload=false
mosip.certify.jsonld.contexts[https\://inji.github.io/inji-config/contexts/farmer-context.json].cache=true
```

---

## Quick Start Scenarios

### Scenario A: Locked-down production (only well-known contexts)

All contexts served from classpath. No remote fetching needed.

```properties
mosip.certify.jsonld.remote.enabled=false

mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].resource=classpath:/contexts/credentials-v1.jsonld
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].preload=true

mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].resource=classpath:/contexts/security-v1.jsonld
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].preload=true
```

Any context IRI not in the registry will be rejected immediately.

### Scenario B: Production with partner contexts

Partner hosts are trusted, but arbitrary hosts are not.

```properties
mosip.certify.jsonld.remote.enabled=true
mosip.certify.jsonld.remote.allowUnknown=false
mosip.certify.jsonld.remote.allowedHosts[0]=www.w3.org
mosip.certify.jsonld.remote.allowedHosts[1]=w3id.org
mosip.certify.jsonld.remote.allowedHosts[2]=partner.example.com
```

With this configuration:
- Well-known contexts (W3C VC, Ed25519) are served from classpath via the default registry
- A VC referencing `https://partner.example.com/context/v1` (not in the registry) will be fetched remotely because the host is in `allowedHosts`
- A VC referencing `https://evil.example.com/context` will be rejected (host not allowed, `allowUnknown=false`)

### Scenario C: Development / testing (open mode)

Any context from any host is allowed. Suitable only for local development.

```properties
mosip.certify.jsonld.remote.enabled=true
mosip.certify.jsonld.remote.allowUnknown=true
# allowedHosts is irrelevant for initial request gating in open mode — all hosts are trusted.
# However, if allowedHosts IS set, redirect hops are still validated against it (SSRF protection).
```

### Scenario D: Adding a new credential type context

If your VC type uses `https://partner.example.com/context/v1`, you have three options:

**Option 1 (most reliable):** Add to registry with a local copy:
```properties
mosip.certify.jsonld.contexts[https\://partner.example.com/context/v1].resource=classpath:/contexts/partner-v1.jsonld
mosip.certify.jsonld.contexts[https\://partner.example.com/context/v1].preload=true
mosip.certify.jsonld.contexts[https\://partner.example.com/context/v1].cache=true
```
Bundle the JSON-LD file in your classpath. No remote dependency at runtime.

**Option 2:** Add to registry with a remote resource:
```properties
mosip.certify.jsonld.contexts[https\://partner.example.com/context/v1].resource=https://partner.example.com/context/v1
mosip.certify.jsonld.contexts[https\://partner.example.com/context/v1].preload=false
mosip.certify.jsonld.contexts[https\://partner.example.com/context/v1].cache=true
```
The context is fetched remotely but goes through the configured-context path (tier 2), not the unmapped path. Still subject to `remote.enabled` and redirect-hop host validation.

**Option 3:** Don't add to registry, just allow the host:
```properties
mosip.certify.jsonld.remote.allowedHosts[N]=partner.example.com
```
The context IRI is not in the registry, so it goes through the unmapped-context path (tier 3). Because the host is in `allowedHosts`, it is allowed even with `allowUnknown=false`. This is the simplest option but provides no preload or per-entry cache control.
