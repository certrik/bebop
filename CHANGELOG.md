# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] - 2026-07-17

A round of API-deprecation fixes plus a substantial deanonymization upgrade:
bebop now gathers pivots across seven+ intelligence engines, correlates them
into ranked candidate origins, and automatically confirms the winners against
the onion baseline.

### Added

#### Intelligence sources
- **Modat Magnify** integration as a new enrichment engine (Pro-tier
  features). Pivots on body hash (`web.html.sha256`), page title (`web.title`),
  domains, TLS certificate serial, and certificate subject/issuer common names
  (`cert.subject.cn` / `cert.issuer.cn`).
- **Validin** integration as a passive-DNS and host-response pivot source
  (resolutions plus hash/certificate/JARM pivots).

#### Deanonymization techniques
- **Config-check origin extraction**: matched misconfiguration leaks are now
  mined for the origin's real addressing (public IPs, `SERVER_ADDR`, Prometheus
  `instance=` labels, Consul addresses, internal hostnames in DB/URL strings).
  Extracted IPs/hostnames are registered as correlation candidates and leaked
  public IPs are confirmed directly against the onion baseline — turning the
  passive path scan into an active deanonymisation pivot. The check list is
  comprehensive (360+ paths) and supports non-GET vectors: GraphQL/Hasura
  introspection, Elasticsearch `_search`/`_sql`, and WordPress XML-RPC method
  enumeration (pingback SSRF vector) all issue `POST` probes.
- **Correlation & confirmation layer** (`app/correlate.py`): fuses
  selector→candidate edges from every engine, ranks candidate origins by the
  number of *independent* selector categories pointing at them, then confirms
  each candidate by fetching it over clearnet and diffing body hash, title, and
  server against the onion baseline. Verdicts: `CONFIRMED`, `LIKELY`, `WEAK`,
  `NO_MATCH`, `UNREACHABLE`.
- **Reverse-resolution second-order pivot**: candidate origin IPs are fed into
  `finddomains` so urlscan / VirusTotal / SecurityTrails / Validin
  reverse-resolve them into associated domains, which are then confirmed
  against the onion and folded back into the ranking (bounded by `max_ips` /
  `max_domains` to respect resolver rate limits).
- **JARM active TLS fingerprinting** (`app/jarm.py`): computes a JARM hash over
  Tor and pivots it across Shodan, ZoomEye, Modat, Censys, and Validin.
- **Content-leak & attribution module** (`app/contentleak.py`): detects
  clearnet resources loaded by an onion page, outbound clearnet links,
  `Onion-Location` headers, canonical/alternate links, embedded PGP public
  keys, and contact emails, plus a full-body hash pivot (mmh3 / md5 / sha1 /
  sha256).
- **Certificate CN pivots** via Modat: a self-signed hidden service often
  reuses a distinctive CN across the operator's clearnet infrastructure, and a
  CA-issued cert's subject CN is the origin hostname itself.

#### Workflow
- **http→https protocol fallback**: when the scheme is auto-assumed, a failed
  `http://` fetch is retried over `https://`, engaging the downstream
  certificate and TLS/JARM branches for https-only onions.

### Changed
- **ZoomEye** integration migrated to the v2 API.
- **Censys** integration migrated to the Platform (v3) API, using the correct
  dataset split — `web.endpoints.http.*` for headers, title, and favicon;
  `host.services.*` for certificate, serial, and JARM.
- Certificate and TLS/JARM probing now route through the Tor SOCKS proxy with
  `rdns=True`, so `.onion` names resolve over Tor instead of failing.
- Path-based config checks no longer fail TLS verification on the self-signed
  certificates that hidden services typically present.
- Cryptocurrency address matches are validated with base58check and
  bech32/bech32m checksums before triggering blockchain lookups, eliminating
  false-positive wallet hits.
- GitHub Actions bumped to Node 24 action releases (`checkout@v5`,
  `upload-artifact@v6`), and the Tor readiness check reworked to gate on the
  SOCKS port plus a reliable routing target instead of a rate-limited endpoint.

### Fixed
- Deprecated/broken ZoomEye and Censys API endpoints no longer error out.
- Invalid engine queries surfaced by live runs corrected: Censys header
  (`web.endpoints.http.headers` key/value), title
  (`web.endpoints.http.html_title`), and favicon
  (`web.endpoints.http.favicons.hash_md5`) fields; Modat body-hash field
  (`web.html.sha256`); embedded quotes stripped from `etag`/`server` header
  pivots.
- `getport()` returning `None` for a schemeless `https://` target no longer
  breaks certificate / JARM / TLS fingerprinting (defaults to 443).
- Favicon MD5 hashing no longer crashes on `data:` URI favicons that arrive as
  a string.
- `pyjarm` no longer clobbers logging configuration at import time.
- Broken README Mermaid diagram now renders on GitHub.
