# OPSEC notes

bebop deanonymises hidden services by pivoting on operator misconfiguration.
Most of what it does is **passive** and **anonymous**: every request to the
target rides over Tor, and the researcher is not exposed. One feature is
different, and this document is about that difference.

## TL;DR — can the researcher be found?

**Passive / in-band pivots (default): no direct exposure to the target.**
Requests go over Tor. The clearnet *confirmation* step (fetching candidate
origin IPs and diffing them against the onion) touches third-party candidate
hosts, not the target's onion — but see "Confirmation & CI" below, because it
does reveal *your* egress IP to those candidate hosts.

**Out-of-band (OOB) callback deanon (`--oob-callback`, opt-in): YES — you can
be found.** This feature deliberately makes the target connect back to
infrastructure you control. That is a two-way interaction, and the target
operator can see your side of it. Read the whole OOB section before you enable
it.

## The out-of-band callback vector

### What it does
When enabled, bebop induces the hidden service to make an outbound request to a
listener you control (interactsh, Burp Collaborator, webhook.site, or a
self-hosted logger):

- **WordPress XML-RPC `pingback.ping`** — WordPress fetches the `sourceURI` you
  supply, server-side, to verify the link. That fetch is the callback.
- **Generic SSRF injection** (`--oob-inject`) — a URL template with `{CALLBACK}`
  substituted, for any URL-accepting parameter you have identified.

The trigger is sent **over Tor**, so the target does not see you on that leg.
When the origin dereferences the callback URL, your listener logs the origin's
real clearnet egress IP. bebop then polls your listener, registers that IP as a
candidate, and confirms it against the onion baseline.

### Why this can expose YOU
The callback URL points at **clearnet infrastructure you control**. The Tor
anonymity on the probe leg does **not** extend to the callback leg. A target
operator who watches the origin's outbound traffic, egress firewall, or DNS
will observe:

- **your callback host** (domain/IP) — if it is registered to you, funded
  through an attributable account, or reused across engagements, it identifies
  you;
- **the timing**, which they can correlate with the inbound onion request they
  just received;
- **the unique token**, tying the interaction to this specific engagement.

In other words, the same class of mistake you are exploiting — a server
revealing where it really is — is one you can make yourself the moment you ask
a hostile server to call you.

### Additional hazards
- **Honeypot / poisoning.** A hostile service can call back deliberately to
  fingerprint, scan, or flood your listener, or route the callback through a
  proxy to feed you a **decoy** source IP and poison your attribution.
- **DNS-only hits deanonymise the resolver, not the host.** A DNS interaction
  reveals the origin's *resolver* egress, which may be a shared public resolver
  (e.g. 8.8.8.8), not the origin. Do not treat a DNS hit as a host-level deanon.
- **It writes to the target.** Pingback attempts and SSRF requests are logged on
  the target side and are noisy. In many jurisdictions, inducing a server to
  make requests without authorisation is unlawful.

### If you enable it anyway
- Only against systems you are **explicitly authorised** to test.
- Use **burner** callback infrastructure that is anonymously funded, never
  reused, and has no WHOIS/hosting/DNS ties to your identity.
- Assume the operator **will** see the callback and plan accordingly.
- Treat the source IP as a lead to verify, not proof — it may be a decoy.

## Confirmation & CI (applies even without OOB)

bebop's confirmation step fetches candidate origin IPs over **clearnet** and
diffs them against the onion baseline. That request goes from wherever bebop
runs to the candidate host:

- **Locally:** your own egress IP is shown to the candidate origin. If the
  candidate is the real origin and the operator is watching, they see you
  connect. Route confirmation through a VPN/proxy you are willing to burn if
  this matters to you.
- **GitHub Actions:** the runner's egress is an attributable Microsoft/Azure IP.
  The target does not learn *your* identity from it, but the interaction is
  visible to the candidate origin and attributable to "a GitHub Actions runner".

For OOB under CI, the **trigger** still egresses over Tor; only the **poll**
touches your own listener. Poll from infrastructure you are willing to burn, and
keep your `BEBOP_OOB_*` secrets scoped to a repository you control.

### Can I use the GitHub runner itself as the callback listener?

**No.** Two independent blockers:

1. **Runners are egress-only.** GitHub-hosted runners are behind NAT, ephemeral,
   and have no inbound reachability. Nothing on the public internet — including
   the target origin — can initiate a connection *to* the runner, so the origin
   cannot "call back to the runner's IP." There is no socket you can bind that
   the target could reach.
2. **GitHub exposes no source-IP-logging surface.** Even where GitHub serves
   your content publicly (Pages, gists, raw URLs, the API), you do not get access
   logs with the client's IP. There is no GitHub endpoint you can point a
   callback at and later read "who connected." So a github.com-owned IP cannot be
   repurposed as a listener either.

What already uses GitHub's (shared Azure) egress IP: the OOB **trigger** (but
that rides over Tor), the **poll** of your own listener, and the clearnet
**confirmation** fetch (this one does show the runner's egress IP to candidate
origins — attributable to "a GitHub Actions runner", not to you personally).

To receive the callback in CI you still need an **externally reachable**
listener, and whatever hosts it is what the operator sees: an external sink
(interactsh / VPS / webhook.site / Collaborator) shows *that host's* IP, or a
tunnel from the runner (cloudflared/ngrok) shows the *tunnel provider's* IP and
is tied to your tunnel account. **The listener is the exposed leg, and it can
never be GitHub's IP** — GitHub's egress ranges are shared and not-yours, but
they are not a listener.

## Summary table

| Activity | Rides over Tor? | Exposes researcher? |
| --- | --- | --- |
| Selector extraction, engine pivots (Shodan/Censys/…) | probe over Tor; API calls are yours | API queries are attributable to your API keys, not to the target |
| Config-check path scan + origin extraction | yes | no direct target exposure |
| Candidate confirmation (clearnet fetch) | no (clearnet by design) | your/runner egress IP shown to candidate hosts |
| **OOB callback (`--oob-callback`)** | trigger yes; **callback no** | **YES — your listener is exposed to the target** |
