---
name: external-network-assessment
description: External network assessment playbook — scoped port/service/TLS discovery, known-CVE template matching, and filing validated exposure findings via analyze_network_scan (assessment only, no exploitation)
---

# External Network Assessment

Use this when the scope includes IP addresses, IP ranges (CIDR), or domains and the
goal is to find what is exposed to the internet and what is misconfigured or known
vulnerable. This is an **assessment** workflow: you observe and classify. You do not
exploit services, guess credentials, or disrupt anything.

## Hard rules

- **Scope is the authorized target list only.** Every IP/range/domain you touch must be
  in the scan scope. Do not follow redirects, certificates, DNS records, or banners to
  hosts that are not in scope. `analyze_network_scan` drops out-of-scope hosts and lists
  them: if it reports any, stop scanning them.
- **No denial of service, no brute forcing, no password guessing, no exploitation.** Do
  not run NSE scripts in the `brute`, `dos`, `exploit` or `fuzzer` categories, and avoid
  other `intrusive` scripts. The one exception is `ssl-enum-ciphers` (nmap files it under
  `intrusive` because it opens many connections, but it only performs TLS handshakes).
  Do not run nuclei templates tagged `dos`, `intrusive`, `fuzz` or `bruteforce`.
- **Rate-limit.** Production systems are fragile: use the conservative flags below.
- **Exposure is not exploitation.** An open port proves reachability. Do not claim
  "unauthenticated" or "compromised" unless you demonstrated it with a single harmless,
  read-only interaction inside scope (for example a `PING` or version query), and say
  exactly what you did.

## Workflow

1. **Confirm scope.** Re-read the targets. For a range, work host by host.
2. **Fast port discovery** (sandbox):
   `naabu -host <target> -top-ports 1000 -rate 300 -json -o naabu.jsonl`
   (use `-p -` only when the instructions ask for a full-port sweep).
3. **Service and TLS detail on the open ports only:**
   `nmap -Pn -n -sT -sV --version-light -p <ports> --script ssl-enum-ciphers,ssl-cert --host-timeout 5m -T3 -oX nmap.xml <target>`
4. **Web surface on discovered HTTP(S) ports:** `httpx` for fingerprinting, then the web
   playbooks (`load_skill` for the relevant vulnerability skills) when a web app is found.
5. **Known-vulnerability matching:**
   `nuclei -u <url-or-host:port> -severity medium,high,critical -exclude-tags dos,intrusive,fuzz,bruteforce -rl 20 -jsonl -o nuclei.jsonl`
6. **Analyse.** Call `analyze_network_scan` with the **raw** contents of `nmap.xml`,
   `naabu.jsonl` and `nuclei.jsonl` (do not summarise or edit them). It returns scoped
   candidates for exposed services, deprecated TLS, weak ciphers, expired certificates and
   template matches, each with a ready-made `validation` object.
7. **Verify, then file.** For each candidate worth reporting:
   - Sanity-check it. A nuclei match can be a false positive: re-read the matched evidence
     and, where a safe read-only check is possible, confirm it before filing.
   - File with `create_vulnerability_report`, passing the candidate's `validation` object
     **unchanged** and its `cwe` (and `cve` when given). A deterministic validator
     re-parses the raw scanner evidence; a finding whose evidence does not hold up is
     flagged unverified (or rejected in enforce mode).
   - Severity: keep the candidate's conservative severity unless you demonstrated more.
8. **Group.** Report one finding per distinct issue per host:port, not one per scanner line.

## What good findings include

- Exact host, port, protocol and the scanner command used.
- The raw scanner excerpt as evidence (the `validation.evidence` already contains it).
- Concrete remediation: close or firewall the port, restrict by source, require VPN/MFA,
  disable the deprecated protocol, renew the certificate, patch the matched software.
- Assumptions: for example "authentication state not verified".

## Do not report

- SSH/HTTP/HTTPS being open on hosts that are meant to serve them.
- Information-only nuclei matches (technology detection) unless they reveal something
  sensitive.
- Anything on a host outside the authorized scope.
