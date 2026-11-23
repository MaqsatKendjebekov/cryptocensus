---
name: cryptocensus
description: Audit the SSH and TLS cryptography of hosts the user owns or is authorised to test, for post-quantum readiness, with the CryptoCensus CLI. It gives a per-algorithm verdict, a 0 to 100 grade per host, a CycloneDX 1.6 CBOM and a live downgrade proof that ends in the server's signed key exchange. It also writes a post-quantum sshd fix and verifies it before and after, builds a dated migration roadmap and runs a CI gate. Use it when asked to check SSH or TLS crypto, quantum readiness or harvest-now-decrypt-later exposure, to produce a CBOM, to confirm ML-KEM or ML-DSA deployment, or to harden and verify an sshd configuration.
---

# CryptoCensus: post-quantum crypto audit for SSH and TLS

CryptoCensus is one Rust binary. It reads the algorithms a server advertises (the SSH
KEXINIT, the TLS 1.3 key share group), scores each one against cited standards, grades
every host, and proves what it claims with live tests. Every command below has a
`--json` mode, so you never parse coloured text.

## Rules you must follow

1. **Authorisation first.** Scan only hosts the user owns or is authorised to test.
   If you are not sure a target is in scope, ask before running anything. Never scan
   public internet addresses on your own initiative. `downgrade` is active testing:
   it opens real SSH sessions with weak proposals.
2. **Never change a server without explicit approval.** `fix` only writes a config file.
   Installing it, reloading sshd or editing anything on a host is the user's decision.
   Show them the file and the predicted grade, then wait.
3. **Report what the tool measured, nothing stronger.** Quote grades, counts and
   verdicts from the JSON. A downgrade verdict of `accepted` is not `completed`. A
   server that offers nothing weak is not proven safe against everything. Say what
   you did not test, such as other ports, other protocols or the host configuration.
4. **The AI summary is prose, not evidence.** `report --ai` and `ask` use a small local
   model. Use the engine's numbers, not the model's sentences, for every claim.
5. **One run directory per run.** Always pass `--out <dir>`. The default `--out results`
   overwrites earlier results.

## Setup

```bash
command -v cryptocensus || export PATH="$PATH:<repo>/target/release"
cryptocensus selftest | tail -1      # must print: self-test passed: N cases
```

If the binary is missing, build it from the repository:
`git clone https://github.com/MaqsatKendjebekov/cryptocensus && cd cryptocensus && cargo build --release`
(about 20 seconds, Rust stable).

Targets are IPv4 addresses or CIDR ranges from /16 to /32, comma separated.
Hostnames are not resolved. Ranges larger than /16 are refused.

## The audit, step by step

A whole read-only audit in one command (no fix is applied):

```bash
bash <skill dir>/scripts/audit.sh <targets> [ssh_port=22] [tls_port]
```

It prints one JSON summary and the run directory. Or run the steps yourself:

| Step | Command | Read from the JSON |
|------|---------|--------------------|
| Inventory and grade | `cryptocensus scan --targets T --port 22 --out RUN --json` | `overall`, `hosts[].verdict`, `hosts[].counts`, `hosts[].findings` |
| TLS too | `cryptocensus tls --targets T --port 443 --out RUN --append --json` | `endpoints[].group`, `endpoints[].post_quantum` |
| Prove weakness | `cryptocensus downgrade --targets T --port 22 --json` | `hosts[].probes[].verdict`, `accepted`, `completed` |
| CI gate | `cryptocensus scan ... --fail-under B --json` | `gate.pass`, exit code 1 on fail |
| Remediate (approval) | `cryptocensus fix --targets T --port 22 --out RUN --json` | `hosts[].current`, `predicted`, `drop`, `file` |
| Verify after the fix | `cryptocensus scan ... --out RUN2 --json`, then `cryptocensus diff RUN/inventory.json RUN2/inventory.json --fail-on-regression --json` | `improvements`, `regressions`, `gate.pass` |
| Plan | `cryptocensus roadmap --out RUN` | writes `RUN/roadmap.html` and `RUN/cbom_roadmap.json` |
| Manager report | `cryptocensus report --out RUN` (add `--ai` only if Ollama runs locally) | writes `RUN/heatmap.html` and `RUN/executive_brief.md` |
| This host's config | `cryptocensus local --out RUN` | text: sshd -T, host keys, OpenSSL, the ssh client's first kex |

`--append` merges into the inventory already in `RUN`. A re-scanned host:port replaces
its old records. The SSH and TLS results of a host then share one CBOM.

Exit codes: `0` success, `1` a gate failed (`--fail-under` or `--fail-on-regression`),
`2` an error. With `--json` an error is still one JSON document:
`{"command": ..., "error": ..., "exit": 2}`.

Field by field descriptions and real examples are in `reference/json-output.md`.

## How to interpret the results

**Bands** (from the policy, every rule cites a source):
- `broken`: unsafe today, no quantum computer needed (RC4, 3DES, Blowfish, CAST, MD5
  MACs, DSA, 1024-bit DH).
- `legacy-classical`: deprecated, phase out (CBC ciphers, ssh-rsa SHA-1 signatures).
  HMAC-SHA1 and 64-bit-tag UMAC are here by a project rule in line with ssh-audit.
  NIST SP 800-131A still allows HMAC-SHA-1, so say "phase out", not "broken".
- `quantum-vulnerable`: safe today, broken by a large quantum computer. This covers
  RSA, ECDH, X25519 and Ed25519, which Shor breaks. It also covers AES-128 and AES-192,
  which Grover only weakens. Putting AES-128/192 here is a project rule stricter
  than NIST, which accepts AES-128 as post-quantum Category 1.
- `pq-ready`: believed quantum-safe (ML-KEM, sntrup761 hybrids, ML-DSA host keys,
  AES-256, ChaCha20-Poly1305, SHA-2 MACs).

**Grade**: 100 x (1 - average penalty), with penalties broken 1, legacy 0.8,
quantum-vulnerable 0.6 and pq-ready 0. A is 90 or more, B 80, C 65, D 50, F below 50.

**Downgrade verdicts**, per probe. One probe is sent for every broken or legacy kex,
cipher and MAC the server lists:
- `completed`: the server accepted the weak proposal, and its key exchange reply came
  back with a valid structure and a host key signature. This is the strongest
  evidence the tool gives.
- `accepted`: the server agreed, but no signed reply came. This happens for a kex the
  probe cannot build, such as ECDH P-384 or P-521.
- `refused`: a disconnect or reset.
- `inconclusive`: no answer either way. Causes include a flood, a server still
  talking at the deadline, or a server that dropped the connection before its ident
  (MaxStartups or PerSourcePenalties).

This is not a man-in-the-middle claim. SSH signs both KEXINITs. The finding is what
an old or attacker-controlled client can get from the server.

**The client decides the SSH key exchange.** A server that prefers ML-KEM but still
offers classical ECDH gives a classical session to any client that prefers ECDH.
macOS's ssh does, through `/etc/ssh/crypto.conf`. Removing the fallbacks is the fix.

**Host keys.** `fix` keeps `ssh-ed25519`, so `predicted` tops out near A 93. The
post-quantum `ssh-mldsa44-ed25519` arrived in OpenSSH 10.4 as an opt-in and is
enabled by default from 10.6. Recommend it only when the user's clients support it.

## Pitfalls

- **Exit 2 or `inconclusive` after many runs against one server:** OpenSSH 9.8+
  `PerSourcePenalties` or `MaxStartups` is dropping you. Wait, or ask the admin to
  allow the scanner. Do not report the host as safe.
- **Lab servers you start yourself:** set `PerSourcePenalties no`, or the server stops
  answering after about 16 scans.
- **Slow links:** raise `--timeout-ms` (default 1500). Lower `--concurrency` (default
  256) on fragile networks.
- `downgrade` probes at most 32 weak algorithms per host and says how many it skipped.
- `tls` names the key share group from the HelloRetryRequest. It is a prober, not a
  full TLS client. It does not read certificates.

## What to hand back to the user

1. Scope: the targets and ports, and what was not tested.
2. Per host: grade and score, then broken, legacy and quantum-vulnerable counts with
   the worst algorithms named.
3. The downgrade proof: which weak algorithms were `completed`, `accepted` or
   `refused`.
4. TLS groups, and whether each is post-quantum.
5. The fix: the drop-in file path and the predicted grade, waiting for approval.
6. The files: inventory.json, cbom.json, report.html, cryptocensus.sarif.
