---
name: cryptocensus
description: Audit the SSH and TLS cryptography of hosts the user owns or is authorised to test, for post-quantum readiness, with the CryptoCensus CLI. It gives a per-algorithm verdict, a 0 to 100 grade per host, a CycloneDX 1.6 CBOM and a live downgrade proof that ends in the server's signed key exchange. It also writes a post-quantum sshd fix and verifies it before and after, builds a dated migration roadmap and runs a CI gate. Use it when asked to check SSH or TLS crypto, quantum readiness or harvest-now-decrypt-later exposure, to produce a CBOM, to confirm ML-KEM or ML-DSA deployment, or to harden and verify an sshd configuration.
---

# CryptoCensus: post-quantum crypto audit for SSH and TLS

CryptoCensus is one Rust binary. It reads the algorithms a server advertises (the SSH
KEXINIT, the TLS 1.3 key share group), scores each one against cited standards, grades
every host, and proves what it claims with live tests. `scan`, `tls`, `downgrade`,
`fix` and `diff` have a `--json` mode, so you never parse coloured text. `roadmap`,
`report`, `local` and `selftest` write files or plain text.

## Rules you must follow

1. **Authorisation first.** Scan only hosts the user owns or is authorised to test.
   If you are not sure a target is in scope, ask before running anything. Never scan
   public internet addresses on your own initiative. `downgrade` is active testing:
   it opens real SSH sessions with weak proposals.
2. **A request is not approval of a file.** "Fix it", "harden it" or "make it
   post-quantum" lets you run `fix`, which only writes a config file. It does not let
   you install that file. Show the user the file and its `side_effects`, and say how
   to install it for their setup (see "Installing a fix"). Then wait for a yes to that
   exact file. If the user asks you to "prove it worked" before they approve, give the
   exact post-install commands. Say clearly that the predicted grade is not a measured
   one yet.
3. **Report what the tool measured, nothing stronger.** Quote grades, counts and
   verdicts from the JSON. A probe verdict of `accepted` is not `completed`. A server
   that offers nothing weak is not proven safe against everything. Say what you did not
   test, such as other ports, other protocols or user authentication.
4. **The AI summary is prose, not evidence.** `report --ai` and `ask` use a small local
   model. Use the engine's numbers, not the model's sentences, for every claim.
5. **One run directory per run, and always the port.** Always pass `--out <dir>` and
   `--port <p>`. The default `--out results` overwrites earlier results, and the default
   port is 22, which may be a server you were not asked to touch. `fix --out RUN` is safe:
   it only writes `RUN/fix/`. `downgrade` has no `--out`, so save its `--json` output into
   the run directory yourself.

## Setup

```bash
command -v cryptocensus || export PATH="$PATH:<repo>/target/release"
cryptocensus selftest --no-color | tail -1     # must print: self-test passed: N cases
```

If the binary is missing, build it from the repository:
`git clone https://github.com/cryptocensus/cryptocensus && cd cryptocensus && cargo build --release`
(about 20 seconds, Rust stable).

Targets are IPv4 addresses or CIDR ranges from /16 to /32, comma separated.
Hostnames are not resolved. Ranges larger than /16 are refused. `selftest`, `roadmap`,
`report` without `--ai`, and `diff` make no network connection. `report --ai` and `ask` talk
only to Ollama on 127.0.0.1.

## The audit

A whole read-only audit in one command (no fix is applied). The script sits next to
this file; for Claude Code it is installed as `~/.claude/skills/cryptocensus`:

```bash
CC_RUN_DIR=<a new directory> bash <this skill's folder>/scripts/audit.sh <targets> [ssh_port=22] [tls_port]
```

It prints one JSON document with `scan`, `tls`, `downgrade` and the file paths. It takes
one SSH port and one TLS port. For several services, run the steps below with one run
directory per SSH port. Then `tls --append` each TLS port into the run of the same host.
Or run the steps yourself:

| Step | Command | Read from the JSON |
|------|---------|--------------------|
| Inventory and grade | `cryptocensus scan --targets T --port 22 --out RUN --json` | `overall`, `hosts[].verdict`, `hosts[].counts`, `hosts[].findings` |
| TLS too | `cryptocensus tls --targets T --port 443 --out RUN --append --json` | `endpoints[].group`, `endpoints[].post_quantum` |
| Prove weakness | `cryptocensus downgrade --targets T --port 22 --json` | `hosts[].probes[].verdict`, `hosts[].counts` |
| CI gate | `cryptocensus scan ... --fail-under B --json` | `gate.pass`, exit code 1 on fail |
| Remediate (file only) | `cryptocensus fix --targets T --port 22 --out RUN --json` | `hosts[].current`, `predicted`, `drop`, `side_effects`, `file` |
| Verify after install | `cryptocensus scan ... --out RUN2 --json`, then `cryptocensus diff RUN/inventory.json RUN2/inventory.json --fail-on-regression --json` | `improvements`, `regressions`, `gate.pass` |
| Plan | `cryptocensus roadmap --out RUN` | writes `RUN/roadmap.html` and `RUN/cbom_roadmap.json` |
| Manager report | `cryptocensus report --out RUN` (add `--ai` only if Ollama runs locally) | writes `RUN/heatmap.html` and `RUN/executive_brief.md` |
| This host's config | `cryptocensus local --out RUN` | text: sshd -T, host keys, OpenSSL, the ssh client's first kex |

`--append` merges into the inventory already in `RUN`. A re-scanned host:port replaces
its old records. The SSH and TLS results of a host then share one CBOM.

Exit codes: `0` success, `1` a gate failed (`--fail-under` or `--fail-on-regression`),
`2` an error. With `--json` an error is still one JSON document:
`{"command": ..., "error": ..., "exit": 2}`.

Field by field descriptions and real examples are in `reference/json-output.md`.

## Installing a fix (only after the user approves the file)

sshd keeps the **first** value it reads for each keyword. The drop-in must therefore be
read before any other `KexAlgorithms`, `Ciphers`, `MACs` or `HostKeyAlgorithms` line.
If it is read later, nothing changes and the re-scan stays weak.

- **Debian or Ubuntu system sshd:** its `sshd_config` includes `sshd_config.d/*.conf` at
  the top. Copy the file to `/etc/ssh/sshd_config.d/00-cryptocensus.conf`, run
  `sudo sshd -t`, then `sudo systemctl reload ssh`.
- **A server started with `sshd -f FILE`** (labs, containers, a second instance):
  1. Back it up: `cp FILE FILE.bak`.
  2. Copy the drop-in to a lasting path next to FILE. An `Include` of a missing file still
     passes `sshd -t` and silently changes nothing, and run directories are often
     temporary.
  3. Make `Include <that copy>` the first line of FILE.
  4. Run `sshd -t -f FILE`, then check `sshd -T -f FILE`.
  5. Reload with `kill -HUP $(cat <its PidFile>)`.
  6. To roll back: `cp FILE.bak FILE` and reload.
- **Before approval, check offline on a staged copy:**
  `printf 'Include %s\n' <drop-in> | cat - FILE > RUN/stage.conf`, then
  `sshd -t -f RUN/stage.conf && sshd -T -f RUN/stage.conf | grep -iE '^(kexalgorithms|ciphers|macs|hostkeyalgorithms)'`.
  The output must show the post-quantum values. `sshd -t` and `sshd -T` are test modes:
  they bind no port and start nothing. Use `grep -i`, because OpenSSH 10.5 prints the
  keywords in CamelCase.
- **Then prove it:** re-scan into a new directory and run
  `diff --fail-on-regression --json`. Run `downgrade` again: the server should list no weak
  algorithm and refuse a weak-only proposal.

Side effects to tell the user, also listed in `fix --json` as `side_effects`:
- Clients without post-quantum key exchange cannot connect. sntrup761 needs OpenSSH
  8.5+, ML-KEM needs 9.9+.
- Only the `ssh-ed25519` host key is offered.
- The server itself needs OpenSSH 9.9+.
- User login keys are not touched.

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
The grade is **per host (IP), not per port**. Several services on one IP that share a run
directory are averaged together. For a grade per service, use one run directory per port,
or read `findings[].port`.

**Downgrade**: one probe is sent for every broken or legacy kex, cipher and MAC the
server lists, up to 32 per host. Each probe gets a verdict:
- `completed`: the server agreed to the weak proposal, and its key exchange reply came
  back with a valid structure and a host key signature. This is the strongest
  evidence the tool gives.
- `accepted`: the server agreed, but no signed reply came. This happens for a kex the
  probe cannot build, such as ECDH P-384 or P-521.
- `refused`: a disconnect or reset.
- `inconclusive`: no answer either way. Causes include a flood, a server still talking
  at the deadline, or a server that dropped the connection before its ident
  (MaxStartups or PerSourcePenalties).
- `not built`: no probe was possible.

`counts.agreed` counts `completed` and `accepted` together. This is not a
man-in-the-middle claim, because SSH signs both KEXINITs. The finding is what an old or
attacker-controlled client can get from the server.

**The client decides the SSH key exchange.** A server that prefers ML-KEM but still
offers classical ECDH gives a classical session to any client that prefers ECDH.
macOS's ssh does, through `/etc/ssh/crypto.conf`. Removing the fallbacks is the fix.

**Host keys.** `fix` keeps `ssh-ed25519`, so `predicted` tops out near A 93. The
post-quantum ML-DSA host key arrived in OpenSSH 10.4 as an opt-in. OpenSSH 10.4 and
10.5 name it `ssh-mldsa44-ed25519@openssh.com`; check the name with `ssh -Q key`. It is
enabled by default from 10.6. Recommend it only when the user's clients support it.

## Pitfalls

- **Exit 2 or `inconclusive` after many runs against one server:** OpenSSH 9.8+
  `PerSourcePenalties` or `MaxStartups` is dropping you. Wait, or ask the admin to
  allow the scanner. Do not report the host as safe.
- **Lab servers you start yourself:** set `PerSourcePenalties no`, or the server stops
  answering after about 16 scans.
- **Slow links:** raise `--timeout-ms` (default 1500). Lower `--concurrency` (default
  256) on fragile networks.
- `tls` names the key share group from the HelloRetryRequest. It is a prober, not a
  full TLS client. It does not read certificates.
- `inventory.json` stores `port` as a string; the `--json` documents use numbers.
- Every `scan` and `tls` run rewrites `inventory.json`, `cbom.json`, `report.html` and
  `cryptocensus.sarif` in its `--out`. With `--append` these hold everything merged so far.
- Some lab servers serve one connection and exit, such as `sshd -d` or a one-shot TLS
  server. A scan would stop them. Check the process command line first if the user said
  not to touch a server.

## What to hand back to the user

1. Scope: the targets and ports, and what was not tested.
2. Per host: grade and score, then broken, legacy and quantum-vulnerable counts with
   the worst algorithms named.
3. The downgrade proof: which weak algorithms were `completed`, `accepted` or
   `refused`.
4. TLS groups, and whether each is post-quantum.
5. If a fix was requested, report it as waiting for approval. Give:
   - the drop-in path and its predicted grade;
   - the side effects;
   - the install steps for the server's real setup (it must come first, then
     `sshd -t` and a reload);
   - the commands that will prove the fix after it is installed.
6. The files: inventory.json, cbom.json, report.html, cryptocensus.sarif.
