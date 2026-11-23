# CryptoCensus

A native crypto-posture scanner. It reads the cryptography a host advertises on
the wire, scores every algorithm for post-quantum readiness against cited
standards, grades the host, writes a CycloneDX 1.6 CBOM, proves the fix, and can
write the report with a local model. One Rust binary, dependency-light.

CryptoCensus is not a port scanner. It speaks SSH at the protocol level: after
the version exchange a server sends its `SSH_MSG_KEXINIT` in the clear, listing
every key exchange, host key, cipher and MAC it supports. CryptoCensus reads that
packet directly (no nmap, no key exchange), so a whole /24 takes about a second
and a half.

![CryptoCensus demo: a weak and a fully post-quantum server scanned, a real OpenSSH client check, the Mac client finding and the live downgrade test](docs/demo.gif)

The `report` command writes a self-contained HTML dashboard: the grade, the
readiness bands, a summary (written by the local model and checked against the
engine with `--ai`, a deterministic template without it), and the engine-computed
remediation plan.

![The HTML dashboard for a two-host lab](docs/dashboard.png)

## Quick start

```
git clone https://github.com/MaqsatKendjebekov/cryptocensus && cd cryptocensus
cargo build --release
./target/release/cryptocensus selftest
./target/release/cryptocensus scan --targets 192.168.56.0/24 --out results
./target/release/cryptocensus report --out results     # then open results/heatmap.html
```

## Build

```
cargo build --release
./target/release/cryptocensus selftest
```

Pure standard library plus `serde_json`; `num-bigint`, `num-integer` and
`num-traits` are used only by the batch-GCD command.

## Readiness bands

Every algorithm is placed in one of four bands, each cited to a standard in
`policy.json`:

- `broken`: unsafe today with no quantum computer (RC4, 3DES, MD5, ssh-dss, 1024-bit DH).
- `legacy-classical`: deprecated, phase out (AES-CBC, ssh-rsa). HMAC-SHA1 and 64-bit-tag
  UMAC are here by a project rule in line with ssh-audit's warnings; NIST SP 800-131A
  still allows HMAC-SHA-1.
- `quantum-vulnerable`: safe today, broken by Shor later (curve25519, ECDH, RSA, ed25519).
  AES-128 is here too by a project rule stricter than NIST: Grover weakens it, it
  is not broken, and CNSA 2.0 asks for AES-256.
- `pq-ready`: believed safe against a quantum computer (ML-KEM, sntrup761, ML-DSA
  host keys, AES-256-GCM, ChaCha20-Poly1305, SHA-2 MACs).

Sources: NIST SP 800-131A, the NIST IR 8547 draft, NIST FIPS 203 and 204, RFC 8439,
OpenSSH release notes (sntrup761 is not a NIST standard).

## Commands

```
cryptocensus scan      --targets <IPs|CIDR> [--out ./results] [--fail-under A|B|C|D]
cryptocensus tls       --targets <IPs|CIDR> --port 443
cryptocensus fix       --targets <IPs|CIDR>        generate a post-quantum sshd config + predicted grade
cryptocensus diff      <before.json> <after.json> [--fail-on-regression]
cryptocensus local                                host configuration: sshd -T, host keys, openssl, ssh client
cryptocensus downgrade --targets <IPs|CIDR>        active test: will the server really use each weak algorithm
cryptocensus shor      [--factor N | --rsa-demo --rsa-n N | --resource BITS]
cryptocensus batchgcd  [--keys N] [--bits B]       shared-prime key recovery (Mining your Ps and Qs)
cryptocensus roadmap   [--out ./results]           dated PQ migration plan (Mosca, knapsack, topo sort)
cryptocensus report    [--ai] [--out ./results]    executive brief and heatmap from an inventory
cryptocensus ask       "<question>" [--out ./results]
cryptocensus bench     --targets <IPs|CIDR> [--nmap]
cryptocensus selftest
```

Each scan writes `inventory.json`, a CycloneDX 1.6 `cbom.json`, an HTML heatmap
`report.html`, and a SARIF 2.1.0 file for CI.

Exit codes: `0` success, `1` a gate failed (`--fail-under`, `--fail-on-regression`),
`2` an error, including a scan where no host answered. A scan that sees nothing is
never graded: it exits 2 and keeps the previous results.

`downgrade` sends one probe for every broken or legacy key exchange, cipher and MAC
the server lists (the policy's red and orange bands), with that algorithm alone in its
slot and the server's own non-weak choices in the others, so a server that accepts a
single weak algorithm is caught. A disconnect or reset counts
as refused; accepted means the connection stays open, waiting for the client's key
exchange message, and it is only reported for an algorithm the server listed. This
shows what an old or attacker-controlled client gets. It is not a man-in-the-middle
claim: SSH signs both KEXINITs into the exchange hash.

`local` also reports the ssh client's first key exchange choice. SSH negotiates the
client's first preference that the server supports, and macOS ships
`/etc/ssh/crypto.conf` with `KexAlgorithms ^ecdh-sha2-nistp256`, so a Mac gets
classical ECDH from any server that still offers it, even when both sides support
ML-KEM. Removing the server's classical fallbacks is what forces ML-KEM.

## Post-quantum host keys

OpenSSH 10.4 added the ML-DSA-44 + Ed25519 host key (`ssh-mldsa44-ed25519`) as an
opt-in, and 10.6 enables it by default. `fix` keeps `ssh-ed25519` so older clients
can still connect, and the generated drop-in explains how to add the ML-DSA key. A
server with an ML-KEM key exchange, AES-256 or ChaCha20 ciphers, SHA-2 MACs and only
an ML-DSA host key grades A 100/100.

## The AI layer

`report --ai` and `ask` use a local model (llama3.2:3b via Ollama on
127.0.0.1). The model only writes the summary paragraph: the grade, every count,
the CBOM and the remediation plan are computed by the engine. The summary is checked
against the engine at runtime (it must name the same worst host) and is rejected
otherwise, with one retry and then a deterministic template. The same template is
used if the model is not running, so the command never fails. Nothing leaves the
host.

```
ollama serve &
ollama pull llama3.2:3b
cryptocensus scan --targets 127.0.0.1 --out results
cryptocensus report --ai --out results
cryptocensus ask "which host is the worst and why?" --out results
```

`ask` answers come from the same computed findings and are advisory.

## Testing against OpenSSH 9.8 or newer

OpenSSH 9.8+ penalises clients that connect repeatedly without logging in
(`PerSourcePenalties`), which is what a scanner does. A test server you scan many
times should set `PerSourcePenalties no`; otherwise it stops answering and the scan
reports "no SSH service answered" (exit 2).

## Limitations

It reads the crypto a service advertises, so it sees SSH and TLS on the wire; the
`local` command adds the host configuration (effective sshd config, host keys,
OpenSSL version, ssh client preference), but it does not see crypto buried inside
application code. The scoring
is a reasonable reading of the standards, not a formal proof.

## Status

Built as an Applied Security capstone. Everything was tested in an isolated lab.
Run it only against hosts you own or are authorised to test.
