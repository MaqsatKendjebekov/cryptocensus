# CryptoCensus

A native crypto-posture scanner. It reads the cryptography a host advertises on
the wire, scores every algorithm for post-quantum readiness against cited
standards, grades the host, writes a CycloneDX 1.6 CBOM, proves the fix, and can
write the report with a local model. One Rust binary, dependency-light.

## Install

macOS or Linux (any distribution), no sudo:

```sh
curl -fsSL https://raw.githubusercontent.com/cryptocensus/cryptocensus/master/install.sh | sh
```

Homebrew (macOS, Linux):

```sh
brew install cryptocensus/tap/cryptocensus
```

Debian, Ubuntu, Kali (apt):

```sh
f=$(mktemp --suffix=.deb) && curl -fsSLo "$f" https://github.com/cryptocensus/cryptocensus/releases/latest/download/cryptocensus_$(dpkg --print-architecture).deb && chmod 644 "$f" && sudo apt install "$f"
```

Arch Linux on x86_64 (pacman; on aarch64 use the first command or `packaging/aur`):

```sh
f=$(mktemp --suffix=.pkg.tar.zst) && curl -fsSLo "$f" https://github.com/cryptocensus/cryptocensus/releases/latest/download/cryptocensus-x86_64.pkg.tar.zst && sudo pacman -U "$f"
```

Windows (PowerShell, no admin):

```powershell
irm https://raw.githubusercontent.com/cryptocensus/cryptocensus/master/install.ps1 | iex
```

Anywhere with Rust:

```sh
cargo install --git https://github.com/cryptocensus/cryptocensus
```

The two install scripts check the SHA-256 of the download against the release's
`SHA256SUMS` and run the binary's self-test before they install it; nothing is installed
if either fails. `CRYPTOCENSUS_VERSION=1.1.0` pins a release. The Linux binaries are static (musl), so one build
runs on every distribution. All release files are built by `release.sh`. The Windows
build compiles and links, but it has not been tested on a Windows machine yet.
`packaging/aur/` holds a `cryptocensus-bin` PKGBUILD for the AUR.

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

## First scan

```sh
cryptocensus scan  --targets 192.0.2.10 --out audit   # read and grade the server's SSH crypto
cryptocensus fix   --targets 192.0.2.10 --out audit   # hardened sshd config + the grade it reaches
cryptocensus local --out audit                        # this machine: host keys, OpenSSL, ssh client
cryptocensus report --out audit                       # HTML dashboard: audit/heatmap.html
```

Only scan systems you own or are allowed to test.

Under the grade table the scan names every algorithm by verdict, says what the menu
means (including what the ssh client on your machine would negotiate, or that it cannot
connect at all), and prints the next command. A default Ubuntu 24.04 server (OpenSSH 9.6p1),
scanned from a Mac:

```
  host             grade  readiness   broken legacy quantum pq   bar
  ------------------------------------------------------------------------------
  192.0.2.10        D       57/100       0      4      16   10   ██████████████████████████████
  ------------------------------------------------------------------------------
  OVERALL network readiness  D  57/100   (30 params, 1 hosts)

  findings 192.0.2.10:22 ssh  SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20
    legacy    4  mac: umac-64-etm@openssh.com, hmac-sha1-etm@openssh.com, umac-64@openssh.com, hmac-sha1
    quantum  16  key exchange: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256,
                               ecdh-sha2-nistp384, ecdh-sha2-nistp521, diffie-hellman-group-exchange-sha256,
                               diffie-hellman-group16-sha512, diffie-hellman-group18-sha512,
                               diffie-hellman-group14-sha256
                 host key: rsa-sha2-512, rsa-sha2-256, ecdsa-sha2-nistp256, ssh-ed25519
                 cipher: aes128-ctr, aes192-ctr, aes128-gcm@openssh.com
    pq       10  key exchange: sntrup761x25519-sha512@openssh.com
                 cipher: chacha20-poly1305@openssh.com, aes256-ctr, aes256-gcm@openssh.com
                 mac: umac-128-etm@openssh.com, hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com,
                      umac-128@openssh.com, hmac-sha2-256, hmac-sha2-512
    verdict      4 legacy: deprecated, phase them out
                 post-quantum key exchange offered, but 9 classical one(s) too, and the client picks
                 no ML-KEM: the ML-KEM-768 (FIPS 203) + X25519 hybrid needs OpenSSH 9.9 or later
                 from this machine, ssh would negotiate ecdh-sha2-nistp256 [quantum-vulnerable]
                 host key classical only: fine for now, it matters for live attacks, not recorded traffic
    next         cryptocensus fix --targets 192.0.2.10 --port 22 --out audit   hardened config + the grade it reaches
                 cryptocensus downgrade --targets 192.0.2.10 --port 22   proves the weak ones live, only on servers you may test
```

## Build from source

```sh
git clone https://github.com/cryptocensus/cryptocensus && cd cryptocensus
cargo build --release
./target/release/cryptocensus selftest
```

Pure standard library plus `serde_json`; `num-bigint`, `num-integer` and
`num-traits` are used only by the batch-GCD command. `./release.sh` builds every
release file (macOS, Linux, Windows, `.deb`, pacman package, Homebrew formula) on an
Apple Silicon Mac with Docker.

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
cryptocensus --version
```

Add `--json` to `scan`, `tls`, `downgrade`, `fix` or `diff` for machine-readable output.

Each scan writes `inventory.json`, a CycloneDX 1.6 `cbom.json`, an HTML heatmap
`report.html`, and a SARIF 2.1.0 file for CI. With `--append`, `scan` and `tls`
merge into the inventory already in `--out`, so the SSH and TLS results of the same
hosts land in one CBOM (a re-scanned host:port replaces its old records).

Exit codes: `0` success, `1` a gate failed (`--fail-under`, `--fail-on-regression`),
`2` an error, including a scan where no host answered. A scan that sees nothing is
never graded: it exits 2 and keeps the previous results.

`downgrade` sends one probe for every broken or legacy key exchange, cipher and MAC
the server lists (the policy's red and orange bands), with that algorithm alone in its
slot and the server's own non-weak choices in the others, so a server that accepts a
single weak algorithm is caught. A disconnect or reset counts
as refused. When the server agrees, the probe completes the key exchange with a
random key share (DH groups, group exchange, curve25519, curve448, P-256,
sntrup761x25519, or mlkem768x25519 with a well-formed FIPS 203 key) and waits for the
server's signed reply, so ACCEPTED means the server really ran the exchange. This
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

`ask` answers come from the same computed findings and are advisory; a wrong
worst-host answer is asked again once, and then the engine answers instead.

## Use it from an AI agent

`scan`, `tls`, `downgrade`, `fix` and `diff` take `--json`: stdout then carries one JSON
document (errors too, with `"exit": 2`), and the human view moves to stderr. The
fields are documented in `skills/cryptocensus/reference/json-output.md`.

`skills/cryptocensus/` is an agent skill (a `SKILL.md` in the open Agent Skills format):
it teaches an agent the audit workflow, how to read every verdict, and the rules (scan
only authorised hosts, never change a server without approval, report only what was
measured). `skills/cryptocensus/scripts/audit.sh <targets> [ssh_port] [tls_port]` runs a
whole read-only audit and prints one JSON summary. For Claude Code:

```
ln -s "$PWD/skills/cryptocensus" ~/.claude/skills/cryptocensus
```

## Related tools

ssh-audit rates SSH algorithms and warns on non post-quantum key exchange; pqcscan lists
which post-quantum algorithms SSH and TLS servers offer; IBM's CBOM Kit builds CBOMs from
source code. CryptoCensus aims at the verified loop on the network side: per-slot verdicts
for SSH and TLS, a CBOM, a live proof with the server's signed key exchange, a generated fix
checked against a re-scan, and a regression gate.

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

## Credits

Written by Maksat Kendjebekov. AI assistants (Claude) helped with code review and testing.
