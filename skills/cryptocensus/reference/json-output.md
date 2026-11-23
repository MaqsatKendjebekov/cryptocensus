# CryptoCensus JSON output

Pass `--json` to `scan`, `tls`, `downgrade`, `fix` or `diff`. stdout then carries exactly
one JSON document; the human view goes to stderr without colour. The examples below are
real runs against two lab servers on 127.0.0.1 (a weak one on 2224, a post-quantum one on
2223 and 4443), shortened with "... N more".

A grade is always an object `{"grade": "A".."F", "score": 0..100}`.
Categories are `broken`, `legacy-classical`, `quantum-vulnerable` and `pq-ready`.
Ports are numbers here; `inventory.json` on disk stores them as strings.

## Errors

Exit code 2 with one document. Nothing answering is never graded and never passes a gate.

```json
{"command": "scan", "error": "no SSH service answered; nothing graded, previous results kept", "exit": 2}
```

## scan

`overall`: the grade of all parameters together. `parameters`: how many were read.
`hosts[]`: `host`, `ports`, `verdict` (grade), `counts` per category, and `findings`
(every non-pq-ready parameter with its `service`, `port`, `ctype`, `value`, `category`
and `source`). `files`: where the inventory, the CBOM, the HTML report and the SARIF
went. `gate`: `null`, or `{"threshold", "pass"}` when `--fail-under` was given (a
failed gate also exits 1).

```json
{
  "command": "scan",
  "files": {
    "cbom": "RUN/cbom.json",
    "inventory": "RUN/inventory.json",
    "report": "RUN/report.html",
    "sarif": "RUN/cryptocensus.sarif"
  },
  "gate": {
    "pass": false,
    "threshold": "B"
  },
  "hosts": [
    {
      "counts": {
        "broken": 3,
        "legacy-classical": 2,
        "pq-ready": 1,
        "quantum-vulnerable": 6
      },
      "findings": [
        {
          "category": "quantum-vulnerable",
          "ctype": "kex",
          "port": 2224,
          "service": "ssh",
          "source": "NIST IR 8547",
          "value": "curve25519-sha256"
        },
        {
          "category": "quantum-vulnerable",
          "ctype": "kex",
          "port": 2224,
          "service": "ssh",
          "source": "NIST IR 8547",
          "value": "diffie-hellman-group14-sha256"
        },
        "... 9 more"
      ],
      "host": "127.0.0.1",
      "ports": [
        2224
      ],
      "verdict": {
        "grade": "F",
        "score": 32
      }
    }
  ],
  "overall": {
    "grade": "F",
    "score": 32
  },
  "parameters": 12,
  "port": 2224
}
```

## tls

The same fields as `scan` for the inventory now in `--out`, plus `endpoints[]` (`host`,
`port`, `group` is the TLS 1.3 key share group the server chose, `category`,
`post_quantum`) and `appended`. With `--append` the inventory holds SSH and TLS
together, as in this example (SSH on 2223 and TLS on 4443, 10 parameters, one CBOM).

```json
{
  "appended": true,
  "command": "tls",
  "endpoints": [
    {
      "category": "pq-ready",
      "group": "X25519MLKEM768",
      "host": "127.0.0.1",
      "port": 4443,
      "post_quantum": true
    }
  ],
  "files": {
    "cbom": "PQ/cbom.json",
    "inventory": "PQ/inventory.json",
    "report": "PQ/report.html",
    "sarif": "PQ/cryptocensus.sarif"
  },
  "hosts": [
    {
      "counts": {
        "broken": 0,
        "legacy-classical": 0,
        "pq-ready": 10,
        "quantum-vulnerable": 0
      },
      "findings": [],
      "host": "127.0.0.1",
      "ports": [
        2223,
        4443
      ],
      "verdict": {
        "grade": "A",
        "score": 100
      }
    }
  ],
  "overall": {
    "grade": "A",
    "score": 100
  },
  "parameters": 10,
  "port": 4443
}
```

## downgrade

`hosts[]`: `host`, `answered`, `probes[]` and `counts`. Each probe has `ctype`, `weak`,
`category`, the `kex`, `cipher` and `mac` actually proposed, and a `verdict`.
`counts` has `agreed` (completed plus accepted), `completed`, `refused`,
`inconclusive` and `not_probed` (over the cap of 32).

Verdicts:
- `completed`: the server agreed, and its key exchange reply came back with a valid
  structure and a host key signature.
- `accepted`: the server agreed, no signed reply.
- `refused`: disconnect or reset.
- `inconclusive`: no answer either way.
- `not built`: no probe was possible.

The weak server:

```json
{
  "command": "downgrade",
  "counts_note": "agreed counts completed and accepted probes together",
  "hosts": [
    {
      "answered": true,
      "counts": {
        "agreed": 5,
        "completed": 5,
        "inconclusive": 0,
        "not_probed": 0,
        "refused": 0
      },
      "host": "127.0.0.1",
      "probes": [
        {
          "category": "broken",
          "cipher": "aes128-ctr",
          "ctype": "kex",
          "kex": "diffie-hellman-group1-sha1",
          "mac": "hmac-sha2-256",
          "verdict": "completed",
          "weak": "diffie-hellman-group1-sha1"
        },
        {
          "category": "legacy-classical",
          "cipher": "aes128-cbc",
          "ctype": "cipher",
          "kex": "curve25519-sha256",
          "mac": "hmac-sha2-256",
          "verdict": "completed",
          "weak": "aes128-cbc"
        },
        "... 3 more"
      ]
    }
  ],
  "port": 2224,
  "verdicts": {
    "accepted": "the server agreed to the weak proposal, no signed reply",
    "completed": "the server agreed to the weak proposal and sent its signed key exchange reply",
    "inconclusive": "no answer either way",
    "refused": "disconnect or reset"
  }
}
```

A host that lists nothing weak has empty `probes` and a `weak_only_proposal` verdict.
That verdict is the server's answer to DH-group1 + 3DES + MD5:

```json
{
  "command": "downgrade",
  "counts_note": "agreed counts completed and accepted probes together",
  "hosts": [
    {
      "answered": true,
      "counts": {
        "agreed": 0,
        "completed": 0,
        "inconclusive": 0,
        "not_probed": 0,
        "refused": 0
      },
      "host": "127.0.0.1",
      "note": "the server lists no broken or legacy kex, cipher or MAC",
      "probes": [],
      "weak_only_proposal": "refused"
    }
  ],
  "port": 2223,
  "verdicts": {
    "accepted": "the server agreed to the weak proposal, no signed reply",
    "completed": "the server agreed to the weak proposal and sent its signed key exchange reply",
    "inconclusive": "no answer either way",
    "refused": "disconnect or reset"
  }
}
```

## fix

`hosts[]`: `host`, `current` and `predicted` grades, `drop` (what the generated config
removes), `kept` (weak but kept on purpose, for example the ed25519 host key), `file`
(the sshd drop-in it wrote), `side_effects` (tell the user before they approve),
`install` (sshd keeps the first value it reads, so the file must come first) and `next`
(the post-install proof with the right port). Nothing
is installed: that is the user's decision.

```json
{
  "command": "fix",
  "hosts": [
    {
      "current": {
        "grade": "F",
        "score": 32
      },
      "drop": [
        {
          "category": "quantum-vulnerable",
          "ctype": "kex",
          "value": "curve25519-sha256"
        },
        {
          "category": "quantum-vulnerable",
          "ctype": "kex",
          "value": "diffie-hellman-group14-sha256"
        },
        "... 8 more"
      ],
      "file": "RUN/fix/127.0.0.1_00-cryptocensus.conf",
      "host": "127.0.0.1",
      "install": "sshd keeps the first value it reads: the file must be included before any other KexAlgorithms, Ciphers, MACs or HostKeyAlgorithms line; check with sshd -T | grep -iE '^(kexalgorithms|ciphers|macs|hostkeyalgorithms)' before reloading",
      "kept": [
        {
          "category": "quantum-vulnerable",
          "ctype": "hostkey",
          "value": "ssh-ed25519"
        }
      ],
      "predicted": {
        "grade": "A",
        "score": 93
      },
      "side_effects": [
        "clients need sntrup761 (OpenSSH 8.5+) or ML-KEM (OpenSSH 9.9+) key exchange; older clients cannot connect",
        "only the ssh-ed25519 host key is offered; a client that accepts only RSA or ECDSA host keys cannot connect",
        "... 1 more"
      ]
    }
  ],
  "next": "after approval: install the drop-in first in the config, sshd -t, reload, then cryptocensus scan --targets <host> --port 2224 --out <new dir> and cryptocensus diff <old dir>/inventory.json <new dir>/inventory.json --fail-on-regression",
  "port": 2224
}
```

## diff

`improvements` and `regressions`. A regression is any of these:
- a non-pq-ready algorithm was added;
- the last pq-ready algorithm of a kind was lost;
- a score fell;
- a host vanished.

Also `added[]`, `removed[]`, `hosts[]` with `before` and `after` grades (null when the
host is missing on one side), and `gate`. With `--fail-on-regression`, a failed gate
exits 1. This example is before and after installing the fix:

```json
{
  "added": [
    {
      "category": "pq-ready",
      "ctype": "cipher",
      "host": "127.0.0.1",
      "port": 2224,
      "value": "aes256-ctr"
    },
    {
      "category": "pq-ready",
      "ctype": "cipher",
      "host": "127.0.0.1",
      "port": 2224,
      "value": "aes256-gcm@openssh.com"
    },
    "... 6 more"
  ],
  "after": "RUN2/inventory.json",
  "before": "RUN/inventory.json",
  "command": "diff",
  "gate": {
    "fail_on_regression": true,
    "pass": true
  },
  "hosts": [
    {
      "after": {
        "grade": "A",
        "score": 93
      },
      "before": {
        "grade": "F",
        "score": 32
      },
      "host": "127.0.0.1"
    }
  ],
  "improvements": 19,
  "regressions": 0,
  "removed": [
    {
      "category": "broken",
      "ctype": "cipher",
      "host": "127.0.0.1",
      "port": 2224,
      "value": "3des-cbc"
    },
    {
      "category": "legacy-classical",
      "ctype": "cipher",
      "host": "127.0.0.1",
      "port": 2224,
      "value": "aes128-cbc"
    },
    "... 9 more"
  ]
}
```
