# CryptoCensus JSON output

Pass `--json` to `scan`, `tls`, `downgrade`, `fix` or `diff`. stdout then carries exactly
one JSON document; the human view goes to stderr without colour. The examples below are
real runs against a lab server, shortened with "... N more".

A grade is always an object `{"grade": "A".."F", "score": 0..100}`.
Categories are `broken`, `legacy-classical`, `quantum-vulnerable` and `pq-ready`.

## Errors

Exit code 2 with one document:

```json
{"command": "scan", "error": "no SSH service answered; nothing graded, previous results kept", "exit": 2}
```

Nothing answering is never graded and never passes a gate.

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
    "cbom": "before/cbom.json",
    "inventory": "before/inventory.json",
    "report": "before/report.html",
    "sarif": "before/cryptocensus.sarif"
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

The same fields as `scan` for the inventory now in `--out` (with `--append` this is
SSH and TLS together), plus `endpoints[]`: `host`, `port`, `group` (the TLS 1.3 key
share group the server chose), `category` and `post_quantum`. `appended` is true when
the result was merged into an existing inventory.

```json
{
  "appended": true,
  "command": "tls",
  "endpoints": [
    {
      "category": "quantum-vulnerable",
      "group": "x25519",
      "host": "127.0.0.1",
      "port": 4444,
      "post_quantum": false
    }
  ],
  "files": {
    "cbom": "RUN/cbom.json",
    "inventory": "RUN/inventory.json"
  },
  "hosts": [
    {
      "counts": {
        "broken": 3,
        "legacy-classical": 2,
        "pq-ready": 1,
        "quantum-vulnerable": 7
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
        "... 10 more"
      ],
      "host": "127.0.0.1",
      "ports": [
        2224,
        4444
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
  "parameters": 13,
  "port": 4444
}
```

## downgrade

`hosts[]`: `host`, `answered`, `probes[]` (`ctype`, `weak`, `category`, the `kex`,
`cipher` and `mac` actually proposed, and the `verdict`), and the counts `accepted`,
`completed`, `inconclusive` and `not_probed`. A host that lists nothing weak has
`weak_only_proposal` (the verdict for a DH-group1 + 3DES + MD5 proposal) and empty
`probes`. Verdicts: `completed` (accepted, and the server's key exchange reply came
back with a valid structure and a host key signature), `accepted` (agreed, no signed
reply), `refused` (disconnect or reset), `inconclusive`, and `not built` (no probe
possible, for example a MAC test without a non-AEAD cipher).

```json
{
  "command": "downgrade",
  "hosts": [
    {
      "accepted": 5,
      "answered": true,
      "completed": 5,
      "host": "127.0.0.1",
      "inconclusive": 0,
      "not_probed": 0,
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
    "completed": "accepted, and the server sent its signed key exchange reply",
    "inconclusive": "no answer either way",
    "refused": "disconnect or reset"
  }
}
```

## fix

`hosts[]`: `host`, `current` and `predicted` grades, `drop` (what the generated config
removes), `kept` (weak but kept on purpose, for example the ed25519 host key) and
`file` (the sshd drop-in it wrote). Nothing is installed: that is the user's decision.

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
      "file": "fix/fix/127.0.0.1_99-cryptocensus.conf",
      "host": "127.0.0.1",
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
      }
    }
  ],
  "next": "review the drop-in, install it with sshd -t, re-scan, then cryptocensus diff before/inventory.json after/inventory.json --fail-on-regression",
  "port": 2224
}
```

## diff

`improvements` and `regressions` (adding a non-pq-ready algorithm, losing the last
pq-ready algorithm of a kind, a falling score or a vanished host is a regression),
`added[]`, `removed[]`, `hosts[]` with `before` and `after` grades (null when the host
is missing on one side), and `gate` (`--fail-on-regression` exits 1 when it fails).

```json
{
  "added": [
    {
      "category": "pq-ready",
      "ctype": "cipher",
      "host": "127.0.0.1",
      "port": 2223,
      "value": "aes256-ctr"
    },
    {
      "category": "pq-ready",
      "ctype": "cipher",
      "host": "127.0.0.1",
      "port": 2223,
      "value": "aes256-gcm@openssh.com"
    },
    "... 7 more"
  ],
  "after": "after/inventory.json",
  "before": "before/inventory.json",
  "command": "diff",
  "gate": {
    "fail_on_regression": true,
    "pass": false
  },
  "hosts": [
    {
      "after": {
        "grade": "A",
        "score": 100
      },
      "before": {
        "grade": "F",
        "score": 37
      },
      "host": "127.0.0.1"
    }
  ],
  "improvements": 21,
  "regressions": 2,
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
    "... 11 more"
  ]
}
```
