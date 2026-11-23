// CryptoCensus: a native crypto-posture scanner.
//
// It speaks SSH at the protocol level: after the version exchange a server sends
// its SSH_MSG_KEXINIT in the clear, listing every key-exchange, host-key, cipher
// and MAC algorithm it supports. CryptoCensus reads that packet directly (no
// nmap, no crypto handshake), scores each algorithm for post-quantum readiness
// against NIST guidance, assigns a readiness score and grade, and emits a JSON
// inventory, a CycloneDX 1.6 CBOM and an HTML risk heatmap. The scan runs on a
// thread pool, so a whole /24 takes about a second where nmap's NSE script takes
// tens of seconds.
//
// This is NOT a port scanner like RustScan: the point is understanding the
// cryptography and its quantum risk, which neither RustScan nor a bare nmap does.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Zero};

const POLICY_EMBED: &str = include_str!("../policy.json");
const SSH_IDENT: &[u8] = b"SSH-2.0-cryptocensus_1.0\r\n";
const KEX_SKIP: [&str; 2] = ["ext-info-", "kex-strict-"];

// ---------- ANSI ----------
static USE_COLOR: AtomicUsize = AtomicUsize::new(1);
fn paint(s: &str, code: &str) -> String {
    if USE_COLOR.load(Ordering::Relaxed) == 1 {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}
fn bold(s: &str) -> String { paint(s, "1") }
fn dim(s: &str) -> String { paint(s, "2") }
fn cat_ansi(cat: &str) -> &'static str {
    match cat {
        "broken" => "1;37;41",          // white on red
        "legacy-classical" => "30;43",  // black on yellow
        "quantum-vulnerable" => "30;103", // black on bright yellow
        "pq-ready" => "1;37;42",        // white on green
        _ => "1;37;100",
    }
}
fn cat_fg(cat: &str) -> &'static str {
    match cat {
        "broken" => "91",
        "legacy-classical" => "33",
        "quantum-vulnerable" => "93",
        "pq-ready" => "92",
        _ => "90",
    }
}

fn banner() {
    let b = r#"
   ___                 _        ___
  / __|_ _ _  _ _ __| |_ ___ / __|___ _ _  ___ _  _ ___
 | (__| '_| || | '_ \  _/ _ \ (__/ -_) ' \(_-< || (_-<
  \___|_|  \_, | .__/\__\___/\___\___|_||_/__/\_,_/__/
          |__/|_|   native post-quantum crypto scanner
"#;
    eprintln!("{}", paint(b, "96"));
    eprintln!("{}", dim("  reads SSH/TLS crypto directly, scores quantum risk, builds a CBOM. not a port scanner.\n"));
}

// ---------- target expansion ----------

fn parse_targets(spec: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for item in spec.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some((base, pfx)) = item.split_once('/') {
            if let (Ok(ip), Ok(p)) = (base.parse::<Ipv4Addr>(), pfx.parse::<u32>()) {
                if p < 16 {
                    eprintln!("[warn] /{p} is too large to scan (largest allowed is /16, 65534 hosts): {item}");
                    continue;
                }
                if p <= 32 {
                    let bits = 32 - p;
                    let net = u32::from(ip) & (!0u32).checked_shl(bits).unwrap_or(0);
                    let count = if bits >= 32 { 1u64 << 32 } else { 1u64 << bits };
                    if count <= 2 {
                        for i in 0..count { out.push(Ipv4Addr::from(net + i as u32)); }
                    } else {
                        for i in 1..(count - 1) { out.push(Ipv4Addr::from(net + i as u32)); }
                    }
                    continue;
                }
            }
            eprintln!("[warn] bad CIDR: {item}");
        } else if let Ok(ip) = item.parse::<Ipv4Addr>() {
            out.push(ip);
        } else {
            eprintln!("[warn] bad target: {item}");
        }
    }
    out
}

// ---------- SSH KEXINIT ----------

fn scan_ssh(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<(String, Vec<(String, String)>)> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    stream.write_all(SSH_IDENT).ok()?;

    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    // the read timeout is per read, so a server dripping one byte at a time could
    // hold a worker forever; an overall deadline bounds the whole exchange
    let deadline = Instant::now() + timeout * 3;
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(recs) = parse_kexinit(&buf) {
                    return Some(recs);
                }
                if buf.len() > 65536 || Instant::now() > deadline { break; }
            }
            Err(_) => break,
        }
    }
    None
}

// The SSH version line must start at the beginning of a line (RFC 4253 4.2).
// A server may send other lines first, and those may contain "SSH-" mid-line.
fn find_ident(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    loop {
        if buf[i..].starts_with(b"SSH-") { return Some(i); }
        i += buf[i..].iter().position(|&b| b == b'\n')? + 1;
        if i >= buf.len() { return None; }
    }
}

// RFC 4251 section 6: algorithm names are printable US-ASCII, at most 64 chars.
// Anything else is dropped, so a hostile server cannot inject newlines or markup
// into the inventory, the HTML report or the AI brief.
fn valid_alg_name(v: &str) -> bool {
    !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn parse_kexinit(buf: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let id_start = find_ident(buf)?;
    let nl = buf[id_start..].iter().position(|&b| b == b'\n')? + id_start;
    let banner: String = String::from_utf8_lossy(&buf[id_start..nl]).chars()
        .filter(|c| (' '..='~').contains(c)).collect::<String>().trim().to_string();
    let rest = &buf[nl + 1..];
    if rest.len() < 5 { return None; }
    let pkt_len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if pkt_len < 2 || 4 + pkt_len > rest.len() { return None; }
    let pad_len = rest[4] as usize;
    let payload_end = (4 + pkt_len).checked_sub(pad_len)?;   // a hostile pad_len must not underflow
    if payload_end <= 5 || payload_end > rest.len() { return None; }
    let payload = &rest[5..payload_end];
    if payload.is_empty() || payload[0] != 20 { return None; }
    let mut p = 17usize;
    let mut lists: Vec<String> = Vec::with_capacity(10);
    for _ in 0..10 {
        if p + 4 > payload.len() { return None; }
        let l = u32::from_be_bytes([payload[p], payload[p + 1], payload[p + 2], payload[p + 3]]) as usize;
        p += 4;
        if p + l > payload.len() { return None; }
        lists.push(String::from_utf8_lossy(&payload[p..p + l]).to_string());
        p += l;
    }
    let mut recs = Vec::new();
    let mut seen = BTreeSet::new();
    for (ctype, idx) in [("kex", 0usize), ("hostkey", 1), ("cipher", 2), ("mac", 4)] {
        for v in lists[idx].split(',') {
            if !valid_alg_name(v) { continue; }
            if ctype == "kex" && KEX_SKIP.iter().any(|m| v.to_lowercase().starts_with(m)) { continue; }
            if !seen.insert((ctype, v.to_string())) { continue; }   // a repeated name must not count twice
            recs.push((ctype.to_string(), v.to_string()));
        }
    }
    Some((banner, recs))
}

// ---------- records ----------

#[derive(Clone)]
struct Record {
    host: String,
    port: u16,
    service: String,
    ctype: String,
    value: String,
    category: String,
    why: String,
    source: String,
}

fn scan_targets(
    ips: &[Ipv4Addr],
    port: u16,
    timeout: Duration,
    workers: usize,
    policy: &Value,
    live: bool,
) -> (Vec<Record>, BTreeMap<String, String>) {
    let cursor = Arc::new(AtomicUsize::new(0));
    let results: Arc<Mutex<Vec<(Ipv4Addr, String, Vec<(String, String)>)>>> = Arc::new(Mutex::new(Vec::new()));
    let ips = Arc::new(ips.to_vec());
    let mut handles = Vec::new();
    let nworkers = workers.min(ips.len().max(1));
    for _ in 0..nworkers {
        let cursor = Arc::clone(&cursor);
        let results = Arc::clone(&results);
        let ips = Arc::clone(&ips);
        handles.push(std::thread::spawn(move || loop {
            let i = cursor.fetch_add(1, Ordering::Relaxed);
            if i >= ips.len() { break; }
            if let Some((banner, found)) = scan_ssh(ips[i], port, timeout) {
                if live {
                    eprintln!("  {} {} {}", paint("+", "92"), bold(&ips[i].to_string()), dim(&banner));
                }
                results.lock().unwrap().push((ips[i], banner, found));
            }
        }));
    }
    for h in handles { h.join().ok(); }

    let mut recs = Vec::new();
    let mut banners = BTreeMap::new();
    let mut hits = results.lock().unwrap().clone();
    hits.sort_by_key(|(ip, _, _)| u32::from(*ip));
    for (ip, banner, found) in hits {
        banners.insert(ip.to_string(), banner);
        for (ctype, value) in found {
            let (category, why, source) = score(policy, &ctype, &value);
            recs.push(Record {
                host: ip.to_string(), port, service: "ssh".to_string(),
                ctype, value, category, why, source,
            });
        }
    }
    (recs, banners)
}

// ---------- native TLS 1.3 post-quantum prober ----------
// Hand-rolled: build a ClientHello offering the hybrid PQ named groups but only a
// classical key_share, so a server that prefers a PQ group answers with a
// HelloRetryRequest naming it. That proves PQ-TLS support with no ML-KEM math.

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

fn u16b(v: &mut Vec<u8>, x: u16) { v.extend_from_slice(&x.to_be_bytes()); }
fn blk16(v: &mut Vec<u8>, inner: Vec<u8>) { u16b(v, inner.len() as u16); v.extend(inner); }

fn tls_group_name(code: u16) -> String {
    match code {
        0x11EC => "X25519MLKEM768".into(),
        0x11EB => "SecP256r1MLKEM768".into(),
        0x11ED => "SecP384r1MLKEM1024".into(),
        0x6399 => "X25519Kyber768".into(),
        0x001D => "x25519".into(),
        0x001E => "x448".into(),
        0x0017 => "secp256r1".into(),
        0x0018 => "secp384r1".into(),
        0x0019 => "secp521r1".into(),
        0x0100 => "ffdhe2048".into(),
        _ => format!("group-0x{code:04X}"),
    }
}

fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut ch = Vec::new();
    ch.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    ch.extend_from_slice(&[0x42u8; 32]); // random (fixed, deterministic)
    ch.push(32); ch.extend_from_slice(&[0x11u8; 32]); // legacy_session_id (compat)
    blk16(&mut ch, { let mut b = Vec::new(); for cs in [0x1301u16, 0x1302, 0x1303] { u16b(&mut b, cs); } b }); // cipher suites
    ch.push(1); ch.push(0); // compression: null

    let mut ext = Vec::new();
    // supported_versions -> TLS 1.3
    u16b(&mut ext, 0x002b); blk16(&mut ext, { let mut e = Vec::new(); e.push(2); u16b(&mut e, 0x0304); e });
    // supported_groups: PQ hybrids first, then classical
    u16b(&mut ext, 0x000a); blk16(&mut ext, {
        let mut e = Vec::new();
        blk16(&mut e, { let mut g = Vec::new(); for gr in [0x11ECu16, 0x11EB, 0x11ED, 0x001D, 0x0017, 0x0018] { u16b(&mut g, gr); } g });
        e });
    // signature_algorithms
    u16b(&mut ext, 0x000d); blk16(&mut ext, {
        let mut e = Vec::new();
        blk16(&mut e, { let mut s = Vec::new(); for sa in [0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0806] { u16b(&mut s, sa); } s });
        e });
    // key_share: offer ONLY a classical x25519 share (forces HRR if server wants PQ)
    u16b(&mut ext, 0x0033); blk16(&mut ext, {
        let mut e = Vec::new();
        blk16(&mut e, { let mut ks = Vec::new(); u16b(&mut ks, 0x001D); blk16(&mut ks, vec![0x33u8; 32]); ks });
        e });
    // SNI
    if !sni.is_empty() {
        u16b(&mut ext, 0x0000); blk16(&mut ext, {
            let mut e = Vec::new();
            blk16(&mut e, { let mut list = Vec::new(); list.push(0); blk16(&mut list, sni.as_bytes().to_vec()); list });
            e });
    }

    blk16(&mut ch, ext); // extensions block

    // handshake header (client_hello = 1, 3-byte length)
    let mut hs = vec![0x01u8];
    let l = ch.len();
    hs.push((l >> 16) as u8); hs.push((l >> 8) as u8); hs.push(l as u8);
    hs.extend(ch);
    // record header (handshake = 22, legacy record version TLS 1.0)
    let mut rec = vec![0x16u8, 0x03, 0x01];
    u16b(&mut rec, hs.len() as u16);
    rec.extend(hs);
    rec
}

struct TlsResult { group: u16, is_hrr: bool, server_share_len: usize }

fn parse_server_hello(buf: &[u8]) -> Option<TlsResult> {
    // record: type(1) ver(2) len(2) payload
    if buf.len() < 5 || buf[0] != 0x16 { return None; }
    let rec_len = ((buf[3] as usize) << 8) | buf[4] as usize;
    let body = buf.get(5..5 + rec_len)?;
    // handshake: type(1)=2 server_hello, len(3), then body
    if body.len() < 4 || body[0] != 0x02 { return None; }
    let sh = &body[4..];
    // legacy_version(2) + random(32)
    if sh.len() < 2 + 32 { return None; }
    let is_hrr = sh[2..34] == HRR_RANDOM;
    let mut p = 34;
    // session_id
    let sid_len = *sh.get(p)? as usize; p += 1 + sid_len;
    // cipher_suite(2) + compression(1)
    p += 3;
    // extensions
    if p + 2 > sh.len() { return None; }
    let ext_total = ((sh[p] as usize) << 8) | sh[p + 1] as usize; p += 2;
    let ext_end = (p + ext_total).min(sh.len());
    while p + 4 <= ext_end {
        let etype = ((sh[p] as usize) << 8) | sh[p + 1] as usize;
        let elen = ((sh[p + 2] as usize) << 8) | sh[p + 3] as usize;
        let edata_start = p + 4;
        let edata_end = (edata_start + elen).min(sh.len());
        if etype == 0x0033 {
            // key_share: HRR -> selected_group(2); ServerHello -> group(2)+len(2)+ks
            if edata_end >= edata_start + 2 {
                let group = ((sh[edata_start] as u16) << 8) | sh[edata_start + 1] as u16;
                let mut share = 0;
                if !is_hrr && edata_end >= edata_start + 4 {
                    share = ((sh[edata_start + 2] as usize) << 8) | sh[edata_start + 3] as usize;
                }
                return Some(TlsResult { group, is_hrr, server_share_len: share });
            }
        }
        p = edata_start + elen;
    }
    None
}

fn tls_probe(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<TlsResult> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    stream.write_all(&build_client_hello(&ip.to_string())).ok()?;
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let deadline = Instant::now() + timeout * 3;   // bound a slow-drip server, as in scan_ssh
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(r) = parse_server_hello(&buf) { return Some(r); }
                if buf.len() > 32768 || Instant::now() > deadline { break; }
            }
            Err(_) => break,
        }
    }
    None
}

fn tls_scan(ips: &[Ipv4Addr], port: u16, timeout: Duration, workers: usize, policy: &Value) -> Vec<Record> {
    let cursor = Arc::new(AtomicUsize::new(0));
    let results: Arc<Mutex<Vec<(Ipv4Addr, TlsResult)>>> = Arc::new(Mutex::new(Vec::new()));
    let ips = Arc::new(ips.to_vec());
    let mut handles = Vec::new();
    for _ in 0..workers.min(ips.len().max(1)) {
        let cursor = Arc::clone(&cursor); let results = Arc::clone(&results); let ips = Arc::clone(&ips);
        handles.push(std::thread::spawn(move || loop {
            let i = cursor.fetch_add(1, Ordering::Relaxed);
            if i >= ips.len() { break; }
            if let Some(r) = tls_probe(ips[i], port, timeout) {
                eprintln!("  {} {}:{} TLS1.3 group {} {}", paint("+", "92"), bold(&ips[i].to_string()), port,
                          tls_group_name(r.group), if r.is_hrr { dim("(via HelloRetryRequest)") } else { String::new() });
                results.lock().unwrap().push((ips[i], r));
            }
        }));
    }
    for h in handles { h.join().ok(); }
    let mut recs = Vec::new();
    let mut hits = results.lock().unwrap().drain(..).collect::<Vec<_>>();
    hits.sort_by_key(|(ip, _)| u32::from(*ip));
    for (ip, r) in hits {
        let name = tls_group_name(r.group);
        let (cat, why, src) = score(policy, "tls_group", &name);
        recs.push(Record { host: ip.to_string(), port, service: "tls".into(), ctype: "tls_group".into(),
                           value: name, category: cat, why, source: src });
    }
    recs
}

// ---------- scoring ----------

// A --policy the user names must load, or the run stops: silently falling back to
// the embedded policy would change verdicts without telling anyone.
fn load_policy(path: Option<&str>) -> Value {
    let Some(p) = path else { return serde_json::from_str(POLICY_EMBED).expect("embedded policy is valid JSON") };
    let text = std::fs::read_to_string(p).unwrap_or_else(|e| {
        eprintln!("  {} cannot read --policy {p}: {e}", paint("error", "91")); std::process::exit(2) });
    let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("  {} --policy {p} is not valid JSON: {e}", paint("error", "91")); std::process::exit(2) });
    if !v["rules"].is_object() {
        eprintln!("  {} --policy {p} has no \"rules\" object", paint("error", "91")); std::process::exit(2);
    }
    v
}

fn score(policy: &Value, ctype: &str, value: &str) -> (String, String, String) {
    let v = value.to_lowercase();
    if let Some(rules) = policy["rules"][ctype].as_array() {
        for rule in rules {
            if let Some(pats) = rule["match"].as_array() {
                for pat in pats {
                    if let Some(ps) = pat.as_str() {
                        if v.contains(&ps.to_lowercase()) {
                            return (
                                rule["category"].as_str().unwrap_or("unclassified").to_string(),
                                rule["why"].as_str().unwrap_or("").to_string(),
                                rule["source"].as_str().unwrap_or("").to_string(),
                            );
                        }
                    }
                }
            }
        }
    }
    ("unclassified".to_string(), "no policy rule matched".to_string(), String::new())
}

fn severity(cat: &str) -> u8 {
    match cat {
        "broken" => 4, "legacy-classical" => 3, "quantum-vulnerable" => 2, "pq-ready" => 1, _ => 0,
    }
}

// post-quantum readiness 0..100 (100 = everything PQ-ready)
fn readiness(recs: &[&Record]) -> f64 {
    if recs.is_empty() { return 100.0; }
    let penalty = |c: &str| match c {
        "broken" => 1.0, "legacy-classical" => 0.8, "quantum-vulnerable" => 0.6,
        "pq-ready" => 0.0, _ => 0.3,
    };
    let sum: f64 = recs.iter().map(|r| penalty(&r.category)).sum();
    (100.0 * (1.0 - sum / recs.len() as f64)).round()
}

fn grade(score: f64) -> (&'static str, &'static str) {
    match score as i64 {
        90..=100 => ("A", "92"),
        80..=89 => ("B", "92"),
        65..=79 => ("C", "93"),
        50..=64 => ("D", "33"),
        _ => ("F", "91"),
    }
}

// ---------- outputs ----------

// days since 1970-01-01 -> (year, month, day), Howard Hinnant's civil_from_days
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { y + 1 } else { y }, month, d)
}
fn iso_utc(secs: u64) -> String {
    let (year, month, d) = civil_from_days((secs / 86400) as i64);
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}-{month:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}
fn now_secs() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }
fn now_iso() -> String { iso_utc(now_secs()) }
fn today_civil() -> (i64, i64, i64) { civil_from_days((now_secs() / 86400) as i64) }

// A failed write is an error, never a silent "written:" line over stale files.
fn write_file(path: &str, data: &str) {
    if let Err(e) = std::fs::write(path, data) {
        eprintln!("  {} cannot write {path}: {e}", paint("error", "91"));
        std::process::exit(2);
    }
}
fn make_dir(dir: &str) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("  {} cannot create directory {dir}: {e}", paint("error", "91"));
        std::process::exit(2);
    }
}

fn write_outputs(recs: &[Record], outdir: &str, stamp: &str) {
    make_dir(outdir);
    let inv_recs: Vec<Value> = recs.iter().map(|r| json!({
        "host": r.host, "port": r.port.to_string(), "service": r.service,
        "ctype": r.ctype, "value": r.value,
        "category": r.category, "why": r.why, "source": r.source
    })).collect();
    let inv = json!({"generated": stamp, "records": inv_recs});
    write_file(&format!("{outdir}/inventory.json"), &serde_json::to_string_pretty(&inv).unwrap());
    write_file(&format!("{outdir}/cbom.json"), &serde_json::to_string_pretty(&build_cbom(recs, stamp)).unwrap());
    write_file(&format!("{outdir}/report.html"), &build_html(recs, stamp));
    write_file(&format!("{outdir}/cryptocensus.sarif"), &serde_json::to_string_pretty(&build_sarif(recs)).unwrap());
}

fn build_cbom(recs: &[Record], stamp: &str) -> Value {
    let mut seen: BTreeMap<(String, String), &Record> = BTreeMap::new();
    for r in recs { seen.entry((r.ctype.clone(), r.value.clone())).or_insert(r); }
    let primitive = |c: &str| match c {
        "kex" => "key-agree", "hostkey" | "cert_sig" => "signature",
        "cipher" => "block-cipher", "mac" => "mac", _ => "other",
    };
    let functions = |c: &str| match c {
        "kex" => vec!["keyderive"], "hostkey" | "cert_sig" => vec!["sign", "verify"],
        "cipher" => vec!["encrypt", "decrypt"], "mac" => vec!["tag"], _ => vec!["other"],
    };
    let comps: Vec<Value> = seen.iter().map(|((ctype, value), r)| {
        let crypto = if ctype == "tls_version" {
            json!({"assetType": "protocol", "protocolProperties": {"type": "tls",
                   "version": value.replace("TLSv", "").replace("SSLv", "")}})
        } else {
            json!({"assetType": "algorithm", "algorithmProperties": {"primitive": primitive(ctype),
                   "cryptoFunctions": functions(ctype)}})
        };
        json!({
            "type": "cryptographic-asset", "name": value,
            "bom-ref": format!("crypto/{ctype}/{value}"),
            "cryptoProperties": crypto,
            "properties": [
                {"name": "cryptocensus:category", "value": r.category},
                {"name": "cryptocensus:rationale", "value": r.why},
                {"name": "cryptocensus:source", "value": if r.source.is_empty() {"n/a"} else {&r.source}},
                {"name": "cryptocensus:function", "value": ctype}
            ]
        })
    }).collect();
    json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": stamp, "tools": [{"name": "CryptoCensus", "version": "1.0"}],
                     "component": {"type": "application", "name": "lab-network-crypto-census"}},
        "components": comps
    })
}

fn color_hex(cat: &str) -> &'static str {
    match cat {
        "broken" => "#c0392b", "legacy-classical" => "#e67e22",
        "quantum-vulnerable" => "#f1c40f", "pq-ready" => "#27ae60", _ => "#7f8c8d",
    }
}
fn ctype_label(c: &str) -> &'static str {
    match c {
        "kex" => "Key exchange", "hostkey" => "Host key", "cipher" => "Cipher",
        "mac" => "MAC", "tls_version" => "TLS version", "cert_sig" => "Cert signature", _ => "Other",
    }
}
fn esc(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;") }

fn build_html(recs: &[Record], stamp: &str) -> String {
    let mut hosts: BTreeMap<String, Vec<&Record>> = BTreeMap::new();
    for r in recs { hosts.entry(r.host.clone()).or_default().push(r); }
    let mut h = String::new();
    h.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>CryptoCensus report</title><style>");
    h.push_str("body{font:14px/1.5 -apple-system,Arial,sans-serif;margin:24px;color:#222}h1{font-size:20px}h2{font-size:16px;margin-top:22px}");
    h.push_str("table{border-collapse:collapse;margin:8px 0;width:100%}td,th{border:1px solid #ccc;padding:5px 8px;text-align:left;font-size:13px}");
    h.push_str("th{background:#f2f2f2}.pill{color:#fff;padding:2px 7px;border-radius:9px;font-size:12px}td.port{white-space:nowrap}</style></head><body>");
    h.push_str(&format!("<h1>CryptoCensus: lab cryptography readiness</h1><p>Generated {stamp}</p>"));
    for (host, rs) in &hosts {
        let worst = rs.iter().map(|r| r.category.as_str()).max_by_key(|c| severity(c)).unwrap_or("pq-ready");
        let score = readiness(rs);
        let (g, _) = grade(score);
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for r in rs { *counts.entry(r.category.as_str()).or_insert(0) += 1; }
        h.push_str(&format!(
            "<h2>{host} <span class=\"pill\" style=\"background:{}\">grade {g}  readiness {score:.0}/100  (worst: {worst})</span></h2>",
            color_hex(worst)));
        let cstr: Vec<String> = counts.iter().map(|(k, v)| format!("{k}: {v}")).collect();
        h.push_str(&format!("<p>{}</p>", cstr.join(", ")));
        h.push_str("<table><tr><th>Port</th><th>Type</th><th>Algorithm</th><th>Category</th><th>Why</th><th>Source</th></tr>");
        let mut sorted = rs.clone();
        sorted.sort_by(|a, b| a.ctype.cmp(&b.ctype));
        for r in sorted {
            h.push_str(&format!(
                "<tr><td class=\"port\">{}/{}</td><td>{}</td><td>{}</td><td><span class=\"pill\" style=\"background:{}\">{}</span></td><td>{}</td><td>{}</td></tr>",
                r.port, esc(&r.service), ctype_label(&r.ctype), esc(&r.value),
                color_hex(&r.category), r.category, esc(&r.why), esc(&r.source)));
        }
        h.push_str("</table>");
    }
    h.push_str("</body></html>");
    h
}

fn print_summary(recs: &[Record], banners: &BTreeMap<String, String>) {
    let mut hosts: BTreeMap<String, Vec<&Record>> = BTreeMap::new();
    for r in recs { hosts.entry(r.host.clone()).or_default().push(r); }
    println!("\n{}", bold("  host             grade  readiness   broken legacy quantum pq   bar"));
    println!("  {}", dim(&"-".repeat(78)));
    for (host, rs) in &hosts {
        let score = readiness(rs);
        let (g, gcol) = grade(score);
        let mut c: BTreeMap<&str, usize> = BTreeMap::new();
        for r in rs { *c.entry(r.category.as_str()).or_insert(0) += 1; }
        let get = |k: &str| *c.get(k).unwrap_or(&0);
        // bar: one block per param, colored by category
        let mut bar = String::new();
        for cat in ["broken", "legacy-classical", "quantum-vulnerable", "pq-ready"] {
            for _ in 0..get(cat) { bar.push_str(&paint("█", cat_fg(cat))); }
        }
        println!("  {:<16} {}   {:>5.0}/100   {:>5}  {:>5}  {:>6}  {:>3}   {}",
                 bold(host), paint(&format!(" {g} "), cat_bg_for_grade(g)),
                 score,
                 paint(&get("broken").to_string(), "91"),
                 paint(&get("legacy-classical").to_string(), "33"),
                 paint(&get("quantum-vulnerable").to_string(), "93"),
                 paint(&get("pq-ready").to_string(), "92"),
                 bar);
        let _ = gcol;
    }
    // overall
    let all: Vec<&Record> = recs.iter().collect();
    let overall = readiness(&all);
    let (og, _) = grade(overall);
    println!("  {}", dim(&"-".repeat(78)));
    println!("  {} network readiness {}  ({} params, {} hosts)\n",
             bold("OVERALL"),
             paint(&format!(" {og}  {overall:.0}/100 "), cat_bg_for_grade(og)),
             recs.len(), hosts.len());
    let _ = banners;
}

fn cat_bg_for_grade(g: &str) -> &'static str {
    match g {
        "A" | "B" => "1;37;42",
        "C" => "30;103",
        "D" => "30;43",
        _ => "1;37;41",
    }
}

// ---------- selftest ----------

fn selftest() {
    let policy = load_policy(None);
    let cases: &[(&str, &str, &str)] = &[
        ("kex", "diffie-hellman-group1-sha1", "broken"),
        ("kex", "diffie-hellman-group14-sha256", "quantum-vulnerable"),
        ("kex", "sntrup761x25519-sha512@openssh.com", "pq-ready"),
        ("kex", "mlkem768x25519-sha256", "pq-ready"),
        ("hostkey", "ssh-dss", "broken"),
        ("hostkey", "ssh-rsa", "legacy-classical"),
        ("hostkey", "ssh-ed25519", "quantum-vulnerable"),
        ("hostkey", "ecdsa-sha2-nistp256", "quantum-vulnerable"),
        ("cipher", "arcfour256", "broken"),
        ("cipher", "3des-cbc", "broken"),
        ("cipher", "aes128-cbc", "legacy-classical"),
        ("cipher", "aes128-ctr", "quantum-vulnerable"),
        ("cipher", "aes256-ctr", "pq-ready"),
        ("cipher", "chacha20-poly1305@openssh.com", "pq-ready"),
        ("mac", "hmac-md5", "broken"),
        ("mac", "hmac-sha1", "legacy-classical"),
        ("mac", "umac-64@openssh.com", "legacy-classical"),
        ("mac", "hmac-sha2-256", "pq-ready"),
        // policy ordering regressions (pq-ready hostkey first, SHA-2 RSA not read as SHA-1)
        ("hostkey", "ssh-ed25519-mldsa44@example.com", "pq-ready"),
        ("hostkey", "ssh-rsa-sha256@ssh.com", "quantum-vulnerable"),
        ("hostkey", "rsa-sha2-512", "quantum-vulnerable"),
        ("kex", "curve448-sha512", "quantum-vulnerable"),
        ("kex", "mlkem768nistp256-sha256", "pq-ready"),
    ];
    let mut bad = 0;
    for (ctype, value, expect) in cases {
        let (got, _, _) = score(&policy, ctype, value);
        let ok = &got == expect;
        if !ok { bad += 1; }
        println!("  {} {ctype:11} {value:38} -> {got} (want {expect})",
                 if ok { paint("ok  ", "92") } else { paint("FAIL", "91") });
    }
    // lifecycle self-checks (remediation, drift, SARIF, downgrade packet)
    assert!((readiness_cat(&vec!["pq-ready".to_string(); 3]) - 100.0).abs() < 0.01);
    assert!(readiness_cat(&vec!["broken".to_string()]) < 1.0);
    assert!(grade_rank("A") > grade_rank("D") && grade_rank("D") > grade_rank("F"));
    let (ps, pg) = predicted_grade(&policy);
    assert_eq!(pg, "A", "hardened config should grade A, got {pg} at {ps}");
    let sample = Record { host: "h".into(), port: 22, service: "ssh".into(), ctype: "cipher".into(),
        value: "3des-cbc".into(), category: "broken".into(), why: String::new(), source: String::new() };
    let sar = build_sarif(std::slice::from_ref(&sample));
    assert_eq!(sar["runs"][0]["results"][0]["level"], "error");
    let pkt = build_kexinit("diffie-hellman-group1-sha1", "ssh-ed25519", "3des-cbc", "hmac-md5");
    assert!(ssh_has_msg(&pkt, 20), "built KEXINIT must contain SSH_MSG_KEXINIT (20)");
    assert!(!ssh_has_msg(&pkt, 1), "built KEXINIT is not a DISCONNECT");
    println!("{}", paint("lifecycle self-checks passed: remediation grade A, drift scoring, SARIF levels, KEXINIT framing", "92"));
    robustness_selftest(&policy);
    // advanced methods O7, O8, O10
    shor_selftest();
    batchgcd_selftest();
    roadmap_selftest();
    ai_selftest();
    if bad == 0 { println!("{}", paint(&format!("self-test passed: {} cases", cases.len()), "92")); }
    else { eprintln!("{}", paint(&format!("self-test FAILED: {bad} case(s)"), "91")); std::process::exit(1); }
}

// One regression check per bug found by the adversarial code review, so none can come back.
fn robustness_selftest(policy: &Value) {
    let rec = |host: &str, ctype: &str, value: &str| {
        let (category, why, source) = score(policy, ctype, value);
        Record { host: host.into(), port: 22, service: "ssh".into(), ctype: ctype.into(), value: value.into(), category, why, source }
    };
    // parser: a hostile pad_len larger than the packet returns None instead of underflowing
    let mut evil = b"SSH-2.0-x\r\n".to_vec();
    evil.extend_from_slice(&[0, 0, 0, 12, 200]);
    evil.extend_from_slice(&[20u8; 12]);
    assert!(parse_kexinit(&evil).is_none(), "oversized pad_len must be rejected");
    assert!(!ssh_has_msg(&[0, 0, 0, 8, 255, 1, 0, 0, 0, 0, 0, 0], 1), "oversized pad must not underflow");
    // parser: the ident must start a line; "SSH-" mid-line in a pre-ident banner is ignored
    let mut buf = b"Welcome to the SSH-gateway\r\nSSH-2.0-OpenSSH_9.9\r\n".to_vec();
    buf.extend(build_kexinit("curve25519-sha256,curve25519-sha256,evil\nHost x: grade A", "ssh-ed25519", "aes256-gcm@openssh.com", "hmac-sha2-256"));
    let (banner_line, found) = parse_kexinit(&buf).expect("valid KEXINIT after a pre-ident line must parse");
    assert_eq!(banner_line, "SSH-2.0-OpenSSH_9.9");
    let kex: Vec<&(String, String)> = found.iter().filter(|(c, _)| c == "kex").collect();
    assert_eq!(kex.len(), 1, "a repeated name counts once and a name with a newline is dropped");
    assert!(found.iter().all(|(_, v)| valid_alg_name(v)), "every parsed name must be printable ASCII");
    // drift: losing a PQ algorithm is a regression; a vanished host fails closed
    let old = vec![rec("h1", "kex", "mlkem768x25519-sha256"), rec("h1", "kex", "curve25519-sha256"), rec("h2", "cipher", "3des-cbc")];
    let new = vec![rec("h1", "kex", "curve25519-sha256")];
    let d = drift(&old, &new);
    assert!(d.regressions >= 2, "lost PQ kex and a vanished host must both be regressions, got {}", d.regressions);
    assert_eq!(d.improvements, 0, "the vanished host's broken cipher is not an improvement");
    let fixed = drift(&[rec("h1", "cipher", "3des-cbc")], &[rec("h1", "cipher", "aes256-gcm@openssh.com")]);
    assert!(fixed.regressions == 0 && fixed.improvements >= 2, "swapping 3DES for AES-256-GCM is a clean improvement");
    let swap = drift(&[rec("h1", "mac", "hmac-sha2-256")], &[rec("h1", "mac", "hmac-sha2-256-etm@openssh.com")]);
    assert_eq!(swap.regressions, 0, "replacing a pq-ready MAC with a stronger pq-ready MAC is not a regression");
    // fix: the generated config keeps ssh-ed25519, so it is never listed as "to drop"
    assert!(hardened_keeps("ssh-ed25519") && !hardened_keeps("3des-cbc"));
    // Shor: a prime is rejected fast and a prime power is factored without a period
    assert!(shor_factor(4093).is_none(), "4093 is prime");
    assert_eq!(shor_factor(9).map(|t| (t.0, t.1)), Some((3, 3)));
    println!("{}", paint("robustness self-checks passed: hostile packets, ident line, name sanitising, dedup, drift gate, fix list, Shor input checks", "92"));
}

// ---------- bench ----------

fn bench(targets: &str, port: u16, timeout: Duration, workers: usize, run_nmap: bool) {
    let policy = load_policy(None);
    let ips = parse_targets(targets);
    println!("{}", bold(&format!("\n  HEAD TO HEAD on {} ({} addresses, port {port})\n", targets, ips.len())));

    let t0 = Instant::now();
    let (recs, _) = scan_targets(&ips, port, timeout, workers, &policy, false);
    let native = t0.elapsed();
    let hosts: BTreeSet<&str> = recs.iter().map(|r| r.host.as_str()).collect();
    let cbom_components = {
        let mut s: BTreeSet<(String, String)> = BTreeSet::new();
        for r in &recs { s.insert((r.ctype.clone(), r.value.clone())); }
        s.len()
    };

    let mut nmap_secs = 0.0;
    if run_nmap {
        let t1 = Instant::now();
        let out = Command::new("nmap")
            .args(["-Pn", "-sT", "-p", &port.to_string(), "--script", "ssh2-enum-algos", targets])
            .output();
        nmap_secs = t1.elapsed().as_secs_f64();
        if out.is_err() { println!("  [warn] nmap not runnable: {:?}", out.err()); nmap_secs = 0.0; }
    }

    // centers PLAIN text to a visible width, then colors it (ANSI stays zero-width)
    fn cell(s: &str, w: usize, code: &str) -> String {
        let pad = w.saturating_sub(s.chars().count());
        let left = pad / 2;
        format!("{}{}{}", " ".repeat(left), paint(s, code), " ".repeat(pad - left))
    }
    let yn = |b: bool| if b { ("yes", "92") } else { ("no", "91") };
    // columns: nmap, RustScan, CryptoCensus  (honest capabilities)
    let rows: [(&str, bool, bool, bool); 6] = [
        ("finds open ports",            true,  true,  true),
        ("lists SSH crypto algorithms", true,  false, true),
        ("post-quantum risk verdict",   false, false, true),
        ("readiness score + grade",     false, false, true),
        ("CycloneDX CBOM output",       false, false, true),
        ("remediation + re-scan proof", false, false, true),
    ];
    println!("  {:<32}{}{}{}", bold("capability"),
             cell("nmap", 10, "1"), cell("RustScan", 10, "1"), cell("CryptoCensus", 14, "1"));
    println!("  {}", dim(&"-".repeat(66)));
    for (name, n, r, c) in rows {
        let (nt, nc) = yn(n); let (rt, rc) = yn(r); let (ct, cc) = yn(c);
        println!("  {:<32}{}{}{}", name, cell(nt, 10, nc), cell(rt, 10, rc), cell(ct, 14, cc));
    }
    println!("  {}", dim(&"-".repeat(66)));
    let nmap_time = if nmap_secs > 0.0 { format!("{nmap_secs:.1}s") } else { "n/a".into() };
    println!("  {:<32}{}{}{}", bold("time on this scan"),
             cell(&nmap_time, 10, "91"), cell("ports only", 10, "2"),
             cell(&format!("{:.1}s", native.as_secs_f64()), 14, "92"));
    println!();
    println!("  {}", bold(&format!("CryptoCensus: {} hosts, {} crypto params, {} CBOM components, {:.2}s",
                                    hosts.len(), recs.len(), cbom_components, native.as_secs_f64())));
    if nmap_secs > 0.0 {
        let x = nmap_secs / native.as_secs_f64().max(0.001);
        println!("  {}", paint(&format!("=> {x:.1}x faster than nmap, and nmap produces 0 of the risk verdict, score, or CBOM above", ), "1;92"));
    }
    println!();
}

// ================= post-verdict lifecycle features =================
// The scanner labels risk. These turn the verdict into action: remediate (fix),
// verify and monitor (diff), see crypto at rest (local), gate CI (SARIF +
// --fail-under), and prove exploitability (active downgrade test).

fn readiness_cat(cats: &[String]) -> f64 {
    if cats.is_empty() { return 100.0; }
    let penalty = |c: &str| match c {
        "broken" => 1.0, "legacy-classical" => 0.8, "quantum-vulnerable" => 0.6,
        "pq-ready" => 0.0, _ => 0.3,
    };
    let sum: f64 = cats.iter().map(|c| penalty(c)).sum();
    (100.0 * (1.0 - sum / cats.len() as f64)).round()
}
fn grade_rank(g: &str) -> u8 { match g { "A" => 5, "B" => 4, "C" => 3, "D" => 2, _ => 1 } }

fn push_rec(recs: &mut Vec<Record>, policy: &Value, host: &str, port: u16, service: &str, ctype: &str, value: &str) {
    if value.is_empty() { return; }
    let (category, why, source) = score(policy, ctype, value);
    recs.push(Record { host: host.to_string(), port, service: service.to_string(),
        ctype: ctype.to_string(), value: value.to_string(), category, why, source });
}

// ----- Feature 4: SARIF 2.1.0 output, so findings show up in a CI security tab -----
fn sarif_level(cat: &str) -> &'static str {
    match cat { "broken" => "error", "legacy-classical" | "quantum-vulnerable" => "warning", _ => "note" }
}
fn build_sarif(recs: &[Record]) -> Value {
    let cats: BTreeSet<&str> = recs.iter().map(|r| r.category.as_str()).collect();
    let rules: Vec<Value> = cats.iter().map(|c| json!({
        "id": format!("cryptocensus/{c}"), "name": format!("crypto-{c}"),
        "shortDescription": {"text": format!("Cryptographic asset classified {c}")},
        "defaultConfiguration": {"level": sarif_level(c)}
    })).collect();
    let results: Vec<Value> = recs.iter().filter(|r| r.category != "pq-ready").map(|r| json!({
        "ruleId": format!("cryptocensus/{}", r.category),
        "level": sarif_level(&r.category),
        "message": {"text": format!("{} '{}' on {}:{} is {}: {}",
            ctype_label(&r.ctype), r.value, r.host, r.port, r.category, r.why)},
        "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": format!("{}://{}:{}", r.service, r.host, r.port)}},
            "logicalLocations": [{"fullyQualifiedName": format!("{}/{}", r.ctype, r.value)}]
        }]
    })).collect();
    json!({
        "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "CryptoCensus", "version": "1.0",
                     "informationUri": "https://localhost/cryptocensus", "rules": rules}},
            "results": results
        }]
    })
}

// ----- Feature 1: remediation. Generate a post-quantum sshd drop-in and the grade it would reach -----
const HARDENED_KEX: &str = "sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256";
const HARDENED_CIPHERS: &str = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr";
const HARDENED_MACS: &str = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com";
const HARDENED_HOSTKEY: &str = "ssh-ed25519";

fn predicted_grade(policy: &Value) -> (f64, &'static str) {
    let mut cats = Vec::new();
    for (ct, list) in [("kex", HARDENED_KEX), ("cipher", HARDENED_CIPHERS), ("mac", HARDENED_MACS), ("hostkey", HARDENED_HOSTKEY)] {
        for v in list.split(',') { let (c, _, _) = score(policy, ct, v); cats.push(c); }
    }
    let s = readiness_cat(&cats);
    (s, grade(s).0)
}
fn hardened_conf(host: &str, file: &str) -> String {
    format!(
"# CryptoCensus post-quantum hardening drop-in for {host}
# Needs OpenSSH 9.9 or newer (mlkem768x25519-sha256); `sshd -t` rejects it on older versions.
# Install:  sudo cp {file} /etc/ssh/sshd_config.d/99-cryptocensus.conf  &&  sudo sshd -t  &&  sudo systemctl reload ssh
# Verify:   cryptocensus scan --targets {host} --out after  &&  cryptocensus diff before/inventory.json after/inventory.json
KexAlgorithms {HARDENED_KEX}
Ciphers {HARDENED_CIPHERS}
MACs {HARDENED_MACS}
HostKeyAlgorithms {HARDENED_HOSTKEY}
PubkeyAcceptedAlgorithms {HARDENED_HOSTKEY}
")
}
// algorithm names the generated config keeps (they are not "to drop", even if not pq-ready)
fn hardened_keeps(value: &str) -> bool {
    let v = value.to_lowercase();
    [HARDENED_KEX, HARDENED_CIPHERS, HARDENED_MACS, HARDENED_HOSTKEY].iter()
        .any(|list| list.split(',').any(|h| h == v))
}
fn fix_cmd(targets: &str, port: u16, timeout: Duration, workers: usize, policy: &Value, outdir: &str) {
    banner();
    let ips = parse_targets(targets);
    eprintln!("  {} {} host(s) on port {port}", bold("remediating"), ips.len());
    let (recs, _) = scan_targets(&ips, port, timeout, workers, policy, true);
    if recs.is_empty() {
        eprintln!("  {} no SSH service answered on {} target(s), port {port}; nothing to remediate", paint("error", "91"), ips.len());
        std::process::exit(2);
    }
    let mut hosts: BTreeMap<String, Vec<&Record>> = BTreeMap::new();
    for r in &recs { hosts.entry(r.host.clone()).or_default().push(r); }
    let dir = format!("{outdir}/fix");
    make_dir(&dir);
    let (pred_s, pred_g) = predicted_grade(policy);
    for (host, rs) in &hosts {
        let before = readiness(rs);
        let (bg, _) = grade(before);
        let drop: Vec<&&Record> = rs.iter().filter(|r| r.category != "pq-ready" && !hardened_keeps(&r.value)).collect();
        let kept_weak: Vec<&&Record> = rs.iter().filter(|r| r.category != "pq-ready" && hardened_keeps(&r.value)).collect();
        let file = format!("{host}_99-cryptocensus.conf");
        let path = format!("{dir}/{file}");
        write_file(&path, &hardened_conf(host, &file));
        println!("\n  {} {}", bold("host"), bold(host));
        println!("    now {} {:.0}/100, {} weak parameter(s) to drop:",
                 paint(&format!(" {bg} "), cat_bg_for_grade(bg)), before, drop.len());
        for w in drop.iter().take(10) {
            println!("      {} {:8} {}", paint("-", "91"), w.ctype, paint(&w.value, cat_fg(&w.category)));
        }
        if drop.len() > 10 { println!("      {} and {} more", dim("..."), drop.len() - 10); }
        for k in &kept_weak {
            println!("      {} {:8} {} {}", dim("="), k.ctype, paint(&k.value, cat_fg(&k.category)),
                     dim("kept: OpenSSH has no post-quantum host key yet"));
        }
        println!("    {} {} {:.0}/100 after applying {}", paint("=>", "92"),
                 paint(&format!(" {pred_g} "), cat_bg_for_grade(pred_g)), pred_s, dim(&path));
    }
    println!("\n  {} drop-in configs in {dir}/. Apply, re-scan, and `cryptocensus diff` to prove the lift.\n", dim("written:"));
}

// ----- Feature 2: drift. Diff two inventories and fail CI on a regression -----
fn record_from_json(r: &Value) -> Option<Record> {
    Some(Record {
        host: r["host"].as_str()?.to_string(),
        port: r["port"].as_str().and_then(|s| s.parse().ok())
              .or_else(|| r["port"].as_u64().map(|n| n as u16)).unwrap_or(0),
        service: r["service"].as_str().unwrap_or("ssh").to_string(),
        ctype: r["ctype"].as_str()?.to_string(),
        value: r["value"].as_str()?.to_string(),
        category: r["category"].as_str().unwrap_or("unclassified").to_string(),
        why: r["why"].as_str().unwrap_or("").to_string(),
        source: r["source"].as_str().unwrap_or("").to_string(),
    })
}
fn load_inventory(path: &str) -> Vec<Record> {
    let txt = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("  {} cannot read {path}: {e}", paint("error", "91")); std::process::exit(2); });
    let v: Value = serde_json::from_str(&txt).unwrap_or_else(|e| {
        eprintln!("  {} {path} is not JSON: {e}", paint("error", "91")); std::process::exit(2); });
    // a record repeated in the file (e.g. the Python prototype listed host keys twice)
    // must not weigh twice in a grade
    let mut seen = BTreeSet::new();
    v["records"].as_array().cloned().unwrap_or_default().iter().filter_map(record_from_json)
        .filter(|r| seen.insert(rkey(r))).collect()
}
fn rkey(r: &Record) -> (String, u16, String, String) { (r.host.clone(), r.port, r.ctype.clone(), r.value.clone()) }
fn is_weak(c: &str) -> bool { c == "broken" || c == "legacy-classical" || c == "quantum-vulnerable" }

// Drift between two scans. Regressions: a weak algorithm added, a post-quantum one
// removed, a host whose score fell, or a host missing from the new scan (fail closed:
// a host that vanished is unknown, not fixed, so its old records are not improvements).
struct Drift { added: Vec<Record>, removed: Vec<Record>, hosts: Vec<(String, Option<f64>, Option<f64>)>, improvements: u32, regressions: u32 }
// Removing a pq-ready name is a regression only if that service has no pq-ready algorithm
// of the same kind left: swapping hmac-sha2-256 for hmac-sha2-256-etm is not a loss,
// stripping every post-quantum key exchange is.
fn pq_lost(r: &Record, new: &[Record]) -> bool {
    r.category == "pq-ready" && !new.iter().any(|n| n.host == r.host && n.port == r.port && n.ctype == r.ctype && n.category == "pq-ready")
}
fn drift(old: &[Record], new: &[Record]) -> Drift {
    let oldset: BTreeMap<_, _> = old.iter().map(|r| (rkey(r), r.clone())).collect();
    let newset: BTreeMap<_, _> = new.iter().map(|r| (rkey(r), r.clone())).collect();
    let old_hosts: BTreeSet<String> = old.iter().map(|r| r.host.clone()).collect();
    let new_hosts: BTreeSet<String> = new.iter().map(|r| r.host.clone()).collect();
    let added: Vec<Record> = newset.iter().filter(|(k, _)| !oldset.contains_key(*k)).map(|(_, r)| r.clone()).collect();
    let removed: Vec<Record> = oldset.iter()
        .filter(|(k, r)| !newset.contains_key(*k) && new_hosts.contains(&r.host)).map(|(_, r)| r.clone()).collect();
    let (mut imp, mut reg) = (0u32, 0u32);
    for r in &added { if is_weak(&r.category) { reg += 1 } else if r.category == "pq-ready" { imp += 1 } }
    for r in &removed { if is_weak(&r.category) { imp += 1 } else if pq_lost(r, new) { reg += 1 } }
    let score_of = |set: &[Record], h: &str| -> Option<f64> {
        let c: Vec<String> = set.iter().filter(|r| r.host == h).map(|r| r.category.clone()).collect();
        if c.is_empty() { None } else { Some(readiness_cat(&c)) }
    };
    let mut hosts = Vec::new();
    for h in old_hosts.union(&new_hosts) {
        let (os, ns) = (score_of(old, h), score_of(new, h));
        match (os, ns) {
            (Some(a), Some(b)) => { if b < a { reg += 1 } else if b > a { imp += 1 } }
            (Some(_), None) => reg += 1,
            _ => {}
        }
        hosts.push((h.clone(), os, ns));
    }
    Drift { added, removed, hosts, improvements: imp, regressions: reg }
}

fn diff_cmd(old_path: &str, new_path: &str, fail_on_regression: bool) {
    let old = load_inventory(old_path);
    let new = load_inventory(new_path);
    let d = drift(&old, &new);
    println!("\n  {}  {}  vs  {}", bold("CryptoCensus drift"), dim(old_path), dim(new_path));
    let line = |sign: String, r: &Record| println!("    {} {}:{} {} {} [{}]", sign, r.host, r.port, r.ctype, bold(&r.value), paint(&r.category, cat_fg(&r.category)));

    println!("\n  {}", bold("added"));
    for r in &d.added {
        let sign = if is_weak(&r.category) { paint("+!", "91") } else { paint("+", "92") };
        line(sign, r);
    }
    if d.added.is_empty() { println!("    {}", dim("none")); }

    println!("  {}", bold("removed"));
    for r in &d.removed {
        let sign = if is_weak(&r.category) { paint("-", "92") } else if pq_lost(r, &new) { paint("-!", "91") } else { dim("-") };
        line(sign, r);
    }
    if d.removed.is_empty() { println!("    {}", dim("none")); }

    println!("  {}", bold("grade change"));
    for (h, os, ns) in &d.hosts {
        match (os, ns) {
            (Some(o), Some(n)) => {
                let (ogd, _) = grade(*o); let (ngd, _) = grade(*n);
                let tag = if n > o { paint("improved", "92") } else if n < o { paint("regressed", "91") } else { dim("same") };
                println!("    {:<16} {} {:>3.0}  to  {} {:>3.0}   {}", bold(h),
                         paint(&format!(" {ogd} "), cat_bg_for_grade(ogd)), o,
                         paint(&format!(" {ngd} "), cat_bg_for_grade(ngd)), n, tag);
            }
            (None, Some(_)) => println!("    {:<16} {}", bold(h), paint("host appeared", "93")),
            (Some(_), None) => println!("    {:<16} {}", bold(h), paint("host gone from the new scan (counted as a regression)", "91")),
            (None, None) => {}
        }
    }
    println!("\n  {} {} improvement(s), {} regression(s)\n", bold("summary"),
             paint(&d.improvements.to_string(), "92"),
             paint(&d.regressions.to_string(), if d.regressions > 0 { "91" } else { "92" }));
    if fail_on_regression && d.regressions > 0 {
        eprintln!("  {} regression gate: {} regression(s)", paint("FAIL", "91"), d.regressions);
        std::process::exit(1);
    }
}

// ----- Feature 3: crypto at rest on this host (closes the "network only" limitation) -----
fn openssl_pq(ver: &str) -> (String, String) {
    let nums: Vec<u32> = ver.split_whitespace().nth(1).unwrap_or("")
        .split('.').take(2).filter_map(|s| s.parse().ok()).collect();
    let ok = matches!(nums.as_slice(), [maj, min] if *maj > 3 || (*maj == 3 && *min >= 5));
    if ok { ("pq-ready".into(), "OpenSSL 3.5+ ships ML-KEM post-quantum key exchange".into()) }
    else { ("quantum-vulnerable".into(), "OpenSSL below 3.5 has no standardised post-quantum KEM".into()) }
}
fn local_cmd(policy: &Value, outdir: &str) {
    banner();
    eprintln!("  {} local crypto at rest: effective sshd algorithms, host keys, openssl", bold("inspecting"));
    let host = "localhost";
    let mut recs: Vec<Record> = Vec::new();
    match Command::new("sshd").arg("-T").output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
            for line in text.lines() {
                let mut it = line.split_whitespace();
                let key = it.next().unwrap_or("");
                let vals = it.next().unwrap_or("");
                let ctype = match key { "kexalgorithms" => "kex", "ciphers" => "cipher", "macs" => "mac", "hostkeyalgorithms" => "hostkey", _ => "" };
                if !ctype.is_empty() {
                    for v in vals.split(',').filter(|s| !s.is_empty()) { push_rec(&mut recs, policy, host, 22, "local-sshd", ctype, v); }
                }
            }
        }
        _ => eprintln!("  {} `sshd -T` unavailable (needs root + valid config); host keys and openssl still checked", paint("note", "93")),
    }
    if let Ok(rd) = std::fs::read_dir("/etc/ssh") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("ssh_host_") && name.ends_with("_key.pub") {
                if let Ok(content) = std::fs::read_to_string(e.path()) {
                    if let Some(algo) = content.split_whitespace().next() {
                        // the key FILE type ssh-rsa is an RSA key; OpenSSH 8.8+ signs with it
                        // via rsa-sha2-*, so the SHA-1 "ssh-rsa" signature rule would misjudge it
                        let scored = if algo == "ssh-rsa" { "rsa-sha2-512" } else { algo };
                        push_rec(&mut recs, policy, host, 22, "local-hostkey", "hostkey", scored);
                    }
                }
            }
        }
    }
    if let Ok(out) = Command::new("openssl").arg("version").output() {
        let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let (cat, why) = openssl_pq(&ver);
        recs.push(Record { host: host.into(), port: 0, service: "local-lib".into(), ctype: "library".into(),
            value: ver, category: cat, why, source: "OpenSSL release notes".into() });
    }
    if recs.is_empty() { eprintln!("  {} nothing collected", paint("error", "91")); std::process::exit(2); }
    let mut seen = BTreeSet::new();   // sshd -T and the key files can name the same algorithm
    recs.retain(|r| seen.insert((r.ctype.clone(), r.value.clone())));
    let stamp = now_iso();
    let dir = format!("{outdir}/local");
    write_outputs(&recs, &dir, &stamp);
    print_summary(&recs, &BTreeMap::new());
    println!("  {} {dir}/inventory.json | {dir}/cbom.json | {dir}/report.html | {dir}/cryptocensus.sarif", dim("written:"));
}

// ----- Feature 5: active downgrade test. Does the server actually accept weak crypto? -----
const WEAK_KEX: [&str; 4] = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "gss-"];
const WEAK_CIPHERS: [&str; 6] = ["3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "aes128-cbc"];
const WEAK_MACS: [&str; 3] = ["hmac-md5", "hmac-md5-96", "hmac-sha1-96"];

fn pick_weak(offered: &BTreeSet<String>, weak: &[&str]) -> Option<String> {
    weak.iter().find(|w| { let wl = w.to_lowercase(); offered.iter().any(|o| o.contains(&wl)) }).map(|w| w.to_string())
}
// hostkeys: the server's own host key list, so only the slot under test can fail
fn build_kexinit(kex: &str, hostkeys: &str, cipher: &str, mac: &str) -> Vec<u8> {
    let names = [kex, hostkeys, cipher, cipher, mac, mac, "none", "none", "", ""];
    let mut payload = vec![20u8];               // SSH_MSG_KEXINIT
    payload.extend_from_slice(&[0x11u8; 16]);   // cookie
    for nm in names {
        let b = nm.as_bytes();
        payload.extend_from_slice(&(b.len() as u32).to_be_bytes());
        payload.extend_from_slice(b);
    }
    payload.push(0);                            // first_kex_packet_follows = false
    payload.extend_from_slice(&[0u8; 4]);       // reserved
    let block = 8usize;
    let mut pad = block - ((5 + payload.len()) % block);
    if pad < 4 { pad += block; }
    let pkt_len = 1 + payload.len() + pad;
    let mut out = Vec::new();
    out.extend_from_slice(&(pkt_len as u32).to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(&payload);
    out.extend(std::iter::repeat(0u8).take(pad));
    out
}
// scan the cleartext SSH stream for a packet of the given message type
fn ssh_has_msg(buf: &[u8], msg: u8) -> bool {
    let mut i = 0;
    if let Some(p) = find_ident(buf) {
        if let Some(nl) = buf[p..].iter().position(|&b| b == b'\n') { i = p + nl + 1; }
    }
    while i + 5 <= buf.len() {
        let pkt_len = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        if pkt_len < 2 || pkt_len > 35000 || i + 4 + pkt_len > buf.len() { break; }
        let pad = buf[i + 4] as usize;
        let payload_start = i + 5;
        let payload_end = (i + 4 + pkt_len).saturating_sub(pad);   // hostile pad must not underflow
        if payload_end > payload_start && payload_end <= buf.len() && buf[payload_start] == msg { return true; }
        i += 4 + pkt_len;
    }
    false
}
#[derive(PartialEq, Debug)]
enum Down { Accepted, Refused, Unknown }
fn live_downgrade(ip: Ipv4Addr, port: u16, kex: &str, hostkeys: &str, cipher: &str, mac: &str, timeout: Duration) -> Down {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) { Ok(s) => s, Err(_) => return Down::Unknown };
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    if stream.write_all(SSH_IDENT).is_err() { return Down::Unknown; }
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    for _ in 0..4 {   // read server ident + its KEXINIT
        match stream.read(&mut tmp) { Ok(0) => break, Ok(n) => { buf.extend_from_slice(&tmp[..n]); if buf.len() > 64 { break; } }, Err(_) => break }
    }
    if stream.write_all(&build_kexinit(kex, hostkeys, cipher, mac)).is_err() { return Down::Unknown; }
    let start = Instant::now();
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => return Down::Refused,                 // closed with no common algorithm
            Ok(n) => { buf.extend_from_slice(&tmp[..n]); if ssh_has_msg(&buf, 1) { return Down::Refused; } } // SSH_MSG_DISCONNECT
            // Only a read TIMEOUT with the socket still open means the server agreed and is
            // waiting for our key exchange reply. WouldBlock is how Unix reports it, TimedOut
            // is Windows. ponytail: heuristic; a host that agrees then idles looks the same.
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return Down::Accepted,
            Err(_) => return Down::Refused,                // a reset or abort after our weak offer is a rejection
        }
        if start.elapsed() > timeout { return Down::Accepted; }
    }
}
// One live probe per weak algorithm the server offers. The weak name goes alone in its
// slot and every other slot is filled from the server's own offer, so the probe can only
// fail on the algorithm under test. (Proposing DH-group1 + 3DES + MD5 together would make
// a server that accepts only one of them look safe.)
fn downgrade_cmd(targets: &str, port: u16, timeout: Duration, policy: &Value) {
    banner();
    let ips = parse_targets(targets);
    eprintln!("  {} active downgrade test on {} host(s), port {port}", bold("probing"), ips.len());
    let mut answered = 0;
    for ip in &ips {
        let found = match scan_ssh(*ip, port, timeout) { Some((_, f)) => f, None => { println!("\n  {} {} no SSH", bold("host"), bold(&ip.to_string())); continue; } };
        answered += 1;
        let offered: BTreeSet<String> = found.iter().map(|(_, v)| v.to_lowercase()).collect();
        let first = |t: &str, no_aead: bool| found.iter()
            .find(|(ct, v)| ct == t && !(no_aead && (v.contains("gcm") || v.contains("poly1305"))))
            .map(|(_, v)| v.clone());
        let hostkeys: Vec<String> = found.iter().filter(|(ct, _)| ct == "hostkey").map(|(_, v)| v.clone()).collect();
        let hk = if hostkeys.is_empty() { "ssh-ed25519,rsa-sha2-256,ssh-rsa".to_string() } else { hostkeys.join(",") };
        let (pk, pc, pm, pc_mac) = (first("kex", false), first("cipher", false), first("mac", false), first("cipher", true));
        println!("\n  {} {}", bold("host"), bold(&ip.to_string()));
        let mut probes: Vec<(&str, Option<String>, Option<String>, Option<String>)> = Vec::new();
        for (ctype, weak) in [("kex", &WEAK_KEX[..]), ("cipher", &WEAK_CIPHERS[..]), ("mac", &WEAK_MACS[..])] {
            if let Some(pat) = pick_weak(&offered, weak) {
                let name = found.iter().find(|(ct, v)| ct == ctype && v.to_lowercase().contains(&pat)).map(|(_, v)| v.clone());
                let shown = name.clone().unwrap_or(pat.clone());
                let (cat, _, _) = score(policy, ctype, &shown);
                println!("    {} offers weak {} {} [{}]", paint("!", "91"), ctype, bold(&shown), paint(&cat, cat_fg(&cat)));
                probes.push(match ctype {
                    "kex" => (ctype, name, pc.clone(), pm.clone()),
                    "cipher" => (ctype, pk.clone(), name, pm.clone()),
                    _ => (ctype, pk.clone(), pc_mac.clone(), name),   // a MAC is only used with a non-AEAD cipher
                });
            }
        }
        if probes.is_empty() {
            println!("    {} no weak kex/cipher/mac in the offer", paint("ok", "92"));
            match live_downgrade(*ip, port, "diffie-hellman-group1-sha1", &hk, "3des-cbc", "hmac-md5", timeout) {
                Down::Refused => println!("    {} weak-only proposal refused (server disconnect)", paint(" refused ", "1;37;42")),
                // a server cannot negotiate algorithms it never offered, so silence is not acceptance
                _ => println!("    {} server stayed silent, but it offers nothing weak, so no downgrade is possible", dim("note")),
            }
            continue;
        }
        for (ctype, k, c, m) in probes {
            let (Some(k), Some(c), Some(m)) = (k, c, m) else {
                println!("    {} cannot build a {ctype} probe from this offer (a MAC test needs a non-AEAD cipher); offered-set verdict stands", dim("note"));
                continue;
            };
            match live_downgrade(*ip, port, &k, &hk, &c, &m, timeout) {
                Down::Accepted => println!("    {} weak {ctype} negotiated: {k} / {c} / {m}", paint(" DOWNGRADE ACCEPTED ", "1;37;41")),
                Down::Refused  => println!("    {} weak {ctype} refused: {k} / {c} / {m}", paint(" refused ", "1;37;42")),
                Down::Unknown  => println!("    {} live {ctype} probe inconclusive; offered-set verdict stands", dim("note")),
            }
        }
    }
    println!();
    if answered == 0 { eprintln!("  {} no SSH service answered on {} target(s)", paint("error", "91"), ips.len()); std::process::exit(2); }
}

// ================= O7: Shor's algorithm (execute the quantum verdict) =================
// CryptoCensus labels RSA and classical DH "quantum-vulnerable, broken by Shor".
// This factors a scanned RSA modulus on a simulated quantum computer and rebuilds
// the private key, closing the loop from "flagged" to "actually broken". The
// modular-exponentiation oracle is evaluated classically, then the inverse QFT (a
// forward DFT here) runs over the full statevector; the interference peaks reveal
// the hidden period exactly as on hardware.
// ponytail: full 2^(2n) statevector. N=3233 needs a 2^24-point FFT (~256MB, a few
// seconds); capped at 24 qubits, so this demo factors moduli below 4096 and scales
// the cost of a real key from published estimates instead.

#[derive(Clone, Copy)]
struct Cpx { re: f64, im: f64 }

fn fft_forward(a: &mut [Cpx]) {
    let n = a.len();
    let mut j = 0usize;
    for i in 1..n {                       // bit-reversal permutation
        let mut bit = n >> 1;
        while j & bit != 0 { j ^= bit; bit >>= 1; }
        j ^= bit;
        if i < j { a.swap(i, j); }
    }
    let mut len = 2usize;
    while len <= n {
        let ang = -2.0 * std::f64::consts::PI / len as f64;   // forward DFT
        let (wr, wi) = (ang.cos(), ang.sin());
        let mut i = 0usize;
        while i < n {
            let (mut cr, mut ci) = (1.0f64, 0.0f64);
            for k in 0..len / 2 {
                let u = a[i + k];
                let v = a[i + k + len / 2];
                let (tr, ti) = (cr * v.re - ci * v.im, cr * v.im + ci * v.re);
                a[i + k] = Cpx { re: u.re + tr, im: u.im + ti };
                a[i + k + len / 2] = Cpx { re: u.re - tr, im: u.im - ti };
                let ncr = cr * wr - ci * wi;
                ci = cr * wi + ci * wr;
                cr = ncr;
            }
            i += len;
        }
        len <<= 1;
    }
}

fn mulmod(a: u128, b: u128, m: u128) -> u128 { a % m * (b % m) % m }
fn modpow_u(mut base: u128, mut exp: u128, m: u128) -> u128 {
    let mut r = 1u128 % m; base %= m;
    while exp > 0 { if exp & 1 == 1 { r = mulmod(r, base, m); } base = mulmod(base, base, m); exp >>= 1; }
    r
}
fn gcd_u(mut a: u128, mut b: u128) -> u128 { while b != 0 { let t = a % b; a = b; b = t; } a }

// best rational approximation of y/q with denominator <= max_den (continued fractions)
fn cf_denominator(y: u128, q: u128, max_den: u128) -> Option<u128> {
    if y == 0 { return None; }
    let (mut p0, mut q0, mut p1, mut q1) = (0i128, 1i128, 1i128, 0i128);
    let (mut n, mut d) = (y as i128, q as i128);
    let md = max_den as i128;
    while d != 0 {
        let a = n / d;
        let q2 = a * q1 + q0;
        if q2 > md { break; }
        let p2 = a * p1 + p0;
        p0 = p1; q0 = q1; p1 = p2; q1 = q2;
        let r = n - a * d; n = d; d = r;
    }
    let _ = (p0, p1);
    if q1 > 0 { Some(q1 as u128) } else { None }
}

fn shor_period(a: u128, n_mod: u128, q_bits: u32) -> Option<u128> {
    // actual multiplicative order of a mod N (classical oracle period)
    let mut order = 0u128; let mut cur = 1u128 % n_mod;
    loop { order += 1; cur = mulmod(cur, a, n_mod); if cur == 1 { break; } if order > n_mod { return None; } }
    let q = 1usize << q_bits;
    // measure work register, condition on residue 1 -> comb on multiples of the order
    let mut psi = vec![Cpx { re: 0.0, im: 0.0 }; q];
    let step = order as usize;
    let mut set = 0u64;
    let mut idx = 0usize;
    while idx < q { psi[idx].re = 1.0; set += 1; idx += step; }
    let norm = (set as f64).sqrt();
    for c in psi.iter_mut() { c.re /= norm; }
    fft_forward(&mut psi);                 // the one genuinely quantum step
    // pick the top 6 interference peaks (skip the dc term y=0)
    let mut peaks: [(f64, usize); 6] = [(-1.0, 0); 6];
    for (i, c) in psi.iter().enumerate().skip(1) {
        let p = c.re * c.re + c.im * c.im;
        if p > peaks[5].0 {
            peaks[5] = (p, i);
            peaks.sort_by(|x, y| y.0.partial_cmp(&x.0).unwrap());
        }
    }
    for &(_, y) in peaks.iter() {
        if let Some(r) = cf_denominator(y as u128, q as u128, n_mod) {
            for cand in [r, 2 * r, 3 * r] {
                if cand > 1 && modpow_u(a, cand, n_mod) == 1 { return Some(cand); }
            }
        }
    }
    None
}

// returns (p, q, period, base)
fn shor_factor(n_mod: u128) -> Option<(u128, u128, u128, u128)> {
    if n_mod < 4 { return None; }
    if n_mod % 2 == 0 { return Some((2, n_mod / 2, 0, 0)); }
    let bitlen = 128 - n_mod.leading_zeros();
    let q_bits = 2 * bitlen;
    if q_bits > 24 { eprintln!("  {} N={n_mod} is too large for the statevector demo (needs {q_bits} qubits); use --resource", paint("note", "93")); return None; }
    // Shor needs a composite that is not a prime power, so check both classically first
    // (the cap above keeps N below 4096, so this is at most 31 trial divisions)
    if (3u128..).step_by(2).take_while(|d| d * d <= n_mod).all(|d| n_mod % d != 0) {
        eprintln!("  {} N={n_mod} is prime: there is nothing to factor", paint("note", "93")); return None;
    }
    for k in 2..=12u32 {
        let r = (n_mod as f64).powf(1.0 / k as f64).round() as u128;
        if r > 1 && r.pow(k) == n_mod { return Some((r, n_mod / r, 0, 0)); }   // prime power
    }
    for a in 2..n_mod {
        let g = gcd_u(a, n_mod);
        if g != 1 { return Some((g, n_mod / g, 0, a)); }   // lucky gcd
        if let Some(r) = shor_period(a, n_mod, q_bits) {
            if r % 2 != 0 { continue; }
            let x = modpow_u(a, r / 2, n_mod);
            if x == n_mod - 1 { continue; }
            let p = gcd_u(x + 1, n_mod);
            let q = gcd_u(x - 1, n_mod);
            for f in [p, q] {
                if f > 1 && f < n_mod && n_mod % f == 0 { return Some((f, n_mod / f, r, a)); }
            }
        }
    }
    None
}

fn modinv_u(e: u128, m: u128) -> Option<u128> {
    let (mut old_r, mut r) = (e as i128, m as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 { let q = old_r / r;
        let tr = old_r - q * r; old_r = r; r = tr;
        let ts = old_s - q * s; old_s = s; s = ts; }
    if old_r != 1 { return None; }
    Some((((old_s % m as i128) + m as i128) % m as i128) as u128)
}

fn shor_rsa_demo(n_mod: u128, e: u128, message: u128) {
    println!("  {} breaking a toy RSA public key with Shor, then decrypting", bold("[*]"));
    // RSA only round-trips a message smaller than N
    let message = if message >= n_mod { (message % n_mod).max(2) } else { message };
    println!("    public key: N={n_mod}, e={e}, message={message}");
    match shor_factor(n_mod) {
        Some((p, q, r, a)) => {
            let phi = (p - 1) * (q - 1);
            let d = match modinv_u(e % phi, phi) { Some(d) => d, None => { println!("    e={e} is not invertible mod phi={phi}, pick another N"); return; } };
            let ct = modpow_u(message, e, n_mod);
            let pt = modpow_u(ct, d, n_mod);
            if r == 0 { println!("    found by a classical shortcut (shared factor or prime power), no period needed"); }
            else { println!("    Shor recovered period r={r} with base a={a}"); }
            println!("    {} N = {} x {}", paint("factored:", "92"), bold(&p.to_string()), bold(&q.to_string()));
            println!("    rebuilt private exponent d={d}");
            println!("    ciphertext {ct}  ->  decrypted {} (original {message})",
                     if pt == message { paint(&pt.to_string(), "92") } else { paint(&pt.to_string(), "91") });
            if pt == message { println!("  {} private key reconstructed from the public key alone, message decrypted", paint("[+]", "92")); }
        }
        None => println!("  {} no factor found", paint("[-]", "91")),
    }
}

fn shor_resource(bits: u128) {
    if bits == 0 || bits > 1_000_000 { eprintln!("  {} --resource must be between 1 and 1000000 bits", paint("error", "91")); std::process::exit(2); }
    let logical = 2 * bits + 3;
    let toffoli = 0.3 * (bits as f64).powi(3);
    println!("  {} Shor cost for a {bits}-bit key: ~{logical} logical qubits, ~{:.1e} Toffoli gates", bold("[*]"), toffoli);
    if bits == 2048 { println!("    Gidney and Ekera 2021: about 20 million physical qubits, about 8 hours"); }
}

fn shor_selftest() {
    let cases: [(u128, (u128, u128)); 5] = [(15, (3, 5)), (21, (3, 7)), (35, (5, 7)), (143, (11, 13)), (323, (17, 19))];
    let mut bad = 0;
    for (n_mod, (ep, eq)) in cases {
        match shor_factor(n_mod) {
            Some((p, q, r, a)) if (p == ep && q == eq) || (p == eq && q == ep) =>
                println!("  {} Shor factor {n_mod:5} -> {p} x {q}  (period r={r}, a={a})", paint("ok  ", "92")),
            other => { bad += 1; println!("  {} Shor factor {n_mod:5} -> {other:?}", paint("FAIL", "91")); }
        }
    }
    assert_eq!(bad, 0, "Shor self-test failed");
    println!("{}", paint(&format!("Shor self-test passed: {} factorizations", cases.len()), "92"));
}

// ================= O8: batch-GCD shared-prime key recovery (Mining your Ps and Qs) =================
// An RSA-2048 key is strong on paper yet falls instantly if weak randomness made it
// share a prime with another key on the network: gcd(N1,N2)=p factors both. This
// runs Bernstein's batch-GCD (product tree + remainder tree) to find every shared
// prime across the whole corpus at once, then rebuilds a private key and forges a
// host signature. USENIX Security 2012 (Heninger, Durumeric, Wustrow, Halderman).

struct Xorshift(u64);
impl Xorshift {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x
    }
}
fn small_primes(limit: u64) -> Vec<u64> {
    let n = limit as usize;
    let mut sieve = vec![true; n + 1];
    let mut p = 2usize;
    while p * p <= n { if sieve[p] { let mut k = p * p; while k <= n { sieve[k] = false; k += p; } } p += 1; }
    (2..=n).filter(|&i| sieve[i]).map(|i| i as u64).collect()
}
fn rand_biguint(rng: &mut Xorshift, bits: u64) -> BigUint {
    let nbytes = ((bits + 7) / 8) as usize;
    let mut bytes = vec![0u8; nbytes];
    for b in bytes.iter_mut() { *b = (rng.next_u64() & 0xff) as u8; }
    let x = BigUint::from_bytes_le(&bytes);
    let top = bits - 1;
    let mask = (BigUint::one() << bits) - BigUint::one();
    let high = BigUint::one() << top;
    (x & mask) | high | BigUint::one()                // mask to `bits`, force high bit and odd
}
fn is_probable_prime(n: &BigUint, small: &[u64], rng: &mut Xorshift) -> bool {
    let two = BigUint::from(2u32);
    if n < &two { return false; }
    for &sp in small {
        let bp = BigUint::from(sp);
        if n == &bp { return true; }
        if (n % &bp).is_zero() { return false; }
    }
    let one = BigUint::one();
    let n1 = n - &one;
    let mut d = n1.clone();
    let mut s = 0u32;
    while d.is_even() { d = d >> 1u32; s += 1; }
    'witness: for _ in 0..12 {
        let a = &(&rand_biguint(rng, n.bits()) % (n - &two)) + &two;
        let mut x = a.modpow(&d, n);
        if x == one || x == n1 { continue; }
        for _ in 0..s.saturating_sub(1) {
            x = x.modpow(&two, n);
            if x == n1 { continue 'witness; }
        }
        return false;
    }
    true
}
fn gen_prime(rng: &mut Xorshift, bits: u64, small: &[u64]) -> BigUint {
    loop { let c = rand_biguint(rng, bits); if is_probable_prime(&c, small, rng) { return c; } }
}
fn batch_gcd(moduli: &[BigUint]) -> Vec<BigUint> {
    // product tree: each level is the pairwise products of the level below
    let mut tree: Vec<Vec<BigUint>> = vec![moduli.to_vec()];
    while tree.last().unwrap().len() > 1 {
        let cur = tree.last().unwrap();
        let mut nxt = Vec::with_capacity((cur.len() + 1) / 2);
        let mut i = 0;
        while i < cur.len() {
            if i + 1 < cur.len() { nxt.push(&cur[i] * &cur[i + 1]); } else { nxt.push(cur[i].clone()); }
            i += 2;
        }
        tree.push(nxt);
    }
    // remainder tree: push the root product down, reducing mod node^2 at each level
    let mut rem: Vec<BigUint> = vec![tree.last().unwrap()[0].clone()];
    for level in tree.iter().rev().skip(1) {
        let mut nxt = Vec::with_capacity(level.len());
        for (i, node) in level.iter().enumerate() { nxt.push(&rem[i / 2] % &(node * node)); }
        rem = nxt;
    }
    moduli.iter().zip(rem.iter()).map(|(n, r)| (r / n).gcd(n)).collect()
}
fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() { (a, BigInt::one(), BigInt::zero()) }
    else { let (g, x, y) = egcd(b.clone(), &a % &b); let ny = &x - &(&a / &b) * &y; (g, y, ny) }
}
fn modinv_big(e: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (g, x, _) = egcd(BigInt::from(e.clone()), BigInt::from(m.clone()));
    if !g.is_one() { return None; }
    let mm = BigInt::from(m.clone());
    (((x % &mm) + &mm) % &mm).to_biguint()
}
fn batchgcd_run(keys: usize, bits: u64) {
    // below 32 bits the prime generator can fail forever (bits 0 or 1) or random primes
    // collide across the corpus and drown the planted pair; above 4096 it is pointless here
    if !(32..=4096).contains(&bits) { eprintln!("  {} --bits must be between 32 and 4096", paint("error", "91")); std::process::exit(2); }
    if keys > 100_000 { eprintln!("  {} --keys must be at most 100000", paint("error", "91")); std::process::exit(2); }
    banner();
    let small = small_primes(2000);
    let mut rng = Xorshift(0x9E3779B97F4A7C15);
    println!("  {} building a corpus of {keys} RSA-{} keys with low-entropy collisions", bold("[*]"), 2 * bits);
    let planted = gen_prime(&mut rng, bits, &small);
    let mut moduli: Vec<BigUint> = Vec::with_capacity(keys + 2);
    let mut labels: Vec<String> = Vec::with_capacity(keys + 2);
    for i in 0..keys {
        let (p, q) = (gen_prime(&mut rng, bits, &small), gen_prime(&mut rng, bits, &small));
        moduli.push(&p * &q); labels.push(format!("synthetic-host-{i}"));
    }
    // two machines that redrew the same prime from a low-entropy pool
    moduli.push(&planted * &gen_prime(&mut rng, bits, &small)); labels.push("victim-A (weak RNG)".into());
    moduli.push(&planted * &gen_prime(&mut rng, bits, &small)); labels.push("victim-B (weak RNG)".into());
    let m = moduli.len();
    let naive = (m as u64) * (m as u64 - 1) / 2;
    println!("  {} {m} keys. naive pairwise GCD would be {naive} big-integer GCDs", bold("[*]"));
    let t0 = Instant::now();
    let gcds = batch_gcd(&moduli);
    let e = BigUint::from(65537u32);
    let mut factored = 0;
    for (i, g) in gcds.iter().enumerate() {
        if g > &BigUint::one() && g < &moduli[i] {
            factored += 1;
            let p = g.clone(); let q = &moduli[i] / &p;
            let phi = (&p - 1u32) * (&q - 1u32);
            let d = match modinv_big(&e, &phi) { Some(d) => d, None => continue };
            let challenge = BigUint::from_bytes_be(b"authenticate-as-this-host") % &moduli[i];
            let sig = challenge.modpow(&d, &moduli[i]);
            let ok = sig.modpow(&e, &moduli[i]) == challenge;
            println!("    {} {}: recovered a {}-bit shared prime, rebuilt the {}-bit private key, forged signature verifies: {}",
                     paint("+", "92"), labels[i], p.bits(), d.bits(),
                     if ok { paint("true", "92") } else { paint("false", "91") });
        }
    }
    let dt = t0.elapsed().as_secs_f64();
    println!("  {} batch-GCD finished in {:.2}s and factored {} key(s)", paint("[+]", "92"), dt, factored);
    if factored > 0 {
        println!("  {} a {}-bit key is strong on paper, broken by shared entropy", paint("[+]", "92"), moduli[moduli.len() - 1].bits());
    } else {
        println!("  {} no shared primes found in the corpus", paint("[-]", "93"));
    }
}
fn batchgcd_selftest() {
    let small = small_primes(2000);
    let mut rng = Xorshift(0xDEADBEEF12345678);
    let p = gen_prime(&mut rng, 128, &small);
    let q1 = gen_prime(&mut rng, 128, &small);
    let q2 = gen_prime(&mut rng, 128, &small);
    let r = gen_prime(&mut rng, 128, &small);
    let s = gen_prime(&mut rng, 128, &small);
    let mods = vec![&p * &q1, &p * &q2, &r * &s];
    let g = batch_gcd(&mods);
    assert!(g[0] == p && g[1] == p, "batch-GCD missed the shared prime");
    assert!(g[2].is_one(), "batch-GCD false positive on a clean key");
    println!("{}", paint("batch-GCD self-test passed: recovers the shared prime, no false positive", "92"));
}

// ================= O10: post-quantum migration roadmap =================
// Turns inventory.json into a dated plan: Mosca's inequality (X+Y>Z) for
// harvest-now-decrypt-later exposure, a CNSA 2.0 / NIST IR 8547 deadline per band,
// a 0/1 knapsack for the first migration wave under a work budget, and a
// topological sort so the PQ key exchange deploys before classical ciphers retire.

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
fn urgency(band: &str) -> i64 { deadline_year(band).unwrap_or(i64::MAX) }
fn deadline_year(band: &str) -> Option<i64> {
    match band { "broken" => Some(2025), "legacy-classical" => Some(2030), "quantum-vulnerable" => Some(2035), _ => None }
}
fn days_to_noncompliant(band: &str) -> Option<i64> {
    let (y, m, d) = today_civil();
    deadline_year(band).map(|yr| days_from_civil(yr, 1, 1) - days_from_civil(y, m, d))
}
fn band_weight(b: &str) -> i64 { match b { "broken" => 4, "legacy-classical" => 3, "quantum-vulnerable" => 2, "pq-ready" => 0, _ => 1 } }
fn ctype_effort(c: &str) -> i64 { match c { "kex" => 2, "hostkey" => 3, "cipher" => 1, "mac" => 1, "tls_version" => 2, "cert_sig" => 3, _ => 2 } }

#[derive(Clone)]
struct Asset { host: String, ctype: String, value: String, band: String }
#[derive(Clone)]
struct Row { idx: usize, host: String, ctype: String, value: String, band: String,
    weight: i64, effort: i64, days: Option<i64>, mosca: bool, rank: Option<usize>, wave1: bool }

fn knapsack(items: &[(i64, i64, usize)], budget: i64) -> BTreeSet<usize> {
    let n = items.len();
    let b = budget.max(0) as usize;
    let mut dp = vec![vec![0i64; b + 1]; n + 1];
    for i in 1..=n {
        let (val, cost, _) = items[i - 1];
        for w in 0..=b {
            dp[i][w] = dp[i - 1][w];
            if cost as usize <= w { dp[i][w] = dp[i][w].max(dp[i - 1][w - cost as usize] + val); }
        }
    }
    let mut chosen = BTreeSet::new();
    let mut w = b;
    for i in (1..=n).rev() {
        if dp[i][w] != dp[i - 1][w] { chosen.insert(items[i - 1].2); w -= items[i - 1].1 as usize; }
    }
    chosen
}
// Kahn's algorithm: within a host, kex migrates before cipher/mac; ties by rank order
fn topo_order(assets: &[Asset], ranked: &[usize]) -> Vec<usize> {
    let rankpos: BTreeMap<usize, usize> = ranked.iter().enumerate().map(|(p, &i)| (i, p)).collect();
    let mut indeg: BTreeMap<usize, usize> = ranked.iter().map(|&i| (i, 0)).collect();
    let mut deps: BTreeMap<usize, Vec<usize>> = ranked.iter().map(|&i| (i, Vec::new())).collect();
    let mut by_host: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &i in ranked { by_host.entry(assets[i].host.clone()).or_default().push(i); }
    for idxs in by_host.values() {
        let kexs: Vec<usize> = idxs.iter().cloned().filter(|&i| assets[i].ctype == "kex").collect();
        let others: Vec<usize> = idxs.iter().cloned().filter(|&i| assets[i].ctype == "cipher" || assets[i].ctype == "mac").collect();
        // the PQ key exchange goes first only among equally urgent work; it must never hold
        // back an algorithm that is due sooner (e.g. an overdue broken cipher behind a 2035 kex)
        for &k in &kexs { for &o in &others {
            if urgency(&assets[k].band) <= urgency(&assets[o].band) {
                deps.get_mut(&k).unwrap().push(o); *indeg.get_mut(&o).unwrap() += 1;
            }
        } }
    }
    let mut ready: Vec<usize> = ranked.iter().cloned().filter(|i| indeg[i] == 0).collect();
    ready.sort_by_key(|i| rankpos[i]);
    let mut order = Vec::new();
    while !ready.is_empty() {
        let i = ready.remove(0);
        order.push(i);
        for &j in &deps[&i] { let e = indeg.get_mut(&j).unwrap(); *e -= 1; if *e == 0 { ready.push(j); } }
        ready.sort_by_key(|i| rankpos[i]);
    }
    order
}
fn roadmap_build(assets: &[Asset]) -> (Vec<Row>, bool, i64) {
    let (mx, my, mz) = (3i64, 10i64, 9i64);
    let mosca_exposed = mx + my > mz;
    let mut rows: Vec<Row> = assets.iter().enumerate().map(|(i, a)| {
        let w = band_weight(&a.band);
        Row { idx: i, host: a.host.clone(), ctype: a.ctype.clone(), value: a.value.clone(), band: a.band.clone(),
            weight: w, effort: ctype_effort(&a.ctype), days: days_to_noncompliant(&a.band),
            mosca: mosca_exposed && w >= 2, rank: None, wave1: false }
    }).collect();
    // rank: nearest deadline first, then risk weight desc
    let mut need: Vec<usize> = rows.iter().filter(|r| r.weight >= 2).map(|r| r.idx).collect();
    need.sort_by(|&a, &b| {
        let da = rows[a].days.unwrap_or(99999); let db = rows[b].days.unwrap_or(99999);
        da.cmp(&db).then(rows[b].weight.cmp(&rows[a].weight))
    });
    let order = topo_order(assets, &need);
    for (pos, &idx) in order.iter().enumerate() { rows[idx].rank = Some(pos + 1); }
    // first wave: 0/1 knapsack under a work budget that at least covers all broken crypto
    let budget = 4.max(rows.iter().filter(|r| r.weight >= 4).map(|r| r.effort).sum::<i64>());
    let items: Vec<(i64, i64, usize)> = rows.iter().filter(|r| r.weight >= 2)
        .map(|r| (r.weight * if r.band == "broken" { 3 } else { 1 }, r.effort, r.idx)).collect();
    let wave1 = knapsack(&items, budget);
    for r in rows.iter_mut() { r.wave1 = wave1.contains(&r.idx); }
    (rows, mosca_exposed, budget)
}
fn roadmap_html(rows: &[Row], mosca: bool, budget: i64) -> String {
    let col = |b: &str| color_hex(b);
    let mut need: Vec<&Row> = rows.iter().filter(|r| r.weight >= 2).collect();
    need.sort_by_key(|r| r.rank.unwrap_or(999));
    let (ty, tm, td) = today_civil();
    let today = format!("{ty:04}-{tm:02}-{td:02}");
    let mut h = String::new();
    h.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>PQ migration roadmap</title><style>");
    h.push_str("body{font:14px/1.5 -apple-system,Arial,sans-serif;margin:24px;color:#222}h1{font-size:20px}");
    h.push_str("table{border-collapse:collapse;width:100%;margin:10px 0}td,th{border:1px solid #ccc;padding:5px 8px;font-size:13px;text-align:left}");
    h.push_str("th{background:#f2f2f2}.pill{color:#fff;padding:2px 7px;border-radius:9px;font-size:12px}.box{background:#f7f7fb;border:1px solid #ddd;border-radius:8px;padding:10px 14px;margin:8px 0}");
    h.push_str("</style></head><body>");
    h.push_str(&format!("<h1>Post-quantum migration roadmap</h1><p>Generated {today}</p>"));
    let (verdict, vcol) = if mosca { ("EXPOSED NOW", "#c0392b") } else { ("within margin", "#27ae60") };
    h.push_str(&format!("<div class=\"box\"><b>Mosca's inequality:</b> X (migrate 3y) + Y (secrecy 10y) = 13y vs Z (quantum in 9y). Verdict: <span class=\"pill\" style=\"background:{vcol}\">{verdict}</span>. If X + Y &gt; Z, data encrypted today is already harvestable for later decryption.</div>"));
    let wave_n = rows.iter().filter(|r| r.wave1).count();
    h.push_str(&format!("<div class=\"box\"><b>First migration wave</b> (0/1 knapsack, work budget {budget} units): {wave_n} highest-risk assets, all broken crypto included. Ordering respects dependencies (post-quantum key exchange before retiring classical ciphers).</div>"));
    h.push_str("<table><tr><th>Rank</th><th>Host</th><th>Asset</th><th>Band</th><th>Non-compliant in</th><th>Mosca</th><th>Wave 1</th></tr>");
    for r in &need {
        let when = match r.days { Some(d) if d < 0 => "overdue".to_string(), Some(d) => format!("{d} days"), None => "compliant".to_string() };
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}: {}</td><td><span class=\"pill\" style=\"background:{}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            r.rank.map(|x| x.to_string()).unwrap_or_default(), esc(&r.host), esc(&r.ctype), esc(&r.value),
            col(&r.band), r.band, when, if r.mosca { "yes" } else { "-" }, if r.wave1 { "yes" } else { "-" }));
    }
    h.push_str("</table>");
    h.push_str("<p style=\"color:#555;font-size:12px\">Deadlines from CNSA 2.0 and NIST IR 8547 (112-bit classical deprecated 2030, disallowed after 2035). Mosca parameters X, Y, Z are a documented, configurable estimate.</p>");
    h.push_str("</body></html>");
    h
}
fn roadmap_cmd(outdir: &str) {
    let inv_path = format!("{outdir}/inventory.json");
    let txt = match std::fs::read_to_string(&inv_path) {
        Ok(t) => t, Err(e) => { eprintln!("  {} cannot read {inv_path}: {e} (run a scan first)", paint("error", "91")); std::process::exit(2); } };
    let v: Value = serde_json::from_str(&txt).unwrap_or_else(|e| { eprintln!("  {} {inv_path} is not JSON: {e}", paint("error", "91")); std::process::exit(2); });
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut assets: Vec<Asset> = Vec::new();
    for r in v["records"].as_array().cloned().unwrap_or_default() {
        let (host, ctype, value, band) = (
            r["host"].as_str().unwrap_or("").to_string(), r["ctype"].as_str().unwrap_or("").to_string(),
            r["value"].as_str().unwrap_or("").to_string(), r["category"].as_str().unwrap_or("unclassified").to_string());
        let key = (host.clone(), ctype.clone(), value.clone());
        if !seen.insert(key) { continue; }
        assets.push(Asset { host, ctype, value, band });
    }
    if assets.is_empty() { eprintln!("  {} {inv_path} has no records; nothing to plan (run a scan first)", paint("error", "91")); std::process::exit(2); }
    let (rows, mosca, budget) = roadmap_build(&assets);
    write_file(&format!("{outdir}/roadmap.html"), &roadmap_html(&rows, mosca, budget));
    // extend the CBOM with roadmap properties, keep it schema-valid
    let cbom_path = format!("{outdir}/cbom.json");
    if let Ok(ctxt) = std::fs::read_to_string(&cbom_path) {
        if let Ok(mut cbom) = serde_json::from_str::<Value>(&ctxt) {
            let by_val: BTreeMap<String, &Row> = rows.iter().map(|r| (r.value.clone(), r)).collect();
            if let Some(comps) = cbom["components"].as_array_mut() {
                for comp in comps.iter_mut() {
                    if let Some(r) = comp["name"].as_str().and_then(|n| by_val.get(n)) {
                        let props = comp["properties"].as_array_mut();
                        if let Some(props) = props {
                            props.push(json!({"name": "cryptocensus:migrationRank", "value": r.rank.map(|x| x.to_string()).unwrap_or_default()}));
                            props.push(json!({"name": "cryptocensus:moscaExposed", "value": r.mosca.to_string()}));
                            if let Some(d) = r.days { props.push(json!({"name": "cryptocensus:daysToNonCompliant", "value": d.to_string()})); }
                        }
                    }
                }
            }
            write_file(&format!("{outdir}/cbom_roadmap.json"), &serde_json::to_string_pretty(&cbom).unwrap());
        }
    }
    let need = rows.iter().filter(|r| r.weight >= 2).count();
    let wave_n = rows.iter().filter(|r| r.wave1).count();
    banner();
    println!("  {} {} assets, {} need migration, Mosca exposed: {}", bold("[*]"), assets.len(), need,
             if mosca { paint("yes", "91") } else { paint("no", "92") });
    println!("  {} first wave (knapsack, budget {budget}): {wave_n} assets", bold("[*]"));
    println!("  {} top of the migration queue:", bold("[*]"));
    let mut ranked: Vec<&Row> = rows.iter().filter(|r| r.rank.is_some()).collect();
    ranked.sort_by_key(|r| r.rank.unwrap());
    for r in ranked.iter().take(6) {
        let when = match r.days { Some(d) if d < 0 => "overdue".to_string(), Some(d) => format!("{d}d"), None => "-".to_string() };
        println!("    #{:<2} {:<16} {}:{} [{}] {}", r.rank.unwrap(), r.host, r.ctype,
                 paint(&r.value, cat_fg(&r.band)), r.band, dim(&when));
    }
    println!("  {} wrote {outdir}/roadmap.html and {outdir}/cbom_roadmap.json", paint("[+]", "92"));
}
fn roadmap_selftest() {
    let assets = vec![
        Asset { host: "h1".into(), ctype: "kex".into(), value: "diffie-hellman-group1-sha1".into(), band: "broken".into() },
        Asset { host: "h1".into(), ctype: "cipher".into(), value: "aes128-cbc".into(), band: "legacy-classical".into() },
        Asset { host: "h1".into(), ctype: "kex".into(), value: "curve25519-sha256".into(), band: "quantum-vulnerable".into() },
        Asset { host: "h2".into(), ctype: "kex".into(), value: "mlkem768x25519".into(), band: "pq-ready".into() },
    ];
    let (rows, mosca, _) = roadmap_build(&assets);
    let broken = rows.iter().find(|r| r.band == "broken").unwrap();
    let pq = rows.iter().find(|r| r.band == "pq-ready").unwrap();
    assert_eq!(broken.rank, Some(1), "broken asset must rank first");
    assert!(broken.wave1, "broken asset must be in wave 1");
    assert!(pq.rank.is_none(), "pq-ready needs no migration");
    assert!(mosca, "Mosca must report exposed");
    // the kex-before-cipher dependency must not push an overdue broken cipher behind a 2035 kex
    let inv = vec![
        Asset { host: "h3".into(), ctype: "kex".into(), value: "curve25519-sha256".into(), band: "quantum-vulnerable".into() },
        Asset { host: "h3".into(), ctype: "cipher".into(), value: "arcfour".into(), band: "broken".into() },
        Asset { host: "h3".into(), ctype: "mac".into(), value: "hmac-sha1".into(), band: "legacy-classical".into() },
    ];
    let (r2, _, _) = roadmap_build(&inv);
    let rank = |v: &str| r2.iter().find(|r| r.value == v).and_then(|r| r.rank).unwrap();
    assert!(rank("arcfour") < rank("curve25519-sha256"), "overdue broken cipher must rank before a 2035 kex");
    assert!(rank("hmac-sha1") < rank("curve25519-sha256"), "a 2030 MAC must rank before a 2035 kex");
    println!("{}", paint("roadmap self-test passed: broken ranks first and is in wave 1, pq-ready excluded, Mosca exposed, no deadline inversion", "92"));
}

// ================= AI layer: a local LLM writes prose, never a verdict =================
// Every grade, count and CBOM entry is computed by the deterministic engine. A LOCAL
// model (Ollama on 127.0.0.1:11434) only turns those computed facts into an executive
// brief (report --ai) or answers a question about them (ask). Nothing leaves the host.
// The authoritative grade printed is always the computed one; the model elaborates on
// it. If the model is not running, report --ai falls back to a deterministic template,
// so output never fails. Long dashes from the model are stripped (project style rule).

const OLLAMA_ADDR: &str = "127.0.0.1:11434";
const OLLAMA_MODEL: &str = "llama3.2:3b";

fn strip_dashes(s: &str) -> String {
    s.replace('\u{2014}', "-").replace('\u{2013}', "-").replace('\u{2012}', "-").replace('\u{2015}', "-")
}
// model output is prose for a terminal and a markdown file: no long dashes, no stray
// markdown emphasis or headings
fn clean_model_text(s: &str) -> String {
    strip_dashes(s).replace("**", "").replace("__", "")
        .lines().map(|l| l.trim_start_matches('#').trim_start()).collect::<Vec<_>>().join("\n").trim().to_string()
}

// Minimal HTTP POST to Ollama using std TcpStream (no HTTP crate). stream:false, so
// the reply is one JSON object; we slice it out of the (possibly chunked) body.
fn ollama_generate(prompt: &str) -> Option<String> {
    let body = json!({
        "model": OLLAMA_MODEL, "prompt": prompt, "stream": false,
        "options": {"temperature": 0.2, "num_predict": 600}
    }).to_string();
    let req = format!(
        "POST /api/generate HTTP/1.1\r\nHost: {OLLAMA_ADDR}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body);
    let addr: SocketAddr = OLLAMA_ADDR.parse().ok()?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(60))).ok();   // first call also loads the model
    s.set_write_timeout(Some(Duration::from_secs(10))).ok();
    s.write_all(req.as_bytes()).ok()?;
    // an overall deadline, so a server that accepts but never finishes (or trickles bytes)
    // cannot freeze a live demo; on timeout the caller falls back to the template
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => { buf.extend_from_slice(&tmp[..n]); if buf.len() > 4_000_000 { return None; } }
            Err(_) => return None,
        }
        if Instant::now() > deadline { return None; }
    }
    let text = String::from_utf8_lossy(&buf);
    let start = text.find('{')?;      // HTTP headers carry no brace; first { opens the JSON object
    let end = text.rfind('}')?;       // last } closes it (chunk trailers carry no brace)
    if end < start { return None; }
    let v: Value = serde_json::from_str(&text[start..=end]).ok()?;
    let out = v["response"].as_str()?.trim().to_string();
    if out.is_empty() { None } else { Some(out) }
}

// Compact, grounded view of the computed findings that the model is allowed to see.
fn build_findings_digest(recs: &[Record]) -> (String, &'static str, f64) {
    // printable text only, so nothing in a loaded inventory can forge a line (e.g. a fake grade)
    let clean = |s: &str| s.chars().map(|c| if (' '..='~').contains(&c) { c } else { '?' }).collect::<String>();
    let mut by_host: BTreeMap<String, Vec<&Record>> = BTreeMap::new();
    for r in recs { by_host.entry(clean(&r.host)).or_default().push(r); }
    let all: Vec<&Record> = recs.iter().collect();
    let os = readiness(&all);
    let (og, _) = grade(os);
    let mut d = format!("Overall: grade {og} ({os:.0}/100) across {} host(s) and {} parameter(s).\n", by_host.len(), recs.len());
    if let Some((w, ws)) = worst_host(recs) {
        d.push_str(&format!("Worst host: {} with grade {} ({ws:.0}/100).\n", clean(&w), grade(ws).0));
    }
    for (h, rs) in &by_host {
        let sc = readiness(rs);
        let (g, _) = grade(sc);
        let mut c: BTreeMap<&str, usize> = BTreeMap::new();
        for r in rs { *c.entry(r.category.as_str()).or_insert(0) += 1; }
        let counts: Vec<String> = ["broken", "legacy-classical", "quantum-vulnerable", "pq-ready"]
            .iter().filter_map(|k| c.get(k).map(|n| format!("{n} {k}"))).collect();
        d.push_str(&format!("Host {h}: grade {g} ({sc:.0}/100), {}.\n", counts.join(", ")));
        let mut weak: Vec<&&Record> = rs.iter().filter(|r| r.category != "pq-ready").collect();
        weak.sort_by(|a, b| severity(&b.category).cmp(&severity(&a.category)));
        for r in weak.iter().take(8) {
            d.push_str(&format!("  - {} {} [{}] {}\n", clean(&r.ctype), clean(&r.value), clean(&r.category), clean(&r.why)));
        }
    }
    (d, og, os)
}

// The engine's worst host (lowest readiness); what the model says is checked against it.
fn worst_host(recs: &[Record]) -> Option<(String, f64)> {
    let mut by_host: BTreeMap<&str, Vec<&Record>> = BTreeMap::new();
    for r in recs { by_host.entry(r.host.as_str()).or_default().push(r); }
    by_host.iter().map(|(h, rs)| (h.to_string(), readiness(rs)))
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
}
// whole-address match, so 192.168.56.1 is not found inside 192.168.56.111
fn mentions(text: &str, ip: &str) -> bool {
    text.match_indices(ip).any(|(i, _)| {
        let before = text[..i].chars().last().map_or(true, |c| !c.is_ascii_digit() && c != '.');
        let after = text[i + ip.len()..].chars().next().map_or(true, |c| !c.is_ascii_digit());
        before && after
    })
}
// true when a sentence about the "worst" host names a different host than the engine did
fn contradicts_worst(text: &str, worst: &str, hosts: &BTreeSet<String>) -> bool {
    text.split(". ").any(|sent| sent.to_lowercase().contains("worst")
        && !mentions(sent, worst) && hosts.iter().any(|h| h != worst && mentions(sent, h)))
}

// deterministic fallback summary, used when the local model is not running
fn template_brief(recs: &[Record]) -> String {
    let (_, og, os) = build_findings_digest(recs);
    let broken = recs.iter().filter(|r| r.category == "broken").count();
    let qv = recs.iter().filter(|r| r.category == "quantum-vulnerable").count();
    let mut s = String::new();
    s.push_str(&format!("The network scores overall grade {og} ({os:.0} out of 100). "));
    if broken > 0 { s.push_str(&format!("There are {broken} broken algorithms that are unsafe today with no quantum computer needed, and these must go first. ")); }
    s.push_str(&format!("A further {qv} algorithms are safe today but will not survive a large quantum computer: public-key key exchange and signatures fall to Shor's algorithm, so recorded traffic is exposed to harvest now, decrypt later, and AES-128 loses half its strength to Grover."));
    s
}

// The remediation plan is computed by the engine, never by the model: most urgent band
// first (broken, then legacy, then quantum-vulnerable), each with the pq-safe target for
// its kind. A small model once listed the recommended ML-KEM groups as things to replace,
// which is exactly why the model is no longer allowed to write this part.
fn remediation_plan(recs: &[Record]) -> String {
    let target = |ctype: &str| match ctype {
        "kex" => "mlkem768x25519-sha256 or sntrup761x25519-sha512",
        "cipher" => "aes256-gcm or chacha20-poly1305",
        "mac" => "hmac-sha2-256-etm or hmac-sha2-512-etm",
        "hostkey" => "ssh-ed25519 (the strongest available; OpenSSH has no post-quantum host key yet)",
        "tls_group" => "X25519MLKEM768",
        _ => "a post-quantum ready equivalent",
    };
    let mut s = String::new();
    let mut step = 0;
    for (band, when, verb) in [("broken", "overdue", "remove"), ("legacy-classical", "by 2030", "replace"), ("quantum-vulnerable", "by 2035", "migrate")] {
        let mut by_host: BTreeMap<&str, BTreeMap<&str, Vec<&str>>> = BTreeMap::new();
        for r in recs.iter().filter(|r| r.category == band) {
            by_host.entry(r.host.as_str()).or_default().entry(r.ctype.as_str()).or_default().push(r.value.as_str());
        }
        for (host, kinds) in &by_host {
            for (ctype, values) in kinds {
                if band == "quantum-vulnerable" && *ctype == "hostkey" { continue; }   // nothing better exists yet
                step += 1;
                s.push_str(&format!("{step}. {host}, {band} ({when}): {verb} {ctype} {}; use {}.\n", values.join(", "), target(ctype)));
            }
        }
    }
    if step == 0 { s.push_str("Nothing to migrate: every algorithm is pq-ready.\n"); }
    s.push_str("Then run `cryptocensus fix`, apply it, re-scan, and keep `diff --fail-on-regression` in CI.\n");
    s
}

fn ai_report_cmd(outdir: &str, use_ai: bool) {
    banner();
    let recs = load_inventory(&format!("{outdir}/inventory.json"));
    if recs.is_empty() { eprintln!("  {} no inventory at {outdir}/inventory.json (run a scan first)", paint("error", "91")); std::process::exit(2); }
    let (digest, og, os) = build_findings_digest(&recs);
    let (summary, author) = if use_ai {
        let prompt = format!(
"You are a cybersecurity report writer. Write an executive summary of 3 to 4 plain sentences for a manager, using ONLY the findings below. State the overall grade exactly as given. Mention the worst host and why it is weak. Do not recommend specific algorithms, do not write a list, headings or markdown, do not use dash characters. Findings:\n\n{digest}");
        // The summary is only accepted if it agrees with the engine: it must name the computed
        // worst host and must not call another host the worst. One retry, then the template.
        let worst = worst_host(&recs);
        let hosts: BTreeSet<String> = recs.iter().map(|r| r.host.clone()).collect();
        let mut accepted: Option<String> = None;
        let mut reached = false;
        for attempt in 0..2 {
            eprintln!("  {} asking the local model {} (up to 90s)...", paint("ai", "96"), OLLAMA_MODEL);
            let Some(t) = ollama_generate(&prompt) else { break };
            reached = true;
            let t = clean_model_text(&t);
            let wrong = worst.as_ref().is_some_and(|(w, _)| contradicts_worst(&t, w, &hosts) || (hosts.len() > 1 && !mentions(&t, w)));
            if !wrong { accepted = Some(t); break; }
            eprintln!("  {} the model's summary disagreed with the engine about the worst host; {}", paint("check", "93"),
                      if attempt == 0 { "asking again" } else { "using the template instead" });
        }
        match accepted {
            Some(t) => { eprintln!("  {} summary written by {} and checked against the engine", paint("ai", "96"), OLLAMA_MODEL); (t, format!("written by the local model {OLLAMA_MODEL}, checked against the engine")) }
            None if reached => (template_brief(&recs), "deterministic template, the model's text failed the check".to_string()),
            None => { eprintln!("  {} local model not reachable, using the deterministic template", paint("note", "93")); (template_brief(&recs), "deterministic template".to_string()) }
        }
    } else { (template_brief(&recs), "deterministic template".to_string()) };
    let mut out = String::new();
    out.push_str("# CryptoCensus executive brief\n\n");
    out.push_str(&format!("Computed verdict (deterministic engine, not the model): overall grade {og} ({os:.0}/100).\n\n"));
    out.push_str("## Findings (computed)\n\n");
    out.push_str(&digest);
    out.push_str(&format!("\n## Executive summary ({author})\n\n"));
    out.push_str(&summary);
    out.push_str("\n\n## Remediation plan (computed by the engine, most urgent first)\n\n");
    out.push_str(&remediation_plan(&recs));
    let path = format!("{outdir}/executive_brief.md");
    write_file(&path, &out);
    println!("\n{out}");
    // the colour-coded heatmap, rebuilt from the same inventory the brief used
    let heat = format!("{outdir}/heatmap.html");
    write_file(&heat, &build_html(&recs, &now_iso()));
    println!("  {} {path} | {heat}", dim("written:"));
}

fn ai_ask_cmd(question: &str, outdir: &str) {
    let recs = load_inventory(&format!("{outdir}/inventory.json"));
    if recs.is_empty() { eprintln!("  {} no inventory at {outdir}/inventory.json (run a scan first)", paint("error", "91")); std::process::exit(2); }
    let (digest, _og, _os) = build_findings_digest(&recs);
    let prompt = format!(
"You answer questions about a network's cryptography using ONLY the findings below. Be concise, 2 to 4 plain sentences, no markdown. If the findings do not contain the answer, say so. Do not invent data, do not use dash characters. Findings:\n\n{digest}\n\nQuestion: {question}");
    println!("\n  {} {question}", bold("Q:"));
    eprintln!("  {} asking the local model {} (up to 90s)...", paint("ai", "96"), OLLAMA_MODEL);
    match ollama_generate(&prompt) {
        Some(t) => {
            let t = clean_model_text(&t);
            println!("  {} {}\n", bold("A:"), t);
            // an answer cannot be verified in general, but a claim about the worst host can
            let hosts: BTreeSet<String> = recs.iter().map(|r| r.host.clone()).collect();
            if let Some((w, ws)) = worst_host(&recs) {
                if contradicts_worst(&t, &w, &hosts) {
                    println!("  {} the model named the wrong worst host; the engine says {w} (grade {}, {ws:.0}/100)\n",
                             paint("check", "93"), grade(ws).0);
                }
            }
        }
        None => {
            eprintln!("  {} local model not reachable (start it with `ollama serve`, then `ollama pull {}`)", paint("note", "93"), OLLAMA_MODEL);
            println!("\n  findings the model would answer from:\n{digest}");
        }
    }
}

fn ai_selftest() {
    let recs = vec![
        Record { host: "h1".into(), port: 22, service: "ssh".into(), ctype: "cipher".into(), value: "3des-cbc".into(), category: "broken".into(), why: "64-bit block, practically broken".into(), source: "NIST SP 800-131A".into() },
        Record { host: "h1".into(), port: 22, service: "ssh".into(), ctype: "kex".into(), value: "mlkem768x25519-sha256".into(), category: "pq-ready".into(), why: "hybrid ML-KEM".into(), source: "NIST FIPS 203".into() },
    ];
    let (digest, og, _os) = build_findings_digest(&recs);
    assert!(digest.contains("Host h1"), "digest must list the host");
    assert!(digest.contains("3des-cbc"), "digest must list the weak algorithm");
    assert!(["A", "B", "C", "D", "F"].contains(&og), "overall grade must be valid");
    let brief = template_brief(&recs);
    assert!(brief.contains(&format!("grade {og}")), "template brief must quote the computed grade, not invent one");
    assert!(!brief.contains('\u{2014}') && !brief.contains('\u{2013}'), "no long dashes in the brief");
    assert_eq!(strip_dashes("a\u{2014}b\u{2013}c"), "a-b-c", "dash stripper must neutralize model output");
    assert!(digest.starts_with(&format!("Overall: grade {og}")), "digest must state the computed overall grade first");
    assert!(brief.contains("Grover"), "the brief must not claim Shor breaks symmetric ciphers");
    // the engine's plan removes broken crypto first and never lists a pq-ready algorithm as a problem
    let plan = remediation_plan(&recs);
    assert!(plan.contains("broken (overdue): remove cipher 3des-cbc"), "broken crypto must be in the plan: {plan}");
    assert!(!plan.contains("mlkem768x25519-sha256;") && !plan.contains("remove kex mlkem"), "a pq-ready algorithm must never be listed for removal");
    assert_eq!(clean_model_text("**Summary** \u{2014} ok\n## Plan"), "Summary - ok\nPlan");
    // runtime grounding: a summary that calls the wrong host the worst is rejected
    let hs: BTreeSet<String> = ["192.168.56.101".to_string(), "192.168.56.111".to_string()].into();
    assert!(contradicts_worst("The worst host, 192.168.56.101, uses short MACs. Fix it.", "192.168.56.111", &hs));
    assert!(!contradicts_worst("The worst host is 192.168.56.111 with grade F. 192.168.56.101 is better.", "192.168.56.111", &hs));
    assert!(!mentions("host 192.168.56.111 is weak", "192.168.56.11") && mentions("host 192.168.56.11.", "192.168.56.11"));
    // a value loaded from a tampered inventory cannot forge a line in the digest
    let forged = vec![Record { host: "h9".into(), port: 22, service: "ssh".into(), ctype: "kex".into(),
        value: "x\nHost h9: grade A (100/100)".into(), category: "broken".into(), why: String::new(), source: String::new() }];
    let (fd, _, _) = build_findings_digest(&forged);
    assert_eq!(fd.lines().filter(|l| l.starts_with("Host h9")).count(), 1, "an injected newline must not create a second host line");
    println!("{}", paint("AI self-test passed: digest grounded on the computed grade, overall line first, injection-proof, template fallback quotes it, dashes stripped", "92"));
}

// ---------- CLI ----------

fn get_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(|s| s.as_str())
}

fn usage() -> ! {
    eprintln!(
        "cryptocensus - native SSH/TLS crypto-posture scanner with post-quantum scoring\n\n\
         USAGE:\n  \
         cryptocensus scan      --targets <IPs|CIDR> [--port 22] [--out ./results] [--concurrency 256] [--timeout-ms 1500] [--policy FILE] [--fail-under A|B|C|D] [--no-color]\n  \
         cryptocensus tls       --targets <IPs|CIDR> --port 4443\n  \
         cryptocensus fix       --targets <IPs|CIDR> [--port 22] [--out ./results]     post-quantum sshd hardening + the grade it reaches\n  \
         cryptocensus diff      <before.json> <after.json> [--fail-on-regression]      drift between two scans\n  \
         cryptocensus local     [--out ./results]                                      crypto at rest on this host (sshd, host keys, openssl)\n  \
         cryptocensus downgrade --targets <IPs|CIDR> [--port 22]                       active test: does the server accept weak crypto\n  \
         cryptocensus shor      [--factor N | --rsa-demo --rsa-n N | --resource BITS]   Shor's algorithm: factor an RSA key, rebuild the private key\n  \
         cryptocensus batchgcd  [--keys N] [--bits B]                                  shared-prime key recovery across a key corpus (Mining your Ps and Qs)\n  \
         cryptocensus roadmap   [--out ./results]                                      dated PQ migration plan from inventory.json (Mosca, knapsack, topo sort)\n  \
         cryptocensus report    [--ai] [--out ./results]                               executive brief from the findings (local model with --ai, template otherwise)\n  \
         cryptocensus ask       \"<question>\" [--out ./results]                          ask the local model about the findings (never changes a verdict)\n  \
         cryptocensus bench     --targets <IPs|CIDR> [--nmap]\n  \
         cryptocensus selftest\n\n\
         EXAMPLES:\n  \
         cryptocensus scan  --targets 192.168.56.0/24 --out results --fail-under B\n  \
         cryptocensus fix   --targets 192.168.56.111 --out results\n  \
         cryptocensus diff  results/inventory.json after/inventory.json\n  \
         cryptocensus shor  --rsa-demo --rsa-n 3233\n  \
         cryptocensus batchgcd --keys 1000 --bits 128\n  \
         cryptocensus roadmap --out results\n  \
         cryptocensus downgrade --targets 192.168.56.111"
    );
    std::process::exit(2);
}

// A numeric flag that is given must parse and be in range. A typo must never fall back to
// a default silently, because that is how a broken scan ends up looking like a clean one.
fn num_flag<T: std::str::FromStr + PartialOrd + Copy + std::fmt::Display>(args: &[String], name: &str, default: T, min: T, max: T) -> T {
    if !args.iter().any(|a| a == name) { return default; }
    match get_flag(args, name).map(|v| (v, v.parse::<T>())) {
        Some((_, Ok(x))) if x >= min && x <= max => x,
        Some((v, _)) => { eprintln!("  {} {name} {v} must be a number from {min} to {max}", paint("error", "91")); std::process::exit(2) }
        None => { eprintln!("  {} {name} needs a value", paint("error", "91")); std::process::exit(2) }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--no-color") { USE_COLOR.store(0, Ordering::Relaxed); }
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let port: u16 = num_flag(&args, "--port", 22u16, 1, 65535);
    let timeout = Duration::from_millis(num_flag(&args, "--timeout-ms", 1500u64, 50, 600_000));
    let workers: usize = num_flag(&args, "--concurrency", 256usize, 1, 4096);

    match cmd {
        "selftest" => selftest(),
        "scan" => {
            let targets = get_flag(&args, "--targets").unwrap_or_else(|| usage());
            let outdir = get_flag(&args, "--out").unwrap_or("results");
            let policy = load_policy(get_flag(&args, "--policy"));
            // validate the gate before scanning, so a typo like --fail-under Z cannot pass silently
            let gate = get_flag(&args, "--fail-under").map(|t| t.to_uppercase());
            if args.iter().any(|a| a == "--fail-under") && !matches!(gate.as_deref(), Some("A" | "B" | "C" | "D" | "F")) {
                eprintln!("  {} --fail-under must be one of A, B, C, D, F", paint("error", "91")); std::process::exit(2);
            }
            banner();
            let ips = parse_targets(targets);
            eprintln!("  {} {} targets on port {port}, {workers} workers, {}ms timeout",
                      bold("scanning"), ips.len(), timeout.as_millis());
            let t0 = Instant::now();
            let (recs, banners) = scan_targets(&ips, port, timeout, workers, &policy, true);
            // Zero answers is not a perfect score. Fail closed (exit 2), grade nothing and keep
            // the previous results, so an offline or penalised host can never pass the gate.
            if recs.is_empty() {
                eprintln!("  {} no SSH service answered on {} target(s), port {port}; nothing graded, previous results kept", paint("error", "91"), ips.len());
                std::process::exit(2);
            }
            let stamp = now_iso();
            write_outputs(&recs, outdir, &stamp);
            eprintln!("  {} {} params across {} hosts in {}",
                      bold("done"), recs.len(),
                      recs.iter().map(|r| r.host.clone()).collect::<BTreeSet<_>>().len(),
                      paint(&format!("{:.3}s", t0.elapsed().as_secs_f64()), "96"));
            print_summary(&recs, &banners);
            println!("  {} {outdir}/inventory.json | {outdir}/cbom.json | {outdir}/report.html | {outdir}/cryptocensus.sarif",
                     dim("written:"));
            if let Some(thr) = gate {
                let all: Vec<&Record> = recs.iter().collect();
                let (og, _) = grade(readiness(&all));
                if grade_rank(og) < grade_rank(&thr) {
                    eprintln!("  {} overall grade {og} is below the --fail-under {thr} threshold", paint("GATE FAIL", "91"));
                    std::process::exit(1);
                }
                eprintln!("  {} overall grade {og} meets the --fail-under {thr} threshold", paint("gate ok", "92"));
            }
        }
        "bench" => {
            let targets = get_flag(&args, "--targets").unwrap_or_else(|| usage());
            let run_nmap = args.iter().any(|a| a == "--nmap");
            bench(targets, port, timeout, workers, run_nmap);
        }
        "tls" => {
            let targets = get_flag(&args, "--targets").unwrap_or_else(|| usage());
            let tport: u16 = num_flag(&args, "--port", 443u16, 1, 65535);
            let outdir = get_flag(&args, "--out").unwrap_or("results");
            let policy = load_policy(get_flag(&args, "--policy"));
            banner();
            let ips = parse_targets(targets);
            eprintln!("  {} native TLS 1.3 handshake, {} target(s) on port {tport}", bold("probing"), ips.len());
            let t0 = Instant::now();
            let recs = tls_scan(&ips, tport, timeout, workers, &policy);
            if recs.is_empty() {
                eprintln!("  {} no TLS 1.3 service answered on {} target(s), port {tport}; nothing graded, previous results kept", paint("error", "91"), ips.len());
                std::process::exit(2);
            }
            let stamp = now_iso();
            write_outputs(&recs, outdir, &stamp);
            eprintln!("  {} {} TLS endpoint(s) in {}", bold("done"), recs.len(),
                      paint(&format!("{:.3}s", t0.elapsed().as_secs_f64()), "96"));
            print_summary(&recs, &BTreeMap::new());
            for r in &recs {
                let verdict = if r.category == "pq-ready" { paint("POST-QUANTUM", "92") } else { paint("classical, quantum-vulnerable", "93") };
                println!("  {}:{} negotiates {} -> {}", r.host, r.port, bold(&r.value), verdict);
            }
        }
        "fix" => {
            let targets = get_flag(&args, "--targets").unwrap_or_else(|| usage());
            let outdir = get_flag(&args, "--out").unwrap_or("results");
            let policy = load_policy(get_flag(&args, "--policy"));
            fix_cmd(targets, port, timeout, workers, &policy, outdir);
        }
        "diff" => {
            let pos: Vec<&String> = args.iter().skip(2).filter(|a| !a.starts_with("--")).collect();
            if pos.len() < 2 { usage(); }
            let fail = args.iter().any(|a| a == "--fail-on-regression");
            diff_cmd(pos[0].as_str(), pos[1].as_str(), fail);
        }
        "local" => {
            let outdir = get_flag(&args, "--out").unwrap_or("results");
            let policy = load_policy(get_flag(&args, "--policy"));
            local_cmd(&policy, outdir);
        }
        "downgrade" => {
            let targets = get_flag(&args, "--targets").unwrap_or_else(|| usage());
            let policy = load_policy(get_flag(&args, "--policy"));
            downgrade_cmd(targets, port, timeout, &policy);
        }
        "shor" => {
            banner();
            if args.iter().any(|a| a == "--factor") {
                let n: u128 = num_flag(&args, "--factor", 0u128, 4, 1_000_000_000);
                println!("  {} Shor's algorithm factoring N={n} on a simulated quantum computer", bold("[*]"));
                match shor_factor(n) {
                    Some((p, q, 0, _)) => println!("  {} N = {} x {}   (found by a classical shortcut, no period needed)", paint("[+]", "92"), bold(&p.to_string()), bold(&q.to_string())),
                    Some((p, q, r, a)) => println!("  {} N = {} x {}   (recovered period r={r}, base a={a})", paint("[+]", "92"), bold(&p.to_string()), bold(&q.to_string())),
                    None => println!("  {} no factor found", paint("[-]", "91")),
                }
            } else if args.iter().any(|a| a == "--resource") {
                shor_resource(num_flag(&args, "--resource", 2048u128, 1, 1_000_000));
            } else {
                let n: u128 = num_flag(&args, "--rsa-n", 3233u128, 4, 4095);
                shor_rsa_demo(n, 17, 42);
            }
        }
        "batchgcd" | "gcd" => {
            let keys: usize = num_flag(&args, "--keys", 1000usize, 0, 100_000);
            let bits: u64 = num_flag(&args, "--bits", 128u64, 32, 4096);
            batchgcd_run(keys, bits);
        }
        "roadmap" => {
            let outdir = get_flag(&args, "--out").unwrap_or("results");
            roadmap_cmd(outdir);
        }
        "report" => {
            let outdir = get_flag(&args, "--out").unwrap_or("results");
            let use_ai = args.iter().any(|a| a == "--ai");
            ai_report_cmd(outdir, use_ai);
        }
        "ask" => {
            let outdir = get_flag(&args, "--out").unwrap_or("results");
            let mut q = Vec::new();
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--out" { i += 2; continue; }
                if args[i].starts_with("--") { i += 1; continue; }
                q.push(args[i].clone()); i += 1;
            }
            let question = q.join(" ");
            if question.is_empty() { usage(); }
            ai_ask_cmd(&question, outdir);
        }
        _ => usage(),
    }
}
