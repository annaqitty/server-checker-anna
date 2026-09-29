#!/usr/bin/env python3
"""mail_server_checker_fast.py — mass verification of public SMTP/IMAP/POP3.

Asyncio rewrite of mail_server_checker.py for very large lists (1 GB+).

Speed comes from:
  * asyncio (no threads) — thousands of in-flight probes
  * built-in pipelined UDP DNS client (EDNS0, retries, multi-resolver)
  * cross-domain caching of host resolution and probe results
  * multi-process sharding (--processes N) + merged CSV output

Requires Python 3.11+. Optional: pip install uvloop (Linux/macOS).

Examples:
  py mail_server_checker_fast.py domains.txt --mode fast --processes 8
  py mail_server_checker_fast.py domains.txt --resolvers 127.0.0.1,1.1.1.1 --timeout 1.5
  py mail_server_checker_fast.py domains.txt --mode mx            (fastest)
"""

import argparse
import asyncio
import csv
import ipaddress
import multiprocessing
import random
import re
import socket
import ssl
import struct
import sys
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

try:
    import uvloop  # optional, Linux/macOS only
except ImportError:
    uvloop = None

# Reuse the huge prefix lists from the original script if present.
try:
    from mail_server_checker import (ALL_SMTP_PREFIXES, ALL_IMAP_PREFIXES,
                                     ALL_POP3_PREFIXES)
except ImportError:
    ALL_SMTP_PREFIXES = ALL_IMAP_PREFIXES = ALL_POP3_PREFIXES = ()

FAST_SMTP_PREFIXES = ("smtp", "mail", "submission", "outgoing", "email", "relay", "mx", "smtp1", "mail1")
FAST_IMAP_PREFIXES = ("imap", "mail", "imap4", "email", "incoming", "mail1")
FAST_POP3_PREFIXES = ("pop", "pop3", "mail", "email", "incoming", "mail1")

TIMEOUT = 1.5
MAX_MX = 5
OUTPUT_COLUMNS = ["Domain", "Host", "Port", "SSL", "Security", "Verification"]
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
IMPLICIT_TLS_PORTS = {465, 993, 995}
SRV_SERVICES = (("_submission._tcp", "smtp", 587), ("_submissions._tcp", "smtp", 465),
                ("_imaps._tcp", "imap", 993), ("_imap._tcp", "imap", 143),
                ("_pop3s._tcp", "pop3", 995), ("_pop3._tcp", "pop3", 110))
_MISS = object()


# --------------------------------------------------------------------------- DNS

def build_query(qid, qname, qtype):
    out = bytearray(struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1))  # RD, 1 question, 1 OPT
    for label in qname.rstrip(".").split("."):
        b = label.encode("ascii", "replace")[:63] or b"x"
        out += bytes((len(b),)) + b
    out += b"\x00" + struct.pack(">HH", qtype, 1)
    out += b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)  # EDNS0
    return bytes(out)


def parse_name(msg, off):
    labels, pos, end, steps = [], off, -1, 0
    while True:
        steps += 1
        if steps > 100 or pos >= len(msg):
            raise ValueError("bad name")
        l = msg[pos]
        if l == 0:
            if end < 0:
                end = pos + 1
            break
        if l & 0xC0:                                   # compression pointer
            if pos + 1 >= len(msg):
                raise ValueError("bad pointer")
            ptr = ((l & 0x3F) << 8) | msg[pos + 1]
            if end < 0:
                end = pos + 2
            pos = ptr
            continue
        if pos + 1 + l > len(msg):
            raise ValueError("bad label")
        labels.append(msg[pos + 1: pos + 1 + l])
        pos += 1 + l
    return b".".join(labels).decode("ascii", "replace").lower(), end


def parse_response(msg):
    if len(msg) < 12:
        return None
    _qid, flags, qd, an, _ns, _ar = struct.unpack_from(">HHHHHH", msg, 0)
    if not flags & 0x8000:                              # not a response
        return None
    rcode, off = flags & 0x000F, 12
    try:
        for _ in range(qd):
            _n, off = parse_name(msg, off)
            off += 4
        answers = []
        for _ in range(an):
            _n, off = parse_name(msg, off)
            rtype, _rclass, _ttl, rdlen = struct.unpack_from(">HHIH", msg, off)
            off += 10
            if off + rdlen > len(msg):
                return None
            answers.append((rtype, off, rdlen))
            off += rdlen
    except ValueError:
        return None
    return rcode, answers, msg


class _DnsProto(asyncio.DatagramProtocol):
    __slots__ = ("transport", "futures")

    def __init__(self):
        self.transport = None
        self.futures = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, _addr):
        if len(data) < 12:
            return
        fut = self.futures.pop(data[0] << 8 | data[1], None)
        if fut is not None and not fut.done():
            fut.set_result(data)

    def error_received(self, _exc):
        pass


class DnsClient:
    """Pipelined UDP DNS client: many queries in flight per socket, demuxed by ID."""

    def __init__(self, addrs, timeout, sockets_per, inflight):
        self.addrs = addrs
        self.timeout = timeout
        self.sockets_per = sockets_per
        self.inflight = inflight
        self.protos = []
        self.sem = None
        self.stats = {"queries": 0, "timeouts": 0, "errors": 0}

    async def start(self):
        loop = asyncio.get_running_loop()
        for ip, port in self.addrs:
            for _ in range(self.sockets_per):
                proto = _DnsProto()
                try:
                    await loop.create_datagram_endpoint(lambda pr=proto: pr, remote_addr=(ip, port))
                except OSError:
                    break
                self.protos.append(proto)
        if not self.protos:
            raise RuntimeError(f"could not open DNS sockets to {self.addrs}")
        self.sem = asyncio.Semaphore(len(self.protos) * self.inflight)

    def close(self):
        for p in self.protos:
            try:
                p.transport.close()
            except Exception:
                pass

    def _pick(self):
        best, best_n = self.protos[0], len(self.protos[0].futures)
        if best_n:
            for p in self.protos[1:]:
                n = len(p.futures)
                if n < best_n:
                    best, best_n = p, n
                    if not n:
                        break
        return best

    async def query(self, qname, qtype):
        """Return (rcode, answers, msg) or None on transport/parse failure."""
        async with self.sem:
            proto = self._pick()
            qid = random.getrandbits(16)
            while qid in proto.futures:
                qid = random.getrandbits(16)
            packet = build_query(qid, qname, qtype)
            loop = asyncio.get_running_loop()
            for _attempt in (0, 1):                     # one UDP retransmit
                fut = loop.create_future()
                proto.futures[qid] = fut
                data = None
                try:
                    proto.transport.sendto(packet)
                    self.stats["queries"] += 1
                    data = await asyncio.wait_for(fut, self.timeout)
                except asyncio.TimeoutError:
                    self.stats["timeouts"] += 1
                except OSError:
                    self.stats["errors"] += 1
                    return None
                finally:
                    if proto.futures.get(qid) is fut:
                        del proto.futures[qid]
                if data is not None:
                    return parse_response(data)
            return None

    async def mx(self, domain):
        res = await self.query(domain, 15)
        if res is None or res[0] != 0:
            return []
        out = []
        for rtype, off, rdlen in res[1]:
            if rtype != 15 or rdlen < 3:
                continue
            pref = struct.unpack_from(">H", res[2], off)[0]
            try:
                name, _ = parse_name(res[2], off + 2)
            except ValueError:
                continue
            if name and name != ".":
                out.append((pref, name))
        out.sort(key=lambda t: (t[0], t[1]))
        return [name for _pref, name in out[:MAX_MX]]

    async def srv(self, domain):
        found = []
        for service, proto, default_port in SRV_SERVICES:
            res = await self.query(f"{service}.{domain}", 33)
            if res is None or res[0] != 0:
                continue
            recs = []
            for rtype, off, rdlen in res[1]:
                if rtype != 33 or rdlen < 8:
                    continue
                prio, _weight, port = struct.unpack_from(">HHH", res[2], off)
                try:
                    target, _ = parse_name(res[2], off + 6)
                except ValueError:
                    continue
                if target and target != ".":
                    recs.append((prio, port, target))
            for _prio, port, target in sorted(recs)[:3]:
                if port == default_port:
                    found.append((proto, target, port))
        return found


async def resolve_host(client, host, cache):
    hit = cache.get(host, _MISS)
    if hit is not _MISS:
        return hit
    ip = None
    res = await client.query(host, 1)                   # A
    if res is not None and res[0] == 0:
        ip = extract_ip(res, 1)
        if ip is None:
            res6 = await client.query(host, 28)         # AAAA-only host
            if res6 is not None and res6[0] == 0:
                ip = extract_ip(res6, 28)
    elif res is None:                                   # transport error, try AAAA
        res6 = await client.query(host, 28)
        if res6 is not None and res6[0] == 0:
            ip = extract_ip(res6, 28)
    cache.put(host, ip)                                 # NXDOMAIN is cached too
    return ip


def extract_ip(res, want):
    for rtype, off, rdlen in res[1]:
        if rtype != want:
            continue
        try:
            return str(ipaddress.ip_address(res[2][off:off + rdlen]))
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------- probes

async def read_smtp_response(reader):
    data = bytearray()
    for _ in range(50):
        line = await reader.readline()
        if not line:
            break
        data += line
        if len(line) < 4 or line[3:4] != b"-":
            break
    return bytes(data)


async def ehlo(reader, writer, host):
    writer.write(f"EHLO {host}\r\n".encode())
    try:
        await writer.drain()
    except OSError:
        return None
    return await read_smtp_response(reader)


async def smtp_flow(reader, writer, host, port, ctx):
    if not (await reader.readline()).startswith(b"220"):
        return None
    resp = await ehlo(reader, writer, host)
    if resp is None or not resp.startswith(b"250"):
        return None
    if port == 465:
        return "implicit_tls"
    if b"STARTTLS" in resp.upper():
        writer.write(b"STARTTLS\r\n")
        try:
            await writer.drain()
            if not (await reader.readline()).startswith(b"220"):
                return "none" if port == 25 else None
            await writer.start_tls(ctx, server_hostname=host)
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            return "none" if port == 25 else None       # EHLO already verified plaintext
        resp = await ehlo(reader, writer, host)
        if resp is not None and resp.startswith(b"250"):
            return "starttls"
        return None
    return "none" if port == 25 else None               # 587 without STARTTLS is rejected


async def imap_cap(reader, writer, tag):
    writer.write(tag + b" CAPABILITY\r\n")
    try:
        await writer.drain()
    except OSError:
        return None
    caps = bytearray()
    while True:
        line = await reader.readline()
        if not line:
            return None
        if line.startswith(tag + b" "):
            return bytes(caps) if line.split(None, 2)[1] == b"OK" else None
        if len(caps) < 65536:
            caps += line


async def imap_flow(reader, writer, host, port, ctx):
    greet = await reader.readline()
    if not (greet.startswith(b"* OK") or greet.startswith(b"* PREAUTH")):
        return None
    caps = await imap_cap(reader, writer, b"a1")
    if caps is None:
        return None
    if port != 143 or b"STARTTLS" not in caps.upper():
        return "implicit_tls" if port == 993 else "none"
    try:
        writer.write(b"a2 STARTTLS\r\n")
        await writer.drain()
        ok = False
        while True:
            line = await reader.readline()
            if not line:
                return None
            if line.startswith(b"a2 "):
                ok = line.split(None, 2)[1] == b"OK"
                break
        if not ok:
            return None
        await writer.start_tls(ctx, server_hostname=host)
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        return None
    return "starttls" if (await imap_cap(reader, writer, b"a3")) is not None else None


async def pop3_flow(reader, writer, host, port, ctx):
    if not (await reader.readline()).startswith(b"+OK"):
        return None
    sec = "implicit_tls" if port == 995 else "none"
    capa = b""
    try:
        writer.write(b"CAPA\r\n")                       # CAPA is optional in POP3
        await writer.drain()
        if (await reader.readline()).startswith(b"+OK"):
            chunks = bytearray()
            while True:
                line = await reader.readline()
                if not line or line.strip() == b".":
                    break
                if len(chunks) < 65536:
                    chunks += line
            capa = bytes(chunks)
        if port == 110 and b"STLS" in capa.upper():
            writer.write(b"STLS\r\n")
            await writer.drain()
            if (await reader.readline()).startswith(b"+OK"):
                await writer.start_tls(ctx, server_hostname=host)
                sec = "starttls"
        writer.write(b"NOOP\r\n")
        await writer.drain()
        return sec if (await reader.readline()).startswith(b"+OK") else None
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        return None


async def probe(host, ip, proto, port, ctx, timeout):
    writer = None
    try:
        async with asyncio.timeout(timeout):
            ssl_arg = ctx if port in IMPLICIT_TLS_PORTS else None
            reader, writer = await asyncio.open_connection(
                ip, port, ssl=ssl_arg, server_hostname=host if ssl_arg else None)
            try:
                sock = writer.get_extra_info("socket")
                if sock is not None:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            if proto == "smtp":
                return await smtp_flow(reader, writer, host, port, ctx)
            if proto == "imap":
                return await imap_flow(reader, writer, host, port, ctx)
            return await pop3_flow(reader, writer, host, port, ctx)
    except Exception:
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def probe_cached(host, ip, proto, port, ctx, timeout, cache):
    key = (proto, host, port)
    hit = cache.get(key, _MISS)
    if hit is not _MISS:
        return hit
    sec = await probe(host, ip, proto, port, ctx, timeout)
    cache.put(key, sec)
    return sec


# --------------------------------------------------------------------------- helpers

class BoundedCache(dict):
    __slots__ = ("cap",)

    def __init__(self, cap):
        super().__init__()
        self.cap = cap

    def put(self, key, value):
        if len(self) >= self.cap:
            self.clear()
        self[key] = value


def clean_domain_bytes(raw):
    line = raw.decode("utf-8", "ignore").strip()
    if not line or line[0] == "#":
        return None
    if DOMAIN_RE.fullmatch(line):                       # fast path: already clean
        return line
    low = line.lower()
    if "://" not in low:
        low = "//" + low
    try:
        host = urlsplit(low).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return host if DOMAIN_RE.fullmatch(host) else None


def build_mode_cfg(mode):
    """(use_mx, use_srv, bare_hosts, prefix_groups)"""
    if mode == "mx":
        return (True, False, (), ())
    bare = (("smtp", (25, 465, 587)), ("imap", (143, 993)), ("pop3", (110, 995)))
    if mode == "all":
        smtp, imap, pop = ALL_SMTP_PREFIXES, ALL_IMAP_PREFIXES, ALL_POP3_PREFIXES
        if not smtp:
            print("[WARN] mail_server_checker.py not found beside this script; "
                  "using fast prefixes for --mode all", file=sys.stderr)
            smtp, imap, pop = FAST_SMTP_PREFIXES, FAST_IMAP_PREFIXES, FAST_POP3_PREFIXES
        return (True, True, bare,
                (("smtp", (25, 465, 587, 2525, 26), tuple(smtp)),
                 ("imap", (143, 993), tuple(imap)),
                 ("pop3", (110, 995), tuple(pop))))
    return (True, False, bare,
            (("smtp", (25, 465, 587), FAST_SMTP_PREFIXES),
             ("imap", (143, 993), FAST_IMAP_PREFIXES),
             ("pop3", (110, 995), FAST_POP3_PREFIXES)))


def parse_resolvers(spec):
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            ip, _, port = part.rpartition(":")
            out.append((ip, int(port)))
        else:
            out.append((part, 53))
    return out or [("1.1.1.1", 53)]


def estimate_lines(path):
    size = path.stat().st_size
    with open(path, "rb") as f:
        sample = f.read(1 << 20)
    lines = sample.count(b"\n") or 1
    return max(int(size / max(len(sample) / lines, 1)), 1)


def fmt_eta(seconds):
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"


# --------------------------------------------------------------------------- worker

async def handle_domain(domain, args, cfg, client, ctx, sem, probe_sem, out_q, rc, pc, counters):
    try:
        counters["domains"] += 1
        mx_on, srv_on, bare, groups = cfg
        hosts = {}

        def add(proto, host, port):
            entry = hosts.get(host)
            if entry is None:
                hosts[host] = [(proto, port)]
            elif (proto, port) not in entry:
                entry.append((proto, port))

        if mx_on:
            for h in await client.mx(domain):
                if len(h) <= 253 and DOMAIN_RE.fullmatch(h):
                    add("smtp", h, 25)
        if srv_on:
            for proto, h, port in await client.srv(domain):
                add(proto, h, port)
        for proto, ports, prefixes in groups:
            for p in prefixes:
                h = p + "." + domain
                if len(h) <= 253:
                    for port in ports:
                        add(proto, h, port)
        for proto, ports in bare:
            for port in ports:
                add(proto, domain, port)

        names = list(hosts)
        ips = await asyncio.gather(*(resolve_host(client, n, rc) for n in names))
        jobs = [(n, ip, hosts[n]) for n, ip in zip(names, ips) if ip]
        counters["resolved"] += len(jobs)
        if not jobs:
            return
        flat = [(proto, n, ip, port) for n, ip, pairs in jobs for proto, port in pairs]
        counters["probes"] += len(flat)

        async def job(item):
            proto, host, ip, port = item
            async with probe_sem:
                sec = await probe_cached(host, ip, proto, port, ctx, args.timeout, pc)
            if sec:
                counters["rows_" + proto] += 1
                await out_q.put((proto, (domain, host, port, int(sec != "none"), sec,
                                         "protocol_handshake")))

        await asyncio.gather(*(job(item) for item in flat))
    except Exception:
        counters["errors"] += 1
    finally:
        sem.release()


async def run_shard(args, shard, count, est_lines, cfg):
    start = time.monotonic()
    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    client = DnsClient(parse_resolvers(args.resolvers), args.timeout,
                       args.dns_sockets, args.dns_inflight)
    await client.start()
    sem = asyncio.Semaphore(args.concurrency)
    probe_sem = asyncio.Semaphore(args.probe_concurrency)
    out_q = asyncio.Queue(maxsize=65536)
    counters = defaultdict(int)
    rc, pc = BoundedCache(args.cache), BoundedCache(args.cache)

    files = {}
    for proto in ("smtp", "imap", "pop3"):
        name = f"{args.out}-{proto}.csv" if count == 1 else f"{args.out}-{proto}.s{shard}.csv"
        f = open(name, "w", newline="", encoding="utf-8-sig", buffering=1 << 20)
        w = csv.writer(f)
        w.writerow(OUTPUT_COLUMNS)
        files[proto] = (f, w)

    async def writer_loop():
        while True:
            item = await out_q.get()
            if item is None:
                break
            proto, row = item
            files[proto][1].writerow(row)
            counters["rows_" + proto] += 1
        for f, _w in files.values():
            f.flush()

    async def stats_loop():
        est = max(est_lines // count, 1)
        while True:
            await asyncio.sleep(10)
            elapsed = time.monotonic() - start
            done = counters["domains"]
            rate = done / max(elapsed, 1e-6)
            eta = (est - done) / rate if rate > 0 and done < est else 0
            print(f"[s{shard}] {rate:,.0f} dom/s | {done:,}/{est:,} domains "
                  f"| dns {client.stats['queries']:,} (t/o {client.stats['timeouts']:,}) "
                  f"| resolved {counters['resolved']:,} | probes {counters['probes']:,} "
                  f"| rows smtp {counters['rows_smtp']:,} imap {counters['rows_imap']:,} "
                  f"pop3 {counters['rows_pop3']:,}"
                  f"{' | ETA ' + fmt_eta(eta) if eta else ''}", file=sys.stderr, flush=True)

    wtask = asyncio.create_task(writer_loop())
    stask = asyncio.create_task(stats_loop())
    tasks = set()
    with open(args.input, "rb") as src:
        for lineno, raw in enumerate(src):
            if lineno % count != shard:
                continue
            domain = clean_domain_bytes(raw)
            if domain is None:
                continue
            await sem.acquire()
            t = asyncio.create_task(handle_domain(domain, args, cfg, client, ctx, sem,
                                                  probe_sem, out_q, rc, pc, counters))
            tasks.add(t)
            t.add_done_callback(tasks.discard)

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    await out_q.put(None)
    await wtask
    stask.cancel()
    for f, _w in files.values():
        f.close()
    client.close()
    print(f"[s{shard}] finished in {fmt_eta(time.monotonic() - start)} | "
          f"domains {counters['domains']:,} | resolved {counters['resolved']:,} "
          f"| probes {counters['probes']:,} | rows smtp {counters['rows_smtp']:,} "
          f"imap {counters['rows_imap']:,} pop3 {counters['rows_pop3']:,} "
          f"| errors {counters['errors']:,}", file=sys.stderr, flush=True)


def child_entry(args, shard, count, est, cfg):
    if uvloop is not None:
        try:
            uvloop.install()
        except Exception:
            pass
    try:
        asyncio.run(run_shard(args, shard, count, est, cfg))
    except KeyboardInterrupt:
        pass


def merge_outputs(args):
    for proto in ("smtp", "imap", "pop3"):
        final = Path(f"{args.out}-{proto}.csv")
        shards = [Path(f"{args.out}-{proto}.s{i}.csv") for i in range(args.processes)]
        shards = [p for p in shards if p.exists()]
        if not shards:
            continue
        rows = 0
        with open(final, "w", newline="", encoding="utf-8-sig") as out:
            w = csv.writer(out)
            w.writerow(OUTPUT_COLUMNS)
            for p in shards:
                with open(p, newline="", encoding="utf-8-sig") as src:
                    r = csv.reader(src)
                    try:
                        next(r)
                    except StopIteration:
                        continue
                    for row in r:
                        w.writerow(row)
                        rows += 1
                p.unlink()
        print(f"{proto.upper()}: {rows:,} verified endpoints -> {final}")


# --------------------------------------------------------------------------- CLI

def parse_args():
    p = argparse.ArgumentParser(description="Mass-verify public SMTP/IMAP/POP3 services (async).")
    p.add_argument("input", help="domain .txt file")
    p.add_argument("--mode", choices=("mx", "fast", "all"), default="fast",
                   help="mx = only MX hosts:25 | fast = MX + common names | all = huge prefix list (very slow)")
    p.add_argument("--processes", type=int, default=min(__import__('os').cpu_count() or 4, 8))
    p.add_argument("--concurrency", type=int, default=2000, help="domains in flight per process")
    p.add_argument("--probe-concurrency", type=int, default=8192, help="max simultaneous handshakes per process")
    p.add_argument("--timeout", type=float, default=TIMEOUT)
    p.add_argument("--resolvers", default="1.1.1.1,8.8.8.8,9.9.9.9,149.112.112.112",
                   help="comma-separated DNS IPs (optionally ip:port); a local unbound is best: 127.0.0.1")
    p.add_argument("--dns-sockets", type=int, default=4, help="UDP sockets per resolver per process")
    p.add_argument("--dns-inflight", type=int, default=256, help="max pipelined queries per UDP socket")
    p.add_argument("--cache", type=int, default=2_000_000, help="max entries per result cache")
    p.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    p.add_argument("--out", default="mailcheck", help="output CSV name prefix")
    return p.parse_args()


def main():
    if sys.version_info < (3, 11):
        sys.exit("[ERROR] Python 3.11+ required (StreamWriter.start_tls / asyncio.timeout).")
    args = parse_args()
    inp = Path(args.input)
    if not inp.is_file():
        sys.exit(f"[ERROR] input file not found: {inp}")
    cfg = build_mode_cfg(args.mode)
    est = estimate_lines(inp)
    print(f"Input: {inp} (~{est:,} lines) | mode {args.mode} | processes {args.processes} "
          f"| concurrency {args.concurrency} | timeout {args.timeout}s", flush=True)
    if args.mode == "all" and est > 2_000_000:
        print("[WARN] --mode all does ~1,100+ DNS queries per domain — a 1 GB file will take "
              "days. Use --mode fast or --mode mx for bulk runs.", file=sys.stderr)
    try:
        if args.processes <= 1:
            child_entry(args, 0, 1, est, cfg)
        else:
            mp = multiprocessing.get_context("spawn")
            procs = [mp.Process(target=child_entry, args=(args, i, args.processes, est, cfg))
                     for i in range(args.processes)]
            for pr in procs:
                pr.start()
            try:
                for pr in procs:
                    pr.join()
            except KeyboardInterrupt:
                print("\n[INFO] stopping workers...", file=sys.stderr)
                for pr in procs:
                    pr.terminate()
                for pr in procs:
                    pr.join(5)
            bad = [i for i, pr in enumerate(procs) if pr.exitcode not in (0, None)]
            if bad:
                print(f"[WARN] shards exited with errors: {bad}", file=sys.stderr)
            merge_outputs(args)
    finally:
        if uvloop is None and sys.platform.startswith("linux"):
            print("Tip: pip install uvloop for a faster event loop.")
        print("Done.", flush=True)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
