"""DNS project implementation: caching + security + benchmarking.

Features:
- UDP recursive DNS forwarder (client-facing)
- In-memory TTL cache with automatic expiration
- Per-source-IP query rate limiting
- Cache-poisoning hardening with 0x20 encoding and source-port randomization
- DNSSEC-aware checks (requires AD when signed data is present)
- Request logging for analysis/auditing
- Simple benchmark mode (cold vs warm queries)
"""

from __future__ import annotations

import argparse
import csv
import random
import socket
import threading
import time
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional, Tuple

import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode


BUFFER_SIZE = 4096
DEFAULT_UPSTREAM = ("1.1.1.1", 53)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def randomize_case_0x20(domain: str, rng: random.Random) -> str:
    output = []
    for ch in domain:
        if ch.isalpha():
            output.append(ch.upper() if rng.random() < 0.5 else ch.lower())
        else:
            output.append(ch)
    return "".join(output)


def rrsets(msg: dns.message.Message) -> Iterable:
    for section in (msg.answer, msg.authority, msg.additional):
        for rrset in section:
            yield rrset


def extract_min_ttl(msg: dns.message.Message, default_ttl: int = 30) -> int:
    values: List[int] = []
    for rrset in rrsets(msg):
        if rrset.ttl > 0:
            values.append(rrset.ttl)
    return min(values) if values else default_ttl


@dataclass
class CacheEntry:
    wire: bytes
    cached_at: float
    expires_at: float


class TTLCache:
    def __init__(self, max_size: int = 2048):
        self.max_size = max_size
        self._data: "OrderedDict[Tuple[str, int], CacheEntry]" = OrderedDict()
        self._lock = threading.Lock()

    def _evict_if_needed(self) -> None:
        while len(self._data) > self.max_size:
            self._data.popitem(last=False)

    def get(self, key: Tuple[str, int]) -> Optional[CacheEntry]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if time.time() >= entry.expires_at:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return entry

    def set(self, key: Tuple[str, int], wire: bytes, ttl: int) -> None:
        ttl = max(1, ttl)
        now = time.time()
        with self._lock:
            self._data[key] = CacheEntry(
                wire=wire,
                cached_at=now,
                expires_at=now + ttl,
            )
            self._data.move_to_end(key)
            self._evict_if_needed()

    def size(self) -> int:
        with self._lock:
            return len(self._data)


class QueryRateLimiter:
    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, source_ip: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = self._timestamps[source_ip]
            while bucket and now - bucket[0] > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True


class RequestLogger:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._ensure_header()

    def _ensure_header(self) -> None:
        if self.path.exists() and self.path.stat().st_size > 0:
            return
        with self.path.open("w", newline="", encoding="utf-8") as fp:
            writer = csv.writer(fp)
            writer.writerow(
                [
                    "timestamp",
                    "client_ip",
                    "qname",
                    "qtype",
                    "rcode",
                    "cache_hit",
                    "latency_ms",
                    "note",
                ]
            )

    def log(
        self,
        client_ip: str,
        qname: str,
        qtype: str,
        rcode_name: str,
        cache_hit: bool,
        latency_ms: float,
        note: str,
    ) -> None:
        row = [
            now_utc_iso(),
            client_ip,
            qname,
            qtype,
            rcode_name,
            str(cache_hit),
            f"{latency_ms:.3f}",
            note,
        ]
        with self._lock:
            with self.path.open("a", newline="", encoding="utf-8") as fp:
                csv.writer(fp).writerow(row)


class DNSProjectServer:
    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 5300,
        upstream_host: str = DEFAULT_UPSTREAM[0],
        upstream_port: int = DEFAULT_UPSTREAM[1],
        timeout: float = 2.5,
        cache_size: int = 2048,
        rate_limit_requests: int = 30,
        rate_limit_window: float = 1.0,
        enable_dnssec_validation: bool = True,
        log_path: str = "results/dns_query_log.csv",
    ):
        self.listen_addr = (listen_host, listen_port)
        self.upstream_addr = (upstream_host, upstream_port)
        self.timeout = timeout
        self.cache = TTLCache(max_size=cache_size)
        self.rate_limiter = QueryRateLimiter(rate_limit_requests, rate_limit_window)
        self.enable_dnssec_validation = enable_dnssec_validation
        self.logger = RequestLogger(log_path)
        self.rng = random.Random()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.listen_addr)

    def serve_forever(self) -> None:
        print(
            "DNS project server listening on "
            f"{self.listen_addr[0]}:{self.listen_addr[1]} -> "
            f"upstream {self.upstream_addr[0]}:{self.upstream_addr[1]}"
        )
        while True:
            payload, client_addr = self.sock.recvfrom(BUFFER_SIZE)
            threading.Thread(
                target=self._handle_request,
                args=(payload, client_addr),
                daemon=True,
            ).start()

    def _refused_response(self, query: dns.message.Message) -> dns.message.Message:
        reply = dns.message.make_response(query)
        reply.set_rcode(dns.rcode.REFUSED)
        return reply

    def _servfail_response(self, query: dns.message.Message) -> dns.message.Message:
        reply = dns.message.make_response(query)
        reply.set_rcode(dns.rcode.SERVFAIL)
        return reply

    def _cache_key(self, query: dns.message.Message) -> Tuple[str, int]:
        q = query.question[0]
        return (str(q.name).lower(), q.rdtype)

    def _clone_cached_with_new_id(
        self,
        entry: CacheEntry,
        query_id: int,
    ) -> dns.message.Message:
        msg = dns.message.from_wire(entry.wire)
        msg.id = query_id
        return msg

    def _response_has_rrsig(self, msg: dns.message.Message) -> bool:
        for rrset in rrsets(msg):
            if rrset.rdtype == dns.rdatatype.RRSIG:
                return True
        return False

    def _validate_upstream_response(
        self,
        response: dns.message.Message,
        expected_id: int,
        expected_qname: str,
        expected_qtype: int,
    ) -> bool:
        if response.id != expected_id:
            return False
        if not response.question:
            return False
        q = response.question[0]
        if str(q.name).lower() != expected_qname.lower():
            return False
        if q.rdtype != expected_qtype:
            return False
        return True

    def _query_upstream(
        self,
        original_query: dns.message.Message,
    ) -> dns.message.Message:
        question = original_query.question[0]
        original_qname = str(question.name)
        qname_0x20 = randomize_case_0x20(original_qname, self.rng)
        forwarded = dns.message.make_query(
            qname_0x20,
            question.rdtype,
            use_edns=True,
            want_dnssec=True,
        )
        forwarded.flags |= dns.flags.RD
        forwarded.id = self.rng.randrange(0, 65536)

        last_error: Optional[Exception] = None
        for _ in range(6):
            source_port = self.rng.randint(1024, 65535)
            try:
                response = dns.query.udp(
                    forwarded,
                    where=self.upstream_addr[0],
                    port=self.upstream_addr[1],
                    timeout=self.timeout,
                    source="0.0.0.0",
                    source_port=source_port,
                    ignore_unexpected=False,
                )
                if not self._validate_upstream_response(
                    response,
                    expected_id=forwarded.id,
                    expected_qname=qname_0x20,
                    expected_qtype=question.rdtype,
                ):
                    raise RuntimeError("Upstream response validation failed")

                # Restore canonical question casing for the client response.
                response.question[0].name = question.name

                if self.enable_dnssec_validation and self._response_has_rrsig(response):
                    ad_present = bool(response.flags & dns.flags.AD)
                    if not ad_present:
                        raise RuntimeError(
                            "DNSSEC signed response received without AD flag"
                        )

                return response
            except Exception as exc:
                last_error = exc

        raise RuntimeError(f"Upstream query failed after retries: {last_error}")

    def _handle_request(self, payload: bytes, client_addr: Tuple[str, int]) -> None:
        client_ip, client_port = client_addr
        start = time.perf_counter()
        qname = ""
        qtype_name = "UNKNOWN"
        cache_hit = False
        note = ""

        try:
            query = dns.message.from_wire(payload)
            if not query.question:
                return

            if not self.rate_limiter.allow(client_ip):
                response = self._refused_response(query)
                note = "rate_limited"
                self.sock.sendto(response.to_wire(), client_addr)
                latency = (time.perf_counter() - start) * 1000
                q = query.question[0]
                self.logger.log(
                    client_ip,
                    str(q.name),
                    dns.rdatatype.to_text(q.rdtype),
                    dns.rcode.to_text(response.rcode()),
                    False,
                    latency,
                    note,
                )
                return

            key = self._cache_key(query)
            qname, qtype = key
            qtype_name = dns.rdatatype.to_text(qtype)
            cached = self.cache.get(key)

            if cached is not None:
                response = self._clone_cached_with_new_id(cached, query.id)
                cache_hit = True
                note = "cache_hit"
            else:
                response = self._query_upstream(query)
                response.id = query.id
                if response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                    ttl = extract_min_ttl(response)
                    self.cache.set(key, response.to_wire(), ttl)
                note = "cache_miss"

            self.sock.sendto(response.to_wire(), (client_ip, client_port))
            latency = (time.perf_counter() - start) * 1000
            self.logger.log(
                client_ip,
                qname,
                qtype_name,
                dns.rcode.to_text(response.rcode()),
                cache_hit,
                latency,
                note,
            )
        except Exception:
            try:
                query = dns.message.from_wire(payload)
                response = self._servfail_response(query)
                self.sock.sendto(response.to_wire(), client_addr)
                latency = (time.perf_counter() - start) * 1000
                if query.question:
                    q = query.question[0]
                    qname = str(q.name)
                    qtype_name = dns.rdatatype.to_text(q.rdtype)
                self.logger.log(
                    client_ip,
                    qname,
                    qtype_name,
                    dns.rcode.to_text(response.rcode()),
                    False,
                    latency,
                    "error",
                )
            except Exception:
                # Ignore malformed input and send nothing.
                return


def query_once(
    server_host: str,
    server_port: int,
    domain: str,
    qtype_text: str = "A",
    timeout: float = 2.5,
) -> Tuple[dns.message.Message, float]:
    rdtype = dns.rdatatype.from_text(qtype_text)
    request = dns.message.make_query(domain, rdtype, use_edns=True)
    start = time.perf_counter()
    response = dns.query.udp(request, server_host, port=server_port, timeout=timeout)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return response, elapsed_ms


def print_response(response: dns.message.Message) -> None:
    print(f"rcode={dns.rcode.to_text(response.rcode())}")
    for section_name, section in (
        ("ANSWER", response.answer),
        ("AUTHORITY", response.authority),
        ("ADDITIONAL", response.additional),
    ):
        print(f"[{section_name}]")
        if not section:
            print("  <empty>")
        for rrset in section:
            print(f"  {rrset}")


def run_benchmark(
    server_host: str,
    server_port: int,
    domain: str,
    qtype_text: str,
    warm_count: int,
) -> None:
    print(f"Benchmark domain={domain} type={qtype_text} via {server_host}:{server_port}")

    cold_response, cold_ms = query_once(server_host, server_port, domain, qtype_text)
    print(f"Cold query: {cold_ms:.3f} ms (rcode={dns.rcode.to_text(cold_response.rcode())})")

    times: List[float] = []
    for _ in range(warm_count):
        _, elapsed = query_once(server_host, server_port, domain, qtype_text)
        times.append(elapsed)

    avg_warm = sum(times) / len(times) if times else 0.0
    fastest = min(times) if times else 0.0
    slowest = max(times) if times else 0.0
    gain = (cold_ms / avg_warm) if avg_warm > 0 else 0.0

    print(
        f"Warm queries: n={warm_count}, avg={avg_warm:.3f} ms, "
        f"min={fastest:.3f} ms, max={slowest:.3f} ms"
    )
    print(f"Estimated speedup (cold/avg_warm): {gain:.2f}x")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DNS project: resolver + cache + security")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the DNS project server")
    serve.add_argument("--listen-host", default="127.0.0.1")
    serve.add_argument("--listen-port", type=int, default=5300)
    serve.add_argument("--upstream-host", default=DEFAULT_UPSTREAM[0])
    serve.add_argument("--upstream-port", type=int, default=DEFAULT_UPSTREAM[1])
    serve.add_argument("--timeout", type=float, default=2.5)
    serve.add_argument("--cache-size", type=int, default=2048)
    serve.add_argument("--rate-limit-requests", type=int, default=30)
    serve.add_argument("--rate-limit-window", type=float, default=1.0)
    serve.add_argument("--dnssec-check", action="store_true", default=False)
    serve.add_argument("--log-path", default="results/dns_query_log.csv")

    resolve = sub.add_parser("resolve", help="Send one DNS query")
    resolve.add_argument("domain")
    resolve.add_argument("--type", default="A")
    resolve.add_argument("--server-host", default="127.0.0.1")
    resolve.add_argument("--server-port", type=int, default=5300)
    resolve.add_argument("--timeout", type=float, default=2.5)

    bench = sub.add_parser("benchmark", help="Measure cold vs warm query performance")
    bench.add_argument("domain")
    bench.add_argument("--type", default="A")
    bench.add_argument("--server-host", default="127.0.0.1")
    bench.add_argument("--server-port", type=int, default=5300)
    bench.add_argument("--warm-count", type=int, default=20)

    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "serve":
        server = DNSProjectServer(
            listen_host=args.listen_host,
            listen_port=args.listen_port,
            upstream_host=args.upstream_host,
            upstream_port=args.upstream_port,
            timeout=args.timeout,
            cache_size=args.cache_size,
            rate_limit_requests=args.rate_limit_requests,
            rate_limit_window=args.rate_limit_window,
            enable_dnssec_validation=args.dnssec_check,
            log_path=args.log_path,
        )
        server.serve_forever()
        return

    if args.command == "resolve":
        response, elapsed = query_once(
            server_host=args.server_host,
            server_port=args.server_port,
            domain=args.domain,
            qtype_text=args.type,
            timeout=args.timeout,
        )
        print(f"Query time: {elapsed:.3f} ms")
        print_response(response)
        return

    if args.command == "benchmark":
        run_benchmark(
            server_host=args.server_host,
            server_port=args.server_port,
            domain=args.domain,
            qtype_text=args.type,
            warm_count=args.warm_count,
        )
        return


if __name__ == "__main__":
    main()
