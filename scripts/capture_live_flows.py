"""
Capture packets continuously, assemble CICFlowMeter-style flows, POST /api/analyze.

Requires Npcap (Windows) or libpcap (Linux/macOS). Run with admin/root for live sniffing.

Usage:
  python capture_live_flows.py --list-ifaces
  python capture_live_flows.py --iface "Ethernet" --url http://127.0.0.1:8000 --token demo-token-user@example.com
  python capture_live_flows.py --iface 1 --filter "tcp or udp" --idle-timeout 5 --max-duration 60

Set --token or NETGUARD_TOKEN. Ctrl+C flushes remaining flows and exits.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
FEATURES_PATH = ROOT / "shared" / "feature_columns.json"

try:
    from scapy.all import (  # type: ignore
        IP,
        TCP,
        UDP,
        IPv6,
        conf,
        get_if_list,
        sniff,
    )
except ImportError:
    print("Install capture deps: pip install -r scripts/requirements-ingest.txt", file=sys.stderr)
    raise SystemExit(1)


def load_features() -> list[str]:
    with open(FEATURES_PATH, encoding="utf-8") as f:
        return json.load(f)


def _headers(token: str | None) -> dict[str, str]:
    h: dict[str, str] = {}
    if token:
        t = token.strip()
        if not t.lower().startswith("bearer "):
            t = f"Bearer {t}"
        h["Authorization"] = t
    return h


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _std(xs: list[float]) -> float:
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    var = sum((x - m) ** 2 for x in xs) / (len(xs) - 1)
    return math.sqrt(var)


def _iat(times: list[float]) -> list[float]:
    if len(times) < 2:
        return []
    return [times[i] - times[i - 1] for i in range(1, len(times))]


class Flow:
    """Bidirectional flow; first packet defines forward direction."""

    __slots__ = (
        "src_ip",
        "dst_ip",
        "sport",
        "dport",
        "proto",
        "start",
        "last",
        "fwd_times",
        "bwd_times",
        "fwd_lens",
        "bwd_lens",
        "fin",
        "syn",
        "rst",
        "psh",
        "ack",
        "fwd_psh",
        "bwd_psh",
        "fwd_urg",
        "bwd_urg",
        "init_fwd_win",
        "init_bwd_win",
        "closed",
    )

    def __init__(self, src_ip: str, dst_ip: str, sport: int, dport: int, proto: int, now: float):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport
        self.proto = proto
        self.start = now
        self.last = now
        self.fwd_times: list[float] = []
        self.bwd_times: list[float] = []
        self.fwd_lens: list[float] = []
        self.bwd_lens: list[float] = []
        self.fin = 0.0
        self.syn = 0.0
        self.rst = 0.0
        self.psh = 0.0
        self.ack = 0.0
        self.fwd_psh = 0.0
        self.bwd_psh = 0.0
        self.fwd_urg = 0.0
        self.bwd_urg = 0.0
        self.init_fwd_win = 0.0
        self.init_bwd_win = 0.0
        self.closed = False

    def add(self, fwd: bool, now: float, length: float, tcp: Any | None) -> None:
        self.last = now
        if fwd:
            self.fwd_times.append(now)
            self.fwd_lens.append(length)
        else:
            self.bwd_times.append(now)
            self.bwd_lens.append(length)
        if tcp is None:
            return
        flags = int(tcp.flags)
        if flags & 0x01:
            self.fin += 1
            self.closed = True
        if flags & 0x02:
            self.syn += 1
        if flags & 0x04:
            self.rst += 1
            self.closed = True
        if flags & 0x08:
            self.psh += 1
            if fwd:
                self.fwd_psh += 1
            else:
                self.bwd_psh += 1
        if flags & 0x10:
            self.ack += 1
        if flags & 0x20:
            if fwd:
                self.fwd_urg += 1
            else:
                self.bwd_urg += 1
        win = float(getattr(tcp, "window", 0) or 0)
        if fwd and self.init_fwd_win == 0.0:
            self.init_fwd_win = win
        if not fwd and self.init_bwd_win == 0.0:
            self.init_bwd_win = win

    def features(self, names: list[str]) -> dict[str, float]:
        duration_s = max(self.last - self.start, 1e-6)
        duration_us = duration_s * 1_000_000.0
        tot_fwd = float(len(self.fwd_lens))
        tot_bwd = float(len(self.bwd_lens))
        totlen_fwd = float(sum(self.fwd_lens))
        totlen_bwd = float(sum(self.bwd_lens))
        all_times = sorted(self.fwd_times + self.bwd_times)
        flow_iats = _iat(all_times)
        fwd_iats = _iat(self.fwd_times)
        bwd_iats = _iat(self.bwd_times)
        tot_pkts = tot_fwd + tot_bwd
        tot_bytes = totlen_fwd + totlen_bwd
        down_up = (totlen_bwd / totlen_fwd) if totlen_fwd > 0 else 0.0
        raw = {
            "flow_duration": duration_us,
            "tot_fwd_pkts": tot_fwd,
            "tot_bwd_pkts": tot_bwd,
            "totlen_fwd_pkts": totlen_fwd,
            "totlen_bwd_pkts": totlen_bwd,
            "fwd_pkt_len_max": max(self.fwd_lens) if self.fwd_lens else 0.0,
            "fwd_pkt_len_min": min(self.fwd_lens) if self.fwd_lens else 0.0,
            "fwd_pkt_len_mean": _mean(self.fwd_lens),
            "fwd_pkt_len_std": _std(self.fwd_lens),
            "bwd_pkt_len_max": max(self.bwd_lens) if self.bwd_lens else 0.0,
            "bwd_pkt_len_min": min(self.bwd_lens) if self.bwd_lens else 0.0,
            "bwd_pkt_len_mean": _mean(self.bwd_lens),
            "bwd_pkt_len_std": _std(self.bwd_lens),
            "flow_bytes_s": tot_bytes / duration_s,
            "flow_pkts_s": tot_pkts / duration_s,
            "flow_iat_mean": _mean(flow_iats),
            "flow_iat_std": _std(flow_iats),
            "flow_iat_max": max(flow_iats) if flow_iats else 0.0,
            "flow_iat_min": min(flow_iats) if flow_iats else 0.0,
            "fwd_iat_tot": sum(fwd_iats) if fwd_iats else 0.0,
            "fwd_iat_mean": _mean(fwd_iats),
            "fwd_iat_max": max(fwd_iats) if fwd_iats else 0.0,
            "fwd_iat_min": min(fwd_iats) if fwd_iats else 0.0,
            "bwd_iat_tot": sum(bwd_iats) if bwd_iats else 0.0,
            "bwd_iat_mean": _mean(bwd_iats),
            "bwd_iat_max": max(bwd_iats) if bwd_iats else 0.0,
            "bwd_iat_min": min(bwd_iats) if bwd_iats else 0.0,
            "fwd_psh_flags": self.fwd_psh,
            "bwd_psh_flags": self.bwd_psh,
            "fwd_urg_flags": self.fwd_urg,
            "bwd_urg_flags": self.bwd_urg,
            "fin_flag_cnt": self.fin,
            "syn_flag_cnt": self.syn,
            "rst_flag_cnt": self.rst,
            "psh_flag_cnt": self.psh,
            "ack_flag_cnt": self.ack,
            "down_up_ratio": down_up,
            "init_fwd_win_byts": self.init_fwd_win,
            "init_bwd_win_byts": self.init_bwd_win,
        }
        return {k: float(raw[k]) for k in names}


def _bidir_key(src: str, dst: str, sport: int, dport: int, proto: int) -> tuple:
    a = (src, sport)
    b = (dst, dport)
    if a <= b:
        return (src, dst, sport, dport, proto)
    return (dst, src, dport, sport, proto)


def _l3(pkt: Any) -> tuple[str, str, int] | None:
    if pkt.haslayer(IP):
        ip = pkt[IP]
        return str(ip.src), str(ip.dst), int(ip.proto)
    if pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        return str(ip.src), str(ip.dst), int(ip.nh)
    return None


def _pkt_len(pkt: Any) -> float:
    if pkt.haslayer(IP):
        return float(pkt[IP].len or len(pkt))
    if pkt.haslayer(IPv6):
        return float((pkt[IPv6].plen or 0) + 40)
    return float(len(pkt))


class LiveCapture:
    def __init__(
        self,
        *,
        url: str,
        token: str | None,
        features: list[str],
        idle_timeout: float,
        max_duration: float,
        dry_run: bool,
    ) -> None:
        self.analyze_url = url.rstrip("/") + "/api/analyze"
        self.headers = _headers(token)
        self.features = features
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        self.dry_run = dry_run
        self.lock = threading.Lock()
        self.flows: dict[tuple, Flow] = {}
        self.stop = threading.Event()
        self.sent = 0
        self.errors = 0
        self.seen_pkts = 0
        self._client: httpx.Client | None = None if dry_run else httpx.Client(timeout=30.0)

    def on_packet(self, pkt: Any) -> None:
        l3 = _l3(pkt)
        if l3 is None:
            return
        src, dst, proto = l3
        sport = dport = 0
        tcp = None
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = int(udp.sport), int(udp.dport)
        else:
            return
        now = time.time()
        key = _bidir_key(src, dst, sport, dport, proto)
        with self.lock:
            self.seen_pkts += 1
            flow = self.flows.get(key)
            if flow is None:
                flow = Flow(src, dst, sport, dport, proto, now)
                self.flows[key] = flow
            fwd = src == flow.src_ip and sport == flow.sport
            flow.add(fwd, now, _pkt_len(pkt), tcp)

    def _expired_keys(self, now: float, flush_all: bool) -> list[tuple]:
        out: list[tuple] = []
        for key, flow in self.flows.items():
            idle = now - flow.last
            age = now - flow.start
            if flush_all or flow.closed or idle >= self.idle_timeout or age >= self.max_duration:
                out.append(key)
        return out

    def flush(self, flush_all: bool = False) -> None:
        now = time.time()
        with self.lock:
            keys = self._expired_keys(now, flush_all)
            batch = [(k, self.flows.pop(k)) for k in keys]
        for _key, flow in batch:
            if not flow.fwd_lens and not flow.bwd_lens:
                continue
            body = {"features": flow.features(self.features), "source_ip": flow.src_ip}
            if self.dry_run:
                self.sent += 1
                print(
                    f"[dry-run] {flow.src_ip}:{flow.sport} -> {flow.dst_ip}:{flow.dport} "
                    f"pkts={len(flow.fwd_lens)+len(flow.bwd_lens)} sent={self.sent}"
                )
                continue
            assert self._client is not None
            try:
                r = self._client.post(self.analyze_url, json=body, headers=self.headers)
                self.sent += 1
                if r.headers.get("content-type", "").startswith("application/json"):
                    data = r.json()
                    label = data.get("label", "?")
                    confd = data.get("confidence")
                    print(f"{r.status_code} {flow.src_ip} {label} conf={confd} total={self.sent}")
                else:
                    print(f"{r.status_code} {r.text[:200]} total={self.sent}")
                if not r.is_success:
                    self.errors += 1
            except httpx.HTTPError as e:
                self.errors += 1
                print(f"post failed: {e}", file=sys.stderr)

    def exporter_loop(self) -> None:
        while not self.stop.wait(0.5):
            self.flush(False)
        self.flush(True)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()


def list_ifaces() -> int:
    print("Scapy interfaces (use --iface with name or 1-based index):\n")
    names = get_if_list()
    for i, name in enumerate(names, start=1):
        print(f"  {i}. {name}")
    if getattr(conf, "ifaces", None):
        print("\nScapy iface table:")
        print(conf.ifaces)
    return 0


def resolve_iface(value: str | None) -> str | None:
    if not value:
        return None
    names = get_if_list()
    if value.isdigit():
        idx = int(value)
        if 1 <= idx <= len(names):
            return names[idx - 1]
        raise SystemExit(f"Interface index {value} out of range (1-{len(names)})")
    return value


def main() -> int:
    p = argparse.ArgumentParser(description="Real-time packet capture to NetGuard /api/analyze")
    p.add_argument("--list-ifaces", action="store_true", help="Print capture interfaces and exit")
    p.add_argument("--iface", help="Interface name or 1-based index from --list-ifaces")
    p.add_argument("--url", default="http://127.0.0.1:8000", help="Backend base URL")
    p.add_argument(
        "--token",
        default=os.environ.get("NETGUARD_TOKEN", ""),
        help="Login token or set NETGUARD_TOKEN",
    )
    p.add_argument("--filter", default="tcp or udp", help="BPF filter")
    p.add_argument("--idle-timeout", type=float, default=5.0, help="Seconds of silence before a flow is sent")
    p.add_argument("--max-duration", type=float, default=60.0, help="Max seconds to hold a flow before sending")
    p.add_argument("--dry-run", action="store_true", help="Print flows; do not POST")
    args = p.parse_args()

    if args.list_ifaces:
        return list_ifaces()

    iface = resolve_iface(args.iface)
    features = load_features()
    cap = LiveCapture(
        url=args.url,
        token=args.token or None,
        features=features,
        idle_timeout=args.idle_timeout,
        max_duration=args.max_duration,
        dry_run=args.dry_run,
    )

    exporter = threading.Thread(target=cap.exporter_loop, name="flow-export", daemon=True)
    exporter.start()

    stopping = {"done": False}

    def shutdown(*_a: object) -> None:
        if stopping["done"]:
            return
        stopping["done"] = True
        print("\nStopping capture; flushing flows...", file=sys.stderr)
        cap.stop.set()

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    print(
        f"Capturing continuously on {iface or 'default iface'} "
        f"filter={args.filter!r} -> {cap.analyze_url} (Ctrl+C to stop)"
    )
    try:
        while not cap.stop.is_set():
            sniff(
                iface=iface,
                filter=args.filter,
                prn=cap.on_packet,
                store=False,
                timeout=1,
                stop_filter=lambda _p: cap.stop.is_set(),
            )
    except KeyboardInterrupt:
        shutdown()
    except OSError as e:
        print(
            f"Capture failed: {e}\n"
            "On Windows install Npcap (WinPcap compatible) and run this terminal as Administrator.",
            file=sys.stderr,
        )
        cap.stop.set()
        cap.close()
        return 1
    finally:
        cap.stop.set()
        exporter.join(timeout=10)
        cap.close()
        print(f"Done. packets={cap.seen_pkts} flows_sent={cap.sent} errors={cap.errors}")
    return 0 if cap.errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())