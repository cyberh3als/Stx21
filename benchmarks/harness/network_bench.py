"""Run real nmap against real loopback sockets and score the network engine.

Opens genuine TCP listeners (one "exposed service" on a Redis-shaped port, one
on an ordinary HTTP-shaped port, one closed/never-opened port as the safe
probe) and runs the actual ``nmap`` binary against ``127.0.0.1``. The XML it
produces is fed through the unmodified parser/rules/validator code path.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import threading
from contextlib import ExitStack
from typing import Self

from benchmarks.harness.ground_truth import GroundTruthFinding, ProbeResult
from benchmarks.harness.scoring import Scorecard
from strix.network import NetworkScope, assess
from strix.network.parsers import parse_nmap_xml
from strix.validators import evaluate


NMAP_TIMEOUT_S = 60
# Real well-known ports the exposed-service rule keys on (this harness runs as
# root in its container, so binding them is possible). RDP is never actually
# bound: it has a rule too, so leaving it closed is a real false-positive test,
# not just an unrelated port the rule table never mentions.
REDIS_PORT = 6379
RDP_PORT = 3389  # left closed on purpose: the "safe" probe


class _Listener:
    def __init__(self, port: int) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(5)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._stop = False

    def _accept_loop(self) -> None:
        self._sock.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            conn.close()

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop = True
        self._thread.join(timeout=2)
        self._sock.close()


def _run_nmap() -> str:
    nmap = shutil.which("nmap")
    if not nmap:
        raise RuntimeError("nmap is not installed")
    result = subprocess.run(  # noqa: S603  # fixed args, loopback-only target, no shell
        [
            nmap,
            "-Pn",
            "-n",
            "-sT",
            "-p",
            f"{REDIS_PORT},{RDP_PORT}",
            "--host-timeout",
            "30s",
            "-oX",
            "-",
            "127.0.0.1",
        ],
        capture_output=True,
        text=True,
        timeout=NMAP_TIMEOUT_S,
        check=True,
    )
    return result.stdout


GROUND_TRUTH: list[GroundTruthFinding] = [
    GroundTruthFinding(
        "exposed_redis_port", None, expect_vulnerable=True, detail=f"real listener on {REDIS_PORT}"
    ),
    GroundTruthFinding(
        "rdp_closed_not_flagged",
        None,
        expect_vulnerable=False,
        detail=f"port {RDP_PORT} has a rule but nothing listens",
    ),
]


def run() -> Scorecard:
    with ExitStack() as stack:
        stack.enter_context(_Listener(REDIS_PORT))
        # RDP_PORT is deliberately left unbound.
        xml = _run_nmap()

    services = parse_nmap_xml(xml)
    open_ports = {svc.port for svc in services if svc.host == "127.0.0.1" or svc.ip == "127.0.0.1"}
    targets = [{"type": "ip_address", "details": {"target_ip": "127.0.0.1"}}]
    scope = NetworkScope.from_targets(targets)
    candidates, _dropped = assess(services, [], scope)

    results = []
    for gt in GROUND_TRUTH:
        if gt.name == "exposed_redis_port":
            candidate = next((c for c in candidates if c.port == REDIS_PORT), None)
            status = "not_validated"
            if candidate is not None:
                status = evaluate(candidate.validation, candidate.cwe)["status"]
            elif REDIS_PORT not in open_ports:
                status = "error"  # nmap itself didn't even see the port as open
            results.append(ProbeResult(gt, status, f"candidates={len(candidates)}"))
        else:  # rdp_closed_not_flagged
            flagged = any(c.port == RDP_PORT for c in candidates)
            results.append(ProbeResult(gt, "verified" if flagged else "unverified"))
    return Scorecard("Network engine (real nmap, real loopback sockets)", results)
