"""Benchmark harness for Strix's detection layer.

Two independent things live here, and neither needs the other:

- **fixtures mode** (this package): runs the deterministic layers this repo
  owns directly — validators, replay, the network engine, the mobile engine —
  against small live/real targets (a local vulnerable HTTP server, real nmap
  output, a real binary APK), with hand-labeled ground truth. No LLM, no
  Docker. It measures whether *validation* is sound: does it confirm real
  bugs (recall) and reject bogus ones (false positives), given correct
  evidence.
- **agent mode** (``agent_runner.py``): drives the actual ``strix`` CLI
  (multi-agent LLM loop in the Docker sandbox) against a target and scores
  its filed findings against ground truth. This measures whether the *agent*
  finds bugs on its own. It needs Docker and an LLM API key; this harness
  only wraps and scores it, it does not provide either.
"""
