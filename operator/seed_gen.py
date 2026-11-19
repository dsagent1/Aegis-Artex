#!/usr/bin/env python3
"""
seed_gen.py -- semantic seed-corpus generation for THE FUZZER (adopted heuristic from Google's
OSS-Fuzz-Gen, NOT the dependency / not its LLM calls). OSS-Fuzz-Gen's win is generating seeds from the
TARGET'S STRUCTURE rather than fuzzing from empty -- structured seeds reach deep code paths far faster
than blind mutation. Here we generate seeds from a lightweight FORMAT SPEC (and boundary/mutation seeds
generically), which we drop into the fuzzer's corpus dir so libFuzzer/AFL++ start from meaningful inputs.
Stdlib-only, offline, deterministic. The oracle still decides what's a real crash.

    from seed_gen import length_prefixed_seeds, boundary_seeds, mutate, write_corpus
    seeds = length_prefixed_seeds(item_lens=(0,1,32,33,255))   # trips trusted-length overflows fast
    write_corpus("invoice", "invoice_fuzzer", seeds)           # -> corpus dir in Kali
"""
from __future__ import annotations

import os
import shlex
import subprocess

WSL_DISTRO = os.environ.get("AEGIS_KALI_DISTRO", "kali-linux")
WORK = os.environ.get("AEGIS_OSSFUZZ_WORK", "/opt/aegis-ossfuzz")
_INTERESTING = bytes([0x00, 0x01, 0x7f, 0x80, 0xff])        # classic boundary bytes


def boundary_seeds(max_len: int = 64, fill: bytes = b"A") -> list:
    """Generic structure-agnostic boundary inputs (empty / single / all-0xff / long run / interesting)."""
    out = [b"", b"\x00", b"\xff", fill, fill * max_len, _INTERESTING]
    out.append(bytes(range(256)))                          # every byte value once
    # de-dup preserving order
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s); uniq.append(s)
    return uniq


def length_prefixed_seeds(n_items=(1, 2), item_lens=(0, 1, 32, 33, 255), fill: bytes = b"A") -> list:
    """SEMANTIC seeds for the very common `[n_items:u8]([len:u8][len bytes])*` record format -- the shape
    behind most trusted-length buffer overflows. Emitting a `len` that exceeds a fixed downstream buffer
    (e.g. 33 or 255 into a 32-byte field) reaches the overflow on the FIRST execution instead of by luck."""
    seeds = []
    for n in n_items:
        for ln in item_lens:
            body = bytearray([n & 0xff])
            for _ in range(max(1, n)):
                body.append(ln & 0xff)
                body.extend((fill * ln)[:ln])
            seeds.append(bytes(body))
    return seeds


def mutate(seed: bytes, n: int = 8) -> list:
    """A few deterministic boundary mutations of one seed (bit flip / truncate / extend / interesting byte)."""
    seed = seed or b"\x00"
    out = []
    for i in range(min(n, len(seed))):                     # single-bit flips at spread positions
        b = bytearray(seed); b[i] ^= 0x80; out.append(bytes(b))
    out.append(seed[: len(seed) // 2])                     # truncate
    out.append(seed + b"\xff" * 8)                         # extend
    for ib in _INTERESTING:                                # splice interesting byte at the front
        out.append(bytes([ib]) + seed)
    seen, uniq = set(), []
    for s in out:
        if s and s not in seen:
            seen.add(s); uniq.append(s)
    return uniq


def default_seeds() -> list:
    """A good general starter corpus when no format spec is supplied."""
    seeds = boundary_seeds() + length_prefixed_seeds()
    extra = []
    for s in seeds[:6]:
        extra += mutate(s, 3)
    return seeds + extra


def depth_seeds(depths=(64, 256, 1024, 3600)) -> list:
    """Seeds for DEPTH / resource-exhaustion targets (stack overflow, quadratic blowup). Coverage-guided
    fuzzing is structurally blind to nesting depth -- recursion produces NO new code coverage, so libFuzzer
    MINIMIZES inputs instead of growing depth and never reaches the overflow. These seeds give it a
    length/structure GRADIENT toward the deep end:
      (a) increasing-LENGTH byte ramps, so a length->depth adapter harness (depth = len(input)) grows
          recursion depth as the corpus grows;
      (b) explicit NESTED-JSON seeds of increasing depth, for a JSON/merge/parse harness that consumes them
          directly.
    Tune `depths` to straddle the target's known/expected overflow depth (e.g. deepmerge-ts ~3000)."""
    seeds = []
    for d in depths:
        seeds.append(b"A" * d)                                # length ramp (len->depth adapter harnesses)
        seeds.append(b'{"a":' * d + b'0' + b'}' * d)          # nested JSON of depth d (direct-consume harnesses)
    return seeds


def _corpus_dir(project: str, fuzzer: str, js: bool = False) -> str:
    """Where seeds must land so the RUNNER actually reads them. JS/Jazzer reads the PROJECT's own
    ./corpus (proj_dir/corpus); the base-runner (c++/python) reads {WORK}/corpus/{project}/{fuzzer}.
    Writing to the wrong one means the fuzzer never sees the seeds -- the JS depth-seed miss where auto
    depth_seeds landed in the base-runner dir and Jazzer, reading proj/corpus, only saw its own minimized
    inputs and never reached the overflow depth."""
    return f"{WORK}/projects/{project}/corpus" if js else f"{WORK}/corpus/{project}/{fuzzer}"


def write_corpus(project: str, fuzzer: str, seeds: list, distro: str = None, js: bool = False) -> dict:
    """Write each seed as a file into the corpus dir the RUNNER reads (base64 per file -- no WSL quoting
    issues; JS -> project ./corpus, else the base-runner dir). Files are named by a content hash so
    re-runs are idempotent."""
    import base64
    import hashlib
    distro = distro or WSL_DISTRO
    cdir = _corpus_dir(project, fuzzer, js)
    cmds = [f"mkdir -p {shlex.quote(cdir)}"]
    for s in seeds:
        h = hashlib.sha1(s).hexdigest()[:16]
        b64 = base64.b64encode(s).decode()
        cmds.append(f"printf '%s' {b64} | base64 -d > {shlex.quote(cdir + '/seed-' + h)}")
    try:
        p = subprocess.run(["wsl", "-d", distro, "-u", "root", "--", "bash", "-lc", " && ".join(cmds)],
                           capture_output=True, text=True, timeout=120)
        ok = p.returncode == 0
    except Exception as e:
        return {"ok": False, "error": str(e)[:160], "corpus": cdir}
    return {"ok": ok, "corpus": cdir, "written": len(seeds)}


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Generate a semantic seed corpus for THE FUZZER (offline).")
    ap.add_argument("project")
    ap.add_argument("fuzzer")
    ap.add_argument("--over", type=int, default=None, help="add a length byte that exceeds this buffer size")
    ap.add_argument("--dry-run", action="store_true", help="just count/preview, don't write to Kali")
    a = ap.parse_args()
    lens = (0, 1, 32, 33, 255)
    if a.over:
        lens = tuple(sorted(set(lens) | {a.over, a.over + 1}))
    seeds = boundary_seeds() + length_prefixed_seeds(item_lens=lens)
    import json
    if a.dry_run:
        print(json.dumps({"seeds": len(seeds), "sizes": sorted({len(s) for s in seeds})[:12]}, indent=2))
        return
    print(json.dumps(write_corpus(a.project, a.fuzzer, seeds), indent=2))


def _selftest():
    lp = length_prefixed_seeds(item_lens=(0, 33, 255))
    assert any(b"\x21" in s[:2] or s[1] == 33 for s in lp), "should emit an oversized (33) length seed"
    assert b"" in boundary_seeds() and bytes(range(256)) in boundary_seeds()
    m = mutate(b"\x01\xffAAAA")
    assert len(m) >= 5 and all(isinstance(x, bytes) for x in m)
    assert len(default_seeds()) > len(boundary_seeds())
    print(f"seed_gen selftest: OK ({len(lp)} length-prefixed, {len(default_seeds())} default seeds)")
    return True


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        sys.exit(0 if _selftest() else 1)
    main()
