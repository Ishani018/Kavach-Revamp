"""
kavach/ministers/deobfuscate.py
===============================

Recover text a command hides behind encoding, then let EXECUTOR's and VAULT's
ordinary rules judge it.

Two sources of decoded text, both checked by the same pure transforms:

* `decode_candidates`: deterministic. Finds encoded-looking runs (base64,
  hex, \\xNN escapes, percent-encoding) and decodes them, recursively, keeping
  only results that are mostly printable text.
* `verify_chain`: for an AI-proposed chain of steps. Each step names one of
  the transforms below, its inputs must be literal substrings of the original
  command or of an earlier step's output, and replaying every step must
  reproduce the claimed plaintext exactly. Anything else is rejected, so a
  model cannot invent a payload: it can only point at one that is really
  there.

Decoded text never relaxes a verdict; it is only checked for more rule hits.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

MAX_STEPS = 8
MAX_OUTPUT = 20_000
MAX_DEPTH = 3


def _b64(s: str) -> str:
    raw = s.strip()
    raw += "=" * (-len(raw) % 4)
    altchars = b"-_" if ("-" in raw or "_" in raw) else None
    return base64.b64decode(raw, altchars=altchars, validate=True).decode("utf-8")


def _b32(s: str) -> str:
    raw = s.strip().upper()
    raw += "=" * (-len(raw) % 8)
    return base64.b32decode(raw).decode("utf-8")


def _hex(s: str) -> str:
    raw = re.sub(r"\\x|0x|[\s:,]", "", s.strip(), flags=re.IGNORECASE)
    return binascii.unhexlify(raw).decode("utf-8")


def _octal(s: str) -> str:
    parts = re.findall(r"\\([0-7]{1,3})", s)
    if not parts or re.sub(r"\\[0-7]{1,3}", "", s).strip():
        raise ValueError("not an octal escape sequence")
    return bytes(int(p, 8) for p in parts).decode("utf-8")


def _charcodes(s: str) -> str:
    numbers = re.findall(r"\d+", s)
    if not numbers or re.sub(r"[\d\s,;()\[\]]", "", s):
        raise ValueError("not a list of character codes")
    return "".join(chr(int(n)) for n in numbers if int(n) < 0x110000)


TRANSFORMS: Dict[str, Callable[[str], str]] = {
    "base64": _b64,
    "base32": _b32,
    "hex": _hex,
    "url": lambda s: urllib.parse.unquote(s, errors="strict"),
    "reverse": lambda s: s[::-1],
    "rot13": lambda s: codecs.decode(s, "rot13"),
    "octal": _octal,
    "charcodes": _charcodes,
}


def _printable(text: str) -> bool:
    if not text:
        return False
    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return good / len(text) >= 0.9


@dataclass(frozen=True)
class Decoded:
    text: str
    transforms: tuple       # e.g. ("base64",) or ("hex", "base64")


_CANDIDATES = [
    ("base64", re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")),
    ("hex", re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")),
    ("hex", re.compile(r"\b(?:[0-9A-Fa-f]{2}){8,}\b")),
    ("url", re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")),
    ("octal", re.compile(r"(?:\\[0-7]{3}){4,}")),
]


def decode_candidates(text: str, _depth: int = 0, _chain: tuple = ()) -> List[Decoded]:
    """Every printable payload found by decoding encoded-looking runs, recursively."""
    found: List[Decoded] = []
    if _depth >= MAX_DEPTH or not text:
        return found
    seen = set()
    for name, pattern in _CANDIDATES:
        for match in pattern.finditer(text):
            run = match.group(0)
            if (name, run) in seen:
                continue
            seen.add((name, run))
            try:
                out = TRANSFORMS[name](run)
            except Exception:
                continue
            if out == run or len(out) > MAX_OUTPUT or not _printable(out):
                continue
            chain = _chain + (name,)
            found.append(Decoded(out, chain))
            found.extend(decode_candidates(out, _depth + 1, chain))
    return found


class ChainRejected(ValueError):
    pass


def verify_chain(original: str, steps: Sequence[dict], claimed: str) -> Decoded:
    """Replay an AI-proposed chain; return the decoded text only if every step
    is grounded in visible text and the replay reproduces `claimed` exactly."""
    if not steps or len(steps) > MAX_STEPS:
        raise ChainRejected("chain is empty or too long")
    visible = [original]
    output: Optional[str] = None
    names = []
    for i, step in enumerate(steps):
        transform = step.get("transform")
        inputs = step.get("inputs")
        if not isinstance(inputs, list) or not inputs or not all(isinstance(x, str) and x for x in inputs):
            raise ChainRejected(f"step {i}: inputs must be non-empty strings")
        for x in inputs:
            if not any(x in v for v in visible):
                raise ChainRejected(f"step {i}: an input is not in the command or an earlier output")
        if transform == "concat":
            output = "".join(inputs)
        elif transform in TRANSFORMS:
            if len(inputs) != 1:
                raise ChainRejected(f"step {i}: {transform} takes exactly one input")
            try:
                output = TRANSFORMS[transform](inputs[0])
            except Exception:
                raise ChainRejected(f"step {i}: {transform} does not apply to its input") from None
        else:
            raise ChainRejected(f"step {i}: unknown transform")
        if len(output) > MAX_OUTPUT:
            raise ChainRejected(f"step {i}: output too long")
        visible.append(output)
        names.append(transform)
    if output != claimed:
        raise ChainRejected("replayed steps do not reproduce the claimed text")
    if output in original:
        raise ChainRejected("decoded text is already visible in the command")
    return Decoded(output, tuple(names))


# Words that suggest a command builds or decodes what it runs. Used only to
# decide whether asking the model is worth it; never as a verdict.
OBFUSCATION_SIGNALS = re.compile(
    r"base64|base32|\bxxd\b|openssl\s+enc|\brev\b|\btr\s|\\x[0-9a-f]{2}|\\[0-7]{3}|fromCharCode|\bchr\s*\(|"
    r"\beval\b|\bexec\b|\bIEX\b|Invoke-Expression|-e(nc|ncodedcommand)?\s|decode\(|unhexlify|codecs\.|\$\{?\w+\}?\$\{?\w+",
    re.IGNORECASE,
)
