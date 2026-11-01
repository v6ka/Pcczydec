#!/usr/bin/env python3
"""
PYTHON PAYLOAD ANALYZER — Telegram bot
Brand: @cummingniggas

Static-only Python source and bytecode inspection.
Uploaded files and recovered payloads are NEVER executed.

Install:
    pip install "python-telegram-bot>=21,<23"

Run:
    export BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
    python decoder_bot.py

Optional environment:
    MAX_FILE_MB=10
    MAX_TEXT_CHARS=1000000
    MAX_DECODE_LAYERS=20
    MAX_CANDIDATES=300
    ALLOWED_USER_IDS=12345,67890   # omit for public access
    LOG_LEVEL=INFO

Optional bytecode decompilers (best-effort, version-dependent):
    pip install decompyle3
    pip install uncompyle6

This tool cannot guarantee recovery of unknown encryption, runtime-generated
payloads, custom virtual machines, missing keys, or unsupported bytecode.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import binascii
import bz2
import codecs
import gzip
import hashlib
import html
import importlib.util
import io
import json
import logging
import lzma
import os
import re
import shutil
import string
import subprocess
import sys
import tempfile
import textwrap
import time
import tokenize
import traceback
import urllib.parse
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, InputFile, Update
from telegram.constants import ChatAction
from telegram.error import BadRequest, Forbidden, NetworkError, RetryAfter, TimedOut
from telegram.request import HTTPXRequest
from telegram.ext import (
    Application, CallbackQueryHandler, CommandHandler, ContextTypes,
    MessageHandler, filters,
)

# ------------------------------ Configuration ------------------------------

BRAND = "@cummingniggas"
BOT_TOKEN = os.getenv("BOT_TOKEN", "9100554087:AAH4lFNN5ZTX3kTwHEkXR4N0hvvpmyzmXTs").strip()
MAX_FILE_MB = max(1, min(40, int(os.getenv("MAX_FILE_MB", "10"))))
MAX_INPUT_BYTES = MAX_FILE_MB * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_TEXT_CHARS = max(1000, int(os.getenv("MAX_TEXT_CHARS", "1000000")))
MAX_DECODE_LAYERS = max(1, min(30, int(os.getenv("MAX_DECODE_LAYERS", "20"))))
MAX_CANDIDATES = max(20, min(2000, int(os.getenv("MAX_CANDIDATES", "300"))))
MAX_AST_NODES = 250_000
MAX_STRINGS_IN_REPORT = 500
MAX_FILE_SECONDS = 25
ALLOWED_IDS = {
    int(x.strip()) for x in os.getenv("ALLOWED_USER_IDS", "").split(",")
    if x.strip().isdigit()
}
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
log = logging.getLogger("py-payload-analyzer")

PY_HINTS = (
    "import ", "from ", "def ", "class ", "return ", "lambda ",
    "__name__", "print(", "exec(", "eval(", "async def ",
)
DANGEROUS_CALLS = {
    "exec", "eval", "compile", "__import__", "marshal.loads",
    "pickle.loads", "os.system", "subprocess.Popen", "subprocess.run",
}
ENCODING_CALLS = {
    "b64decode", "urlsafe_b64decode", "b32decode", "b16decode",
    "b85decode", "a85decode", "decompress", "loads", "fromhex",
}
TEXT_EXTENSIONS = {".py", ".pyw", ".pyi", ".pyc", ".pyo", ".txt", ".bin", ".dat"}
BINARY_EXTENSIONS = {".pyc", ".pyo", ".bin", ".dat"}
PRINTABLE = set(string.printable)


# -------------------------------- Data model --------------------------------

@dataclass
class Finding:
    category: str
    description: str
    line: Optional[int] = None
    detail: str = ""


@dataclass
class Payload:
    label: str
    source: str
    data: bytes
    layers: list[str] = field(default_factory=list)
    line: Optional[int] = None
    confidence: str = "possible"
    notes: list[str] = field(default_factory=list)


@dataclass
class Analysis:
    filename: str
    size: int
    sha256: str
    findings: list[Finding] = field(default_factory=list)
    payloads: list[Payload] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    syntax_ok: bool = False
    syntax_error: str = ""
    source_text: str = ""
    pyc_info: str = ""
    decompiler_note: str = ""
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


# ----------------------------- Safe primitives -----------------------------

def bounded(data: bytes) -> bytes:
    if len(data) > MAX_OUTPUT_BYTES:
        raise ValueError("decoded output exceeded the configured size limit")
    return data


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_text(data: bytes) -> str:
    if data.startswith(codecs.BOM_UTF8):
        return data.decode("utf-8-sig", errors="replace")
    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def is_text(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:8192]
    if b"\x00" in sample:
        return False
    valid = sum(
        b in (9, 10, 13) or 32 <= b <= 126 or b >= 160
        for b in sample
    )
    return valid / max(1, len(sample)) >= 0.78


def looks_like_python(text: str) -> bool:
    return any(hint in text for hint in PY_HINTS) or text.lstrip().startswith("#!")


def syntax_check(text: str) -> tuple[bool, str]:
    try:
        ast.parse(text)
        return True, "Python syntax parsed successfully."
    except SyntaxError as exc:
        return False, f"SyntaxError at line {exc.lineno}, column {exc.offset}: {exc.msg}"
    except (ValueError, TypeError, MemoryError, RecursionError) as exc:
        return False, f"Parser issue: {type(exc).__name__}: {exc}"


def printable_strings(data: bytes, minimum: int = 5) -> list[str]:
    found: list[str] = []
    try:
        for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
            found.append(match.group().decode("ascii", errors="replace"))
    except Exception:
        pass
    # UTF-16LE ASCII-range strings
    try:
        decoded = data.decode("utf-16le", errors="ignore")
        found.extend(
            match.group() for match in re.finditer(r"[ -~]{%d,}" % minimum, decoded)
        )
    except Exception:
        pass
    # Keep order, cap output, and avoid empty strings.
    return list(dict.fromkeys(x.strip() for x in found if x.strip()))[:MAX_STRINGS_IN_REPORT]


# ----------------------------- Decode detectors ----------------------------

def decode_base64(data: bytes) -> Optional[bytes]:
    try:
        raw = re.sub(rb"\s+", b"", data.strip())
        if len(raw) < 8 or not re.fullmatch(rb"[A-Za-z0-9+/_-]*={0,2}", raw):
            return None
        raw = raw.replace(b"-", b"+").replace(b"_", b"/")
        raw += b"=" * ((-len(raw)) % 4)
        out = base64.b64decode(raw, validate=True)
        return bounded(out) if out and out != data else None
    except (ValueError, binascii.Error):
        return None


def decode_base32(data: bytes) -> Optional[bytes]:
    try:
        raw = re.sub(rb"\s+", b"", data.strip()).upper()
        if len(raw) < 8 or not re.fullmatch(rb"[A-Z2-7]+=*", raw):
            return None
        raw += b"=" * ((-len(raw)) % 8)
        out = base64.b32decode(raw, casefold=True)
        return bounded(out) if out and out != data else None
    except Exception:
        return None


def decode_base85(data: bytes) -> Optional[bytes]:
    try:
        raw = data.strip()
        if len(raw) < 10:
            return None
        out = base64.b85decode(raw)
        return bounded(out) if out and out != data else None
    except Exception:
        try:
            out = base64.a85decode(data.strip(), adobe=True)
            return bounded(out) if out and out != data else None
        except Exception:
            return None


def decode_hex(data: bytes) -> Optional[bytes]:
    try:
        raw = data.strip()
        if raw.lower().startswith(b"0x"):
            raw = raw[2:]
        raw = re.sub(rb"[\s,:_-]", b"", raw)
        if len(raw) < 8 or len(raw) % 2 or not re.fullmatch(rb"[0-9a-fA-F]+", raw):
            return None
        out = bytes.fromhex(raw.decode("ascii"))
        return bounded(out) if out and out != data else None
    except Exception:
        return None


def decode_binary(data: bytes) -> Optional[bytes]:
    try:
        text = data.decode("ascii").strip()
        chunks = re.split(r"[\s,]+", text)
        if len(chunks) < 8 or any(not re.fullmatch(r"[01]{8}", c) for c in chunks):
            return None
        out = bytes(int(c, 2) for c in chunks)
        return bounded(out) if out and out != data else None
    except Exception:
        return None


def decode_url(data: bytes) -> Optional[bytes]:
    try:
        text = data.decode("utf-8").strip()
        if not re.search(r"%(?:[0-9a-fA-F]{2})", text):
            return None
        out = urllib.parse.unquote_to_bytes(text.replace("+", " "))
        return bounded(out) if out and out != data else None
    except Exception:
        return None


def decode_rot13(data: bytes) -> Optional[bytes]:
    try:
        text = data.decode("utf-8")
        if not text.isascii() or not any(ch.isalpha() for ch in text):
            return None
        out = codecs.encode(text, "rot_13").encode()
        decoded = out.decode("utf-8", "ignore")
        return out if out != data and looks_like_python(decoded) else None
    except Exception:
        return None


def decode_reverse(data: bytes) -> Optional[bytes]:
    out = data[::-1]
    if out == data:
        return None
    if is_text(out):
        text = safe_text(out)
        if looks_like_python(text) or decode_base64(out) is not None or decode_hex(out) is not None:
            return out
    return None


def decompress_any(data: bytes) -> list[tuple[bytes, str]]:
    results = []
    methods = (
        ("zlib", zlib.decompress),
        ("gzip", gzip.decompress),
        ("bz2", bz2.decompress),
        ("lzma/xz", lzma.decompress),
    )
    for name, func in methods:
        try:
            out = bounded(func(data))
            if out and out != data:
                results.append((out, name))
        except Exception:
            continue
    try:
        out = bounded(zlib.decompress(data, -zlib.MAX_WBITS))
        if out and out != data:
            results.append((out, "raw deflate"))
    except Exception:
        pass
    return results


def decode_candidates(data: bytes) -> list[tuple[bytes, str]]:
    candidates = []
    methods = (
        ("Base64", decode_base64),
        ("Base32", decode_base32),
        ("Base85", decode_base85),
        ("Hex", decode_hex),
        ("Binary text", decode_binary),
        ("URL encoding", decode_url),
        ("ROT13", decode_rot13),
        ("Reversed bytes", decode_reverse),
    )
    for label, func in methods:
        try:
            out = func(data)
            if out:
                candidates.append((out, label))
        except Exception:
            continue
    candidates.extend(decompress_any(data))
    # Stable deduplication
    seen = set()
    unique = []
    for blob, label in candidates:
        digest = hashlib.sha256(blob).digest()
        if digest not in seen:
            seen.add(digest)
            unique.append((blob, label))
    return unique


# ----------------------- AST literal and data-flow engine -------------------

class StaticResolver:
    """
    Resolve only safe, statically-known values. Never eval() or execute code.
    Handles constants, concatenation, bytes(), chr(), ord(), reversed(),
    join(), selected encoding/compression calls and simple variable chains.
    """

    def __init__(self, tree: ast.AST):
        self.tree = tree
        self.values: dict[str, Any] = {}
        self.assign_nodes: dict[str, list[ast.AST]] = defaultdict(list)
        self.node_count = 0
        self._collect_assignments()

    def _collect_assignments(self) -> None:
        for node in ast.walk(self.tree):
            self.node_count += 1
            if self.node_count > MAX_AST_NODES:
                raise ValueError("AST node limit reached")
            targets: list[ast.AST] = []
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    self.assign_nodes[target.id].append(node)

    def resolve_name(self, name: str, depth: int = 0) -> Any:
        if name in self.values:
            return self.values[name]
        if depth > 20:
            return None
        nodes = self.assign_nodes.get(name, [])
        # Last assignment wins only if every relevant assignment can be resolved.
        resolved = None
        for node in nodes[-20:]:
            value_node = node.value
            value = self.resolve(value_node, depth + 1, set())
            if value is None:
                continue
            resolved = value
        if resolved is not None:
            self.values[name] = resolved
        return resolved

    def resolve(self, node: ast.AST, depth: int = 0, seen: Optional[set[int]] = None) -> Any:
        if depth > 25:
            return None
        if seen is None:
            seen = set()
        ident = id(node)
        if ident in seen:
            return None
        seen.add(ident)
        try:
            if isinstance(node, ast.Constant):
                if isinstance(node.value, (str, bytes, int, float, bool, type(None))):
                    return node.value
                return None
            if isinstance(node, ast.Name):
                return self.resolve_name(node.id, depth + 1)
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                vals = [self.resolve(x, depth + 1, seen.copy()) for x in node.elts]
                if any(v is None for v in vals):
                    return None
                return vals if isinstance(node, ast.List) else tuple(vals) if isinstance(node, ast.Tuple) else set(vals)
            if isinstance(node, ast.Dict):
                keys = [self.resolve(k, depth + 1, seen.copy()) for k in node.keys]
                vals = [self.resolve(v, depth + 1, seen.copy()) for v in node.values]
                if any(v is None for v in keys + vals):
                    return None
                return dict(zip(keys, vals))
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
                left = self.resolve(node.left, depth + 1, seen.copy())
                right = self.resolve(node.right, depth + 1, seen.copy())
                if isinstance(node.op, ast.Add) and type(left) is type(right) and isinstance(left, (str, bytes, tuple, list)):
                    out = left + right
                    return out if len(out) <= MAX_OUTPUT_BYTES else None
                if isinstance(node.op, ast.Mod) and isinstance(left, (str, bytes)):
                    if isinstance(right, (str, bytes, tuple, dict, int)):
                        try:
                            out = left % right
                            return out if len(out) <= MAX_OUTPUT_BYTES else None
                        except Exception:
                            return None
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
                val = self.resolve(node.operand, depth + 1, seen.copy())
                return -val if isinstance(val, (int, float)) else None
            if isinstance(node, ast.JoinedStr):
                pieces = []
                for value in node.values:
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        pieces.append(value.value)
                    else:
                        return None
                return "".join(pieces)
            if isinstance(node, ast.Call):
                return self._resolve_call(node, depth, seen)
            if isinstance(node, ast.Subscript):
                base = self.resolve(node.value, depth + 1, seen.copy())
                # Python slicing is common in lightweight packers: value[::-1],
                # value[2:], value[:-1], and related forms.
                if isinstance(node.slice, ast.Slice):
                    lower = self.resolve(node.slice.lower, depth + 1, seen.copy()) if node.slice.lower else None
                    upper = self.resolve(node.slice.upper, depth + 1, seen.copy()) if node.slice.upper else None
                    step = self.resolve(node.slice.step, depth + 1, seen.copy()) if node.slice.step else None
                    try:
                        if isinstance(base, (str, bytes, tuple, list)):
                            return base[slice(lower, upper, step)]
                    except Exception:
                        return None
                    return None
                index = self.resolve(node.slice, depth + 1, seen.copy())
                try:
                    if isinstance(base, (str, bytes, tuple, list, dict)) and isinstance(index, (int, str)):
                        return base[index]
                except Exception:
                    return None
            return None
        except (MemoryError, RecursionError, ValueError, TypeError, OverflowError):
            return None

    def _resolve_call(self, node: ast.Call, depth: int, seen: set[int]) -> Any:
        name = call_name(node.func)
        args = [self.resolve(a, depth + 1, seen.copy()) for a in node.args]
        if name == "compile" and args and isinstance(args[0], (str, bytes)):
            # Return the source argument as data; never compile or execute it.
            return args[0]
        if name.endswith(".decode") and args == [] and isinstance(node.func, ast.Attribute):
            receiver = self.resolve(node.func.value, depth + 1, seen.copy())
            encoding = "utf-8"
            for keyword in node.keywords:
                if keyword.arg == "encoding":
                    candidate = self.resolve(keyword.value, depth + 1, seen.copy())
                    if isinstance(candidate, str):
                        encoding = candidate
            try:
                return receiver.decode(encoding, errors="replace") if isinstance(receiver, bytes) else None
            except Exception:
                return None
        if name.endswith(".encode") and args == [] and isinstance(node.func, ast.Attribute):
            receiver = self.resolve(node.func.value, depth + 1, seen.copy())
            encoding = "utf-8"
            for keyword in node.keywords:
                if keyword.arg == "encoding":
                    candidate = self.resolve(keyword.value, depth + 1, seen.copy())
                    if isinstance(candidate, str):
                        encoding = candidate
            try:
                return receiver.encode(encoding) if isinstance(receiver, str) else None
            except Exception:
                return None
        if name in {"bytes.fromhex", "fromhex"} and args and isinstance(args[0], str):
            try:
                return bytes.fromhex(args[0])
            except Exception:
                return None
        if name in {"base64.b64decode", "b64decode"} and args and isinstance(args[0], (str, bytes)):
            try:
                raw = args[0].encode() if isinstance(args[0], str) else args[0]
                return bounded(base64.b64decode(raw + b"=" * ((-len(raw)) % 4)))
            except Exception:
                return None
        if name in {"base64.urlsafe_b64decode", "urlsafe_b64decode"} and args and isinstance(args[0], (str, bytes)):
            try:
                raw = args[0].encode() if isinstance(args[0], str) else args[0]
                return bounded(base64.urlsafe_b64decode(raw + b"=" * ((-len(raw)) % 4)))
            except Exception:
                return None
        if name in {"base64.b32decode", "b32decode"} and args and isinstance(args[0], (str, bytes)):
            try:
                raw = args[0].encode() if isinstance(args[0], str) else args[0]
                return bounded(base64.b32decode(raw + b"=" * ((-len(raw)) % 8), casefold=True))
            except Exception:
                return None
        if name in {"zlib.decompress", "decompress"} and args and isinstance(args[0], bytes):
            try:
                return bounded(zlib.decompress(args[0]))
            except Exception:
                return None
        if name in {"gzip.decompress"} and args and isinstance(args[0], bytes):
            try:
                return bounded(gzip.decompress(args[0]))
            except Exception:
                return None
        if name in {"bz2.decompress"} and args and isinstance(args[0], bytes):
            try:
                return bounded(bz2.decompress(args[0]))
            except Exception:
                return None
        if name in {"lzma.decompress"} and args and isinstance(args[0], bytes):
            try:
                return bounded(lzma.decompress(args[0]))
            except Exception:
                return None
        if name in {"codecs.decode", "decode"} and len(args) >= 2:
            try:
                return codecs.decode(args[0], args[1])
            except Exception:
                return None
        if name == "chr" and args and isinstance(args[0], int) and 0 <= args[0] <= 0x10FFFF:
            return chr(args[0])
        if name == "ord" and args and isinstance(args[0], str) and len(args[0]) == 1:
            return ord(args[0])
        if name == "str" and args and args[0] is not None:
            return str(args[0])[:MAX_TEXT_CHARS]
        if name == "bytes" and args:
            try:
                if isinstance(args[0], (list, tuple)) and all(isinstance(x, int) for x in args[0]):
                    return bytes(args[0])
                if isinstance(args[0], str):
                    encoding = args[1] if len(args) > 1 and isinstance(args[1], str) else "utf-8"
                    return args[0].encode(encoding, errors="replace")
            except Exception:
                return None
        if name in {"list", "tuple"} and args and isinstance(args[0], (str, bytes, list, tuple)):
            return list(args[0]) if name == "list" else tuple(args[0])
        if name == "reversed" and args and isinstance(args[0], (str, bytes, list, tuple)):
            return args[0][::-1]
        if name.endswith(".join") and len(args) == 1 and isinstance(args[0], (list, tuple)):
            sep = self.resolve(node.func.value, depth + 1, seen.copy()) if isinstance(node.func, ast.Attribute) else None
            if isinstance(sep, (str, bytes)) and all(type(x) is type(sep) for x in args[0]):
                try:
                    return sep.join(args[0])
                except Exception:
                    return None
        if name in {"int"} and args and isinstance(args[0], str):
            try:
                base = args[1] if len(args) > 1 and isinstance(args[1], int) else 10
                return int(args[0], base)
            except Exception:
                return None
        return None


def call_name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def line_of(node: ast.AST) -> Optional[int]:
    return getattr(node, "lineno", None)


# ------------------------------ AST inspection ------------------------------

def inspect_ast(text: str, report: Analysis) -> None:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError) as exc:
        report.syntax_ok = False
        report.syntax_error = f"{type(exc).__name__}: {exc}"
        report.warnings.append("AST parsing failed; fallback string/token scanning was used.")
        return

    report.syntax_ok = True
    resolver = StaticResolver(tree)
    imports = set()
    calls = Counter()
    assignments = 0
    strings = 0
    payload_refs = []
    findings = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            else:
                imports.add(node.module or "")
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            assignments += 1
        elif isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            strings += 1
        elif isinstance(node, ast.Call):
            name = call_name(node.func)
            calls[name] += 1
            short = name.split(".")[-1]
            if name in DANGEROUS_CALLS or short in {"exec", "eval", "compile", "__import__"}:
                findings.append(Finding(
                    "dynamic execution",
                    f"Potential dynamic-code call: {name}()",
                    line_of(node),
                ))
            if short in ENCODING_CALLS or name.endswith(".decompress"):
                findings.append(Finding(
                    "decode / loader",
                    f"Potential payload transformation: {name}()",
                    line_of(node),
                ))
            if short in {"exec", "eval", "compile"} and node.args:
                payload_refs.append((node.args[0], name, line_of(node)))
        elif isinstance(node, ast.Subprocess if hasattr(ast, "Subprocess") else ast.AST):
            pass

    report.imports = sorted(x for x in imports if x)
    report.stats = {
        "AST nodes": resolver.node_count,
        "assignments": assignments,
        "string constants": strings,
        "function definitions": sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree)),
        "class definitions": sum(isinstance(n, ast.ClassDef) for n in ast.walk(tree)),
        "calls": sum(calls.values()),
    }
    report.findings.extend(findings)

    # Look for every statically recoverable assigned value, not just the last string.
    for name, nodes in resolver.assign_nodes.items():
        for node in nodes[-10:]:
            value = resolver.resolve(node.value)
            if isinstance(value, str):
                raw = value.encode("utf-8", errors="replace")
            elif isinstance(value, bytes):
                raw = value
            else:
                continue
            if len(raw) >= 8 and (not is_text(raw) or looks_like_python(safe_text(raw)) or decode_candidates(raw)):
                report.payloads.append(Payload(
                    label=f"variable: {name}",
                    source="AST assignment / static value reconstruction",
                    data=raw,
                    line=line_of(node),
                    confidence="high" if decode_candidates(raw) else "possible",
                ))

    # Resolve arguments passed to dynamic execution sinks.
    for expression, sink, lineno in payload_refs:
        value = resolver.resolve(expression)
        if isinstance(value, str):
            raw = value.encode("utf-8", errors="replace")
        elif isinstance(value, bytes):
            raw = value
        else:
            raw = b""
        if raw:
            report.payloads.append(Payload(
                label=f"argument to {sink}()",
                source="statically resolved dynamic-execution argument",
                data=raw,
                line=lineno,
                confidence="high",
            ))
        else:
            report.findings.append(Finding(
                "unresolved dynamic payload",
                f"Could not statically resolve argument to {sink}(). It may be built at runtime.",
                lineno,
            ))

    # Report calls that are often associated with obfuscation or loaders.
    for name, count in calls.most_common(30):
        if name.split(".")[-1] in ENCODING_CALLS or name.endswith(".decompress"):
            report.findings.append(Finding(
                "transform call", f"{name} appears {count} time(s)"
            ))


# ----------------------------- Payload recovery -----------------------------

def recover_layers(initial: bytes, label: str, source: str, line: Optional[int]) -> list[Payload]:
    outputs = []
    queue: list[tuple[bytes, list[str]]] = [(initial, [])]
    seen = {sha256(initial)}
    iterations = 0
    while queue and iterations < MAX_DECODE_LAYERS:
        current, layers = queue.pop(0)
        iterations += 1
        outputs.append(Payload(
            label=label, source=source, data=current,
            layers=list(layers), line=line,
            confidence="high" if layers else "possible",
        ))
        if len(outputs) >= 20:
            break
        for candidate, method in decode_candidates(current):
            digest = sha256(candidate)
            if digest in seen:
                continue
            seen.add(digest)
            queue.append((candidate, layers + [method]))
    return outputs


def pyc_header_info(data: bytes) -> str:
    if len(data) < 8:
        return ""
    magic = importlib.util.MAGIC_NUMBER
    if data[:4] == magic:
        flags = int.from_bytes(data[4:8], "little")
        return (
            f"Bytecode magic matches this bot runtime (Python "
            f"{sys.version_info.major}.{sys.version_info.minor}); flags={flags}. "
            "A compatible decompiler may still be needed."
        )
    if data[:2] == b"\x1b\r":
        return "Possible .pyc file; bytecode magic differs from this runtime."
    return ""


def try_decompile_pyc(data: bytes, filename: str) -> tuple[str, str]:
    info = pyc_header_info(data)
    if not info or data[:4] != importlib.util.MAGIC_NUMBER:
        return "", "No bytecode matching this Python runtime was identified."
    tools = [name for name in ("decompyle3", "uncompyle6") if shutil.which(name)]
    if not tools:
        return "", "Optional decompiler not installed; install decompyle3 or uncompyle6."
    with tempfile.TemporaryDirectory(prefix="py_static_") as tmp:
        src = Path(tmp) / (Path(filename).name or "input.pyc")
        out = Path(tmp) / "recovered.py"
        src.write_bytes(data)
        last_error = ""
        for tool in tools:
            try:
                proc = subprocess.run(
                    [tool, "-o", str(out), str(src)],
                    cwd=tmp, capture_output=True, text=True, timeout=18,
                    env={"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"},
                    check=False,
                )
                if out.exists() and out.stat().st_size <= MAX_OUTPUT_BYTES:
                    text = out.read_text("utf-8", errors="replace")
                    if text.strip():
                        return text, f"Best-effort output from {tool}."
                last_error = (proc.stderr or proc.stdout or f"{tool} returned no source")[-500:]
            except subprocess.TimeoutExpired:
                last_error = f"{tool} timed out."
            except Exception as exc:
                last_error = f"{tool}: {type(exc).__name__}: {exc}"
        return "", last_error or "Decompilation was unsuccessful."


def analyze_file(data: bytes, filename: str) -> Analysis:
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"File exceeds {MAX_FILE_MB} MB limit.")
    started = time.monotonic()
    report = Analysis(filename, len(data), sha256(data))
    report.strings = printable_strings(data)
    report.pyc_info = pyc_header_info(data)

    suffix = Path(filename).suffix.lower()
    if suffix in {".pyc", ".pyo"} or report.pyc_info:
        decompiled, note = try_decompile_pyc(data, filename)
        report.decompiler_note = note
        if decompiled:
            report.source_text = decompiled
            report.syntax_ok, report.syntax_error = syntax_check(decompiled)
            inspect_ast(decompiled, report)
            report.findings.append(Finding("bytecode", "Source was recovered by an optional decompiler."))
        else:
            report.warnings.append(note)

    if is_text(data):
        source = safe_text(data)
        report.source_text = source
        report.syntax_ok, report.syntax_error = syntax_check(source)
        if report.syntax_ok:
            inspect_ast(source, report)
        else:
            # Tokenization can still reveal strings/import-like content despite syntax errors.
            try:
                for tok in tokenize.generate_tokens(io.StringIO(source).readline):
                    if tok.type == tokenize.STRING:
                        try:
                            value = ast.literal_eval(tok.string)
                            if isinstance(value, (str, bytes)):
                                raw = value.encode() if isinstance(value, str) else value
                                if len(raw) >= 8:
                                    report.payloads.append(Payload(
                                        "string token", "tokenizer fallback", raw,
                                        line=tok.start[0], confidence="possible"
                                    ))
                        except Exception:
                            pass
            except (tokenize.TokenError, IndentationError, SyntaxError):
                pass
            report.warnings.append("Source has syntax/encoding issues; partial scanning was attempted.")
            # AST partial recovery: parse independent top-level fragments.
            report.payloads.extend(scan_recoverable_fragments(source))

    # Scan raw file itself for a possible encoded blob, and all AST payload candidates.
    raw_candidates = [Payload("whole file", "raw file bytes", data)]
    raw_candidates.extend(report.payloads)
    recovered: list[Payload] = []
    seen_payloads = set()
    for candidate in raw_candidates[:MAX_CANDIDATES]:
        if len(recovered) >= MAX_CANDIDATES:
            break
        key = sha256(candidate.data)
        if key in seen_payloads:
            continue
        seen_payloads.add(key)
        remaining = MAX_CANDIDATES - len(recovered)
        recovered.extend(recover_layers(
            candidate.data, candidate.label, candidate.source, candidate.line
        )[:remaining])
    report.payloads = deduplicate_payloads(recovered)[:MAX_CANDIDATES]

    # Add likely source outputs from decoded candidates.
    source_candidates = []
    for payload in report.payloads:
        if is_text(payload.data):
            candidate_text = safe_text(payload.data)
            if looks_like_python(candidate_text):
                valid, _ = syntax_check(candidate_text)
                # A statically resolved exec/eval/compile argument is a much
                # stronger source candidate than the outer loader wrapper.
                priority = 3 if payload.label.startswith("argument to ") else 2 if payload.layers else 0
                source_candidates.append((valid, priority, len(candidate_text), candidate_text, payload))
    if source_candidates:
        source_candidates.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
        best_valid, best_priority, _, best, best_payload = source_candidates[0]
        original_is_loader = any(token in report.source_text for token in (
            "exec(", "eval(", "base64.b64decode", "zlib.decompress", "marshal.loads"
        ))
        # Prefer extracted executable payloads even when the wrapper is longer
        # and itself parses as valid Python.
        should_replace = (
            best != report.source_text
            and best_valid
            and (best_priority > 0 or not report.syntax_ok or original_is_loader)
        )
        if should_replace:
            report.source_text = best
            report.syntax_ok, report.syntax_error = syntax_check(best)
            report.findings.append(Finding(
                "recovered source",
                f"Selected extracted payload from {best_payload.label}; "
                "it outranked the outer loader wrapper."
            ))

    report.stats["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    report.stats["payload_candidates"] = len(report.payloads)
    report.stats["strings_extracted"] = len(report.strings)
    return report


def scan_recoverable_fragments(source: str) -> list[Payload]:
    """Parse independent top-level statements to salvage strings from damaged source."""
    payloads = []
    try:
        lines = source.splitlines()
    except Exception:
        return payloads
    # Conservative fallback: parse line groups; never execute.
    for index, line in enumerate(lines[:5000], 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(stripped) > MAX_TEXT_CHARS:
            continue
        try:
            node = ast.parse(stripped)
            resolver = StaticResolver(node)
            for name, nodes in resolver.assign_nodes.items():
                for assignment in nodes:
                    value = resolver.resolve(assignment.value)
                    if isinstance(value, str):
                        raw = value.encode("utf-8", errors="replace")
                    elif isinstance(value, bytes):
                        raw = value
                    else:
                        continue
                    if len(raw) >= 8:
                        payloads.append(Payload(
                            f"fragment variable: {name}", "line-level AST fallback",
                            raw, line=index, confidence="possible"
                        ))
        except Exception:
            continue
    return payloads


def deduplicate_payloads(items: list[Payload]) -> list[Payload]:
    seen = set()
    result = []
    for item in items:
        key = (sha256(item.data), tuple(item.layers))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


# ------------------------------- Report output ------------------------------

def build_report(a: Analysis) -> str:
    lines = [
        f"{BRAND}  /  PYTHON PAYLOAD ANALYSIS",
        "=" * 62,
        f"File: {a.filename}",
        f"Size: {a.size:,} bytes",
        f"SHA-256: {a.sha256}",
        f"Python syntax: {'valid' if a.syntax_ok else 'not confirmed'}",
        "",
        "SUMMARY",
        "-" * 62,
    ]
    for key, value in a.stats.items():
        lines.append(f"{key}: {value}")
    if a.syntax_error:
        lines.append("Syntax detail: " + a.syntax_error)
    if a.pyc_info:
        lines += ["", "BYTECODE", "-" * 62, a.pyc_info]
    if a.decompiler_note:
        lines.append(a.decompiler_note)

    lines += ["", "IMPORTS", "-" * 62]
    lines.extend(a.imports[:150] or ["No imports identified."])

    lines += ["", "FINDINGS", "-" * 62]
    if not a.findings:
        lines.append("No notable loader/decode patterns identified.")
    for f in a.findings[:250]:
        loc = f"line {f.line}: " if f.line else ""
        lines.append(f"[{f.category}] {loc}{f.description}")

    lines += ["", "PAYLOAD CANDIDATES", "-" * 62]
    if not a.payloads:
        lines.append("No payload candidate recovered.")
    for i, p in enumerate(a.payloads[:100], 1):
        line = f", line {p.line}" if p.line else ""
        layers = " -> ".join(p.layers) if p.layers else "no transform"
        lines.append(
            f"{i}. {p.label}{line}\n"
            f"   source: {p.source}\n"
            f"   size: {len(p.data)} bytes | confidence: {p.confidence}\n"
            f"   layers: {layers}"
        )

    lines += ["", "WARNINGS", "-" * 62]
    lines.extend(a.warnings or ["None."])
    lines += [
        "",
        "SAFETY / LIMITATIONS",
        "-" * 62,
        "No uploaded code or recovered payload was executed.",
        "Unknown encryption needs the correct key. Runtime-built strings, custom",
        "virtual machines, external dependencies and unsupported bytecode may",
        "prevent complete recovery. Syntax validation is not a security guarantee.",
    ]
    return "\n".join(lines)


def build_source_output(a: Analysis) -> bytes:
    if a.source_text.strip():
        text = a.source_text
    else:
        text = (
            "# No complete Python source was recovered.\n"
            "# See the companion analysis report for candidates and extracted strings.\n"
        )
    return text.encode("utf-8", errors="replace")


def build_payload_bundle(a: Analysis) -> bytes:
    """Plain text bundle of decoded payload candidates for manual inspection."""
    chunks = [f"# {BRAND} - RECOVERED PAYLOAD CANDIDATES\n"]
    for i, p in enumerate(a.payloads[:100], 1):
        chunks.append(
            f"\n\n# {'=' * 30}\n# Candidate {i}: {p.label}\n"
            f"# Source: {p.source}\n# Line: {p.line}\n"
            f"# Layers: {' -> '.join(p.layers) or 'none'}\n"
        )
        if is_text(p.data):
            chunks.append(safe_text(p.data))
        else:
            chunks.append("# Binary payload (hex preview):\n" + p.data[:4096].hex())
    return "\n".join(chunks).encode("utf-8", errors="replace")


# -------------------------------- Telegram UI -------------------------------

def authorized(update: Update) -> bool:
    if not ALLOWED_IDS:
        return True
    user = update.effective_user
    return bool(user and user.id in ALLOWED_IDS)


async def require_access(update: Update) -> bool:
    if authorized(update):
        return True
    if update.effective_message:
        await update.effective_message.reply_text("This bot is currently restricted.")
    return False


def menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("How it works", callback_data="how"),
            InlineKeyboardButton("Capabilities", callback_data="features"),
        ],
        [InlineKeyboardButton("Privacy & limits", callback_data="privacy")],
    ])


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_access(update):
        return
    msg = (
        "<b>PYTHON PAYLOAD ANALYZER</b>\n"
        f"<code>{BRAND}</code>\n\n"
        "Send a Python file or paste encoded content.\n"
        "I'll inspect the source, trace statically-known payload variables, "
        "try common decoding layers and return an analysis report.\n\n"
        "<i>Static analysis only. Nothing you upload is executed.</i>"
    )
    await update.effective_message.reply_text(msg, parse_mode="HTML", reply_markup=menu())


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_access(update):
        return
    await update.effective_message.reply_text(
        "Send a .py, .pyw, .pyi, .pyc or .pyo file, or paste a payload.\n\n"
        "/start — home\n/help — instructions\n/features — supported analysis\n"
        "/limits — current limits\n\n"
        "The analyzer scans the whole file, examines assignments and loader calls, "
        "and tries to recover statically-resolvable strings. It does not run code."
    )


async def features_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_access(update):
        return
    await update.effective_message.reply_text(
        "<b>ANALYSIS MODULES</b>\n\n"
        "• Whole-file scanning and SHA-256 fingerprint\n"
        "• AST parsing, syntax diagnostics and tokenizer fallback\n"
        "• Variable assignment collection and reference tracing\n"
        "• Static string/bytes reconstruction\n"
        "• exec/eval/compile argument inspection\n"
        "• Concatenation, formatting and literal container handling\n"
        "• chr/ord/bytes/fromhex/reversed/join reconstruction\n"
        "• Base16/32/64/85, URL, binary and ROT13 decoding\n"
        "• zlib, gzip, bz2, lzma and raw-deflate extraction\n"
        "• Nested layers, candidate deduplication and size limits\n"
        "• Printable ASCII/UTF-16 string extraction\n"
        "• Imports, functions, classes and call statistics\n"
        "• Loader/transform call detection\n"
        "• .pyc header recognition and optional decompilation\n"
        "• Recovered source, payload bundle and detailed report\n"
        "• No uploaded code execution",
        parse_mode="HTML",
    )


async def limits_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_access(update):
        return
    await update.effective_message.reply_text(
        f"File limit: {MAX_FILE_MB} MB\n"
        f"Text limit: {MAX_TEXT_CHARS:,} characters\n"
        f"Decode depth: {MAX_DECODE_LAYERS}\n"
        f"Candidate cap: {MAX_CANDIDATES}\n"
        "Long-running operations have a time limit. Limits protect the bot from "
        "oversized or malformed input."
    )


async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query:
        return
    await query.answer()
    if not await require_access(update):
        return
    if query.data == "how":
        text = (
            "Upload a Python file or paste encoded text. The bot parses source "
            "without executing it, finds statically resolvable payload values, "
            "then tries supported decoding and decompression steps."
        )
    elif query.data == "features":
        text = (
            "AST analysis, variable tracing, loader-call inspection, nested "
            "encoding/compression detection, printable-string extraction, "
            "syntax diagnostics and optional .pyc decompilation."
        )
    else:
        text = (
            f"Files up to {MAX_FILE_MB} MB. Source is processed in memory and "
            "temporary bytecode files are removed after analysis. No uploaded "
            "code is executed. Do not upload secrets or private credentials."
        )
    await query.message.reply_text(text)


async def send_document_with_retry(msg, document: bytes, filename: str, caption: str) -> bool:
    """Upload one generated file with a longer timeout and one cautious retry."""
    for attempt in range(2):
        try:
            await msg.reply_document(
                document=InputFile(io.BytesIO(document), filename=filename),
                caption=caption,
                connect_timeout=30,
                read_timeout=120,
                write_timeout=120,
                pool_timeout=30,
            )
            return True
        except (TimedOut, NetworkError) as exc:
            log.warning(
                "Telegram document upload failed (%s), attempt %s/2",
                type(exc).__name__, attempt + 1,
            )
            if attempt == 0:
                await asyncio.sleep(2)
        except (BadRequest, Forbidden) as exc:
            log.error("Telegram rejected document %s: %s", filename, type(exc).__name__)
            return False
    return False


async def send_analysis(update: Update, filename: str, raw: bytes) -> None:
    msg = update.effective_message
    if not msg:
        return
    if len(raw) > MAX_INPUT_BYTES:
        await msg.reply_text(f"File exceeds the {MAX_FILE_MB} MB limit.")
        return
    status = await msg.reply_text("Reading and analysing…")
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(analyze_file, raw, filename),
            timeout=MAX_FILE_SECONDS,
        )
        report_bytes = build_report(result).encode("utf-8", errors="replace")
        source_bytes = build_source_output(result)
        payload_bytes = build_payload_bundle(result)
        syntax = "valid" if result.syntax_ok else "not confirmed"
        summary = (
            "<b>Analysis complete</b>\n"
            f"Syntax: {syntax}\n"
            f"Payload candidates: {len(result.payloads)}\n"
            f"Extracted strings: {len(result.strings)}\n"
            f"Findings: {len(result.findings)}\n"
            f"Time: {result.stats.get('elapsed_ms', 0)} ms"
        )
        await status.edit_text(summary, parse_mode="HTML")
        stem = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(filename).stem)[:45] or "python"
        uploads = [
            (source_bytes, f"{stem}_recovered.py", "Best recovered source (may be partial)."),
            (report_bytes, f"{stem}_analysis.txt", "Detailed static analysis report."),
        ]
        if result.payloads:
            uploads.append((payload_bytes, f"{stem}_payloads.txt",
                            "Decoded payload candidates for manual review."))

        failed = []
        for data, out_name, caption in uploads:
            if not await send_document_with_retry(msg, data, out_name, caption):
                failed.append(out_name)

        if failed:
            await status.edit_text(
                "Analysis finished, but Telegram could not upload: "
                + ", ".join(failed)
                + ". Please resend / try again on a more stable connection."
            )
        else:
            await status.edit_text("Analysis complete. All output files were sent.")
    except asyncio.TimeoutError:
        await status.edit_text("Analysis timed out. Try a smaller file or lower-complexity input.")
    except (MemoryError, RecursionError) as exc:
        await status.edit_text(f"Input exceeded processing resources: {type(exc).__name__}.")
    except Exception as exc:
        log.exception("Analysis failure")
        try:
            await status.edit_text(f"Could not analyse input: {type(exc).__name__}.")
        except Exception:
            await msg.reply_text(f"Could not analyse input: {type(exc).__name__}.")


async def document_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_access(update):
        return
    msg = update.effective_message
    if not msg or not msg.document:
        return
    doc = msg.document
    filename = doc.file_name or "python_input.py"
    suffix = Path(filename).suffix.lower()
    if suffix not in TEXT_EXTENSIONS:
        await msg.reply_text(
            "Python files only. Supported: .py, .pyw, .pyi, .pyc, .pyo "
            "(also .txt/.bin/.dat for raw payloads)."
        )
        return
    if doc.file_size and doc.file_size > MAX_INPUT_BYTES:
        await msg.reply_text(f"File exceeds the {MAX_FILE_MB} MB limit.")
        return
    try:
        await msg.chat.send_action(ChatAction.TYPING)
        tg_file = await context.bot.get_file(doc.file_id)
        content = await tg_file.download_as_bytearray()
        await send_analysis(update, filename, bytes(content))
    except (TimedOut, NetworkError):
        await msg.reply_text("Telegram download timed out. Please resend the file.")
    except Forbidden:
        await msg.reply_text("I couldn't access that file. Please resend it.")
    except Exception as exc:
        log.exception("Download error")
        await msg.reply_text(f"File download failed: {type(exc).__name__}.")


async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await require_access(update):
        return
    msg = update.effective_message
    if not msg or not msg.text:
        return
    text = msg.text.strip()
    if not text or text.startswith("/"):
        return
    if len(text) > MAX_TEXT_CHARS:
        await msg.reply_text("Text is too long. Upload it as a .txt or .py file.")
        return
    await send_analysis(update, "pasted_payload.py", text.encode("utf-8"))


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    err = context.error
    if isinstance(err, RetryAfter):
        log.warning("Telegram rate limited; retry after %s", err.retry_after)
    elif isinstance(err, (TimedOut, NetworkError)):
        log.warning("Telegram network issue: %s", type(err).__name__)
    else:
        log.exception("Unhandled Telegram error", exc_info=err)


def main() -> None:
    if not BOT_TOKEN:
        raise SystemExit(
            "BOT_TOKEN is missing. Set it first:\n"
            '  export BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"'
        )
    upload_request = HTTPXRequest(
        connection_pool_size=20,
        connect_timeout=30,
        read_timeout=120,
        write_timeout=120,
        pool_timeout=30,
    )
    polling_request = HTTPXRequest(
        connection_pool_size=8,
        connect_timeout=30,
        read_timeout=45,
        write_timeout=30,
        pool_timeout=30,
    )
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .request(upload_request)
        .get_updates_request(polling_request)
        .concurrent_updates(2)
        .build()
    )
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("features", features_cmd))
    app.add_handler(CommandHandler("limits", limits_cmd))
    app.add_handler(CallbackQueryHandler(menu_callback))
    app.add_handler(MessageHandler(filters.Document.ALL, document_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    app.add_error_handler(error_handler)
    log.info("%s Python payload analyzer is running", BRAND)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
