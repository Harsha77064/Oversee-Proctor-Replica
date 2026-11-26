"""Small helpers that reproduce JavaScript semantics the API contract depends on.

The browser sends JSON and expects the same validation behaviour, rounding and
timestamp format the server has always had, so these are deliberately exact.
"""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Any


class _Undefined:
    """A JSON field that was not sent at all (JavaScript `undefined`), as opposed to `null`."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "undefined"

    def __bool__(self) -> bool:
        return False


UNDEFINED: Any = _Undefined()


def get(body: Any, key: str) -> Any:
    """`body[key]`, or UNDEFINED when the key is missing (or the body is not an object)."""
    return body.get(key, UNDEFINED) if isinstance(body, dict) else UNDEFINED


def truthy(v: Any) -> bool:
    """JavaScript truthiness: [] and {} are true; 0, '', NaN, null and undefined are false."""
    if v is None or v is UNDEFINED or v is False:
        return False
    if isinstance(v, (int, float)):
        return not (v == 0 or (isinstance(v, float) and math.isnan(v)))
    if isinstance(v, str):
        return v != ""
    return True


def js_string(v: Any) -> str:
    """`String(v)`."""
    if v is None:
        return "null"
    if v is UNDEFINED:
        return "undefined"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "Infinity" if v > 0 else "-Infinity"
        if v.is_integer() and abs(v) < 1e21:
            return str(int(v))
        return repr(v)
    if isinstance(v, list):
        return ",".join("" if x is None else js_string(x) for x in v)
    if isinstance(v, dict):
        return "[object Object]"
    return str(v)


_NUM = re.compile(r"^[+-]?(\d+\.?\d*(e[+-]?\d+)?|\.\d+(e[+-]?\d+)?)$", re.I)


def js_number(v: Any) -> float:
    """`Number(v)`. Returns a float (NaN when not a number)."""
    if v is UNDEFINED:
        return math.nan
    if v is None or v is False:
        return 0.0
    if v is True:
        return 1.0
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, list):
        if not v:
            return 0.0
        return js_number(js_string(v[0])) if len(v) == 1 else math.nan
    if isinstance(v, dict):
        return math.nan
    s = str(v).strip()
    if s == "":
        return 0.0
    low = s.lower()
    if low in ("infinity", "+infinity"):
        return math.inf
    if low == "-infinity":
        return -math.inf
    for prefix, base in (("0x", 16), ("0o", 8), ("0b", 2)):
        if low.startswith(prefix):
            try:
                return float(int(s[2:], base))
            except ValueError:
                return math.nan
    return float(s) if _NUM.match(s) else math.nan


def is_integer(n: float) -> bool:
    """`Number.isInteger(n)`."""
    return isinstance(n, (int, float)) and math.isfinite(n) and float(n).is_integer()


def js_round(x: float) -> int:
    """`Math.round(x)`: halves round up (towards +infinity), unlike Python's round()."""
    return math.floor(x + 0.5)


def js_length(s: str) -> int:
    """`s.length` (UTF-16 code units)."""
    return len(s.encode("utf-16-le")) // 2


def now_ms() -> int:
    """`Date.now()`."""
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def iso(dt: datetime) -> str:
    """`date.toISOString()`: UTC, millisecond precision, trailing Z."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.astimezone(timezone.utc).microsecond // 1000:03d}Z"


def iso_from_ms(ms: float) -> str:
    return iso(datetime.fromtimestamp(ms / 1000, tz=timezone.utc))


def now_iso() -> str:
    """`new Date().toISOString()`."""
    return iso(datetime.now(timezone.utc))


def parse_date(v: Any) -> datetime | None:
    """`new Date(v)` for the inputs the app sends (ISO strings, millisecond timestamps).

    Date-only strings are UTC and date-times without a zone are local time, as in JavaScript.
    Returns None for invalid input.
    """
    if v is None or v is UNDEFINED or v is False or v is True:
        return None
    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(v / 1000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(v).strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        if re.fullmatch(r"\d{4}-\d{2}(-\d{2})?", s):
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone()  # local time, like JavaScript
    return dt


def date_ms(v: str) -> float:
    """`new Date(isoString).getTime()` for timestamps the server stored."""
    d = parse_date(v)
    return d.timestamp() * 1000 if d else math.nan


def dumps(value: Any) -> str:
    """`JSON.stringify(value)`."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def loads(s: Any, fallback: Any = None) -> Any:
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return fallback
