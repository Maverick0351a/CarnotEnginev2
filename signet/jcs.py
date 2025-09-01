# RFC 8785 (JCS) canonicalization in pure Python
# Byte-for-byte stable output for common JSON types (objects with string keys,
# arrays, strings, booleans, null, and numbers). Numbers are rendered in a
# canonical minimal form per RFC 8785 guidance.

from decimal import Decimal, getcontext, InvalidOperation
import json
from math import isfinite
from typing import Any

# Set high precision to avoid rounding artifacts for typical inputs.
getcontext().prec = 100


def _format_decimal(d: Decimal) -> str:
    # Zero
    if d.is_zero():
        return "0"

    sign = '-' if d.is_signed() else ''
    d = d.copy_abs().normalize()  # remove trailing zeros

    t = d.as_tuple()
    digits = ''.join(str(x) for x in t.digits)
    if not digits:
        return "0"

    exp = t.exponent  # power of 10
    k = len(digits) + exp  # decimal point index relative to left of digits

    # Scientific notation if k <= -6 or k > 21 (per RFC 8785 guidance)
    if k <= -6 or k > 21:
        int_digit = digits[0]
        frac_digits = digits[1:].rstrip('0')
        mant = int_digit
        if frac_digits:
            mant += '.' + frac_digits
        exp_val = k - 1
        return f"{sign}{mant}e{exp_val}"

    # Plain decimal
    if exp >= 0:
        # append zeros
        return f"{sign}{digits}{'0'*exp}"

    # exp < 0 -> insert decimal point
    point = k
    if point > 0:
        left = digits[:point]
        right = digits[point:]
        return f"{sign}{left}.{right}"
    else:
        # leading zeros after decimal point
        return f"{sign}0.{'0'*(-point)}{digits}"


def _dump_string(s: str) -> str:
    # Ensure UTF-8 compatible JSON string with minimal escaping.
    return json.dumps(s, ensure_ascii=False, separators=(',', ':'))


def _serialize(o: Any) -> str:
    if o is None:
        return 'null'
    if o is True:
        return 'true'
    if o is False:
        return 'false'

    if isinstance(o, int):
        return str(o)
    if isinstance(o, float):
        # RFC 8785 disallows NaN / Infinity; they are not valid JSON numbers.
        if not isfinite(o):
            raise ValueError("Non-finite numbers are not permitted in JCS canonicalization")
        # Convert via Decimal using Python's shortest round-trip repr to avoid
        # binary floating artifacts then format per RFC rules.
        try:
            return _format_decimal(Decimal(str(o)))
        except (InvalidOperation, ValueError) as e:
            raise ValueError("Invalid float for JCS canonicalization") from e
    if isinstance(o, Decimal):
        return _format_decimal(o)
    if isinstance(o, str):
        return _dump_string(o)

    if isinstance(o, list):
        return '[' + ','.join(_serialize(v) for v in o) + ']'

    if isinstance(o, dict):
        # Keys must be strings; order by Unicode code point
        for k in o.keys():
            if not isinstance(k, str):
                raise TypeError('JCS requires object keys to be strings')
        items = []
        for k in sorted(o.keys()):
            items.append(_dump_string(k) + ':' + _serialize(o[k]))
        return '{' + ','.join(items) + '}'

    # Fallback: json round-trip to get JSON-compatible structure
    return _serialize(json.loads(json.dumps(o)))


def canonicalize(obj: Any) -> bytes:
    """Return canonical RFC 8785 representation as UTF-8 bytes."""
    s = _serialize(obj)
    return s.encode('utf-8')
