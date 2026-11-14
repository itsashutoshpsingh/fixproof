"""Package version comparison for dpkg, rpm and apk.

Each function returns -1, 0 or 1, like the package manager's own comparison.
Written from the published algorithms (Debian Policy 5.6.12, rpmvercmp,
apk-tools version.c) so the truth logic does not depend on any scanner.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------- dpkg

def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _dpkg_split(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e)
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def dpkg_cmp(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


# ---------------------------------------------------------------- rpm

def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] not in "~^":
            j += 1
        # tilde sorts before everything, caret after the end but before anything else
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if not (i < len(a) and a[i] == "~"):
                return 1
            if not (j < len(b) and b[j] == "~"):
                return -1
            i += 1
            j += 1
            continue
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (i < len(a) and j < len(b)):
            break
        if a[i].isdigit():
            m = re.match(r"\d+", a[i:]).group()
            n = re.match(r"\d+", b[j:])
            if not n:
                return 1  # numeric segment is newer than alpha
            n = n.group()
            i += len(m)
            j += len(n)
            x, y = m.lstrip("0"), n.lstrip("0")
            if len(x) != len(y):
                return -1 if len(x) < len(y) else 1
            if x != y:
                return -1 if x < y else 1
        else:
            m = re.match(r"[A-Za-z]+", a[i:]).group()
            n = re.match(r"[A-Za-z]+", b[j:])
            if not n:
                return -1
            n = n.group()
            i += len(m)
            j += len(n)
            if m != n:
                return -1 if m < n else 1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _rpm_split(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e or 0)
    ver, _, rel = v.partition("-")
    return epoch, ver, rel


def rpm_cmp(a: str, b: str) -> int:
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _rpmvercmp(va, vb) or (_rpmvercmp(ra, rb) if ra and rb else 0)


# ---------------------------------------------------------------- apk

_APK_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "": 0, "cvs": 1, "svn": 2, "git": 3,
               "hg": 4, "p": 5}


def _apk_tokens(v: str) -> tuple[list, int]:
    rev = 0
    m = re.search(r"-r(\d+)$", v)
    if m:
        rev = int(m.group(1))
        v = v[: m.start()]
    main, *suffixes = v.split("_")
    m = re.match(r"^([0-9.]+)([a-z]?)$", main)
    if not m:
        raise ValueError(f"not an apk version: {v}")
    nums = [int(x) for x in m.group(1).split(".")]
    tokens: list = [("n", x) for x in nums]
    tokens.append(("l", m.group(2)))
    for s in suffixes:
        sm = re.match(r"^([a-z]+)(\d*)$", s)
        tokens.append(("s", _APK_SUFFIX.get(sm.group(1), 0), int(sm.group(2) or 0)))
    return tokens, rev


def apk_cmp(a: str, b: str) -> int:
    ta, ra = _apk_tokens(a)
    tb, rb = _apk_tokens(b)
    na = [t[1] for t in ta if t[0] == "n"]
    nb = [t[1] for t in tb if t[0] == "n"]
    for x, y in zip(na, nb, strict=False):
        if x != y:
            return -1 if x < y else 1
    if len(na) != len(nb):
        return -1 if len(na) < len(nb) else 1
    la = next(t[1] for t in ta if t[0] == "l")
    lb = next(t[1] for t in tb if t[0] == "l")
    if la != lb:
        return -1 if la < lb else 1
    sa = [t[1:] for t in ta if t[0] == "s"] or [(0, 0)]
    sb = [t[1:] for t in tb if t[0] == "s"] or [(0, 0)]
    for x, y in zip(sa, sb, strict=False):
        if x != y:
            return -1 if x < y else 1
    if len(sa) != len(sb):
        longer, sign = (sa, 1) if len(sa) > len(sb) else (sb, -1)
        extra = longer[min(len(sa), len(sb))]
        return sign if extra[0] > 0 else -sign
    if ra != rb:
        return -1 if ra < rb else 1
    return 0


CMP = {"dpkg": dpkg_cmp, "rpm": rpm_cmp, "apk": apk_cmp}


def compare(kind: str, a: str, b: str) -> int:
    return CMP[kind](a, b)
