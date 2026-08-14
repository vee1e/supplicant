"""Recursive dependency-tree resolution with cycle detection.

Pragmatic semver resolution (no external lib): proper numeric ordering with
prerelease handling, plus ^ / ~ / wildcard / comparator range matching.
"""

from __future__ import annotations

import re

from ..context import ScanContext
from ..models import Artifact

_RE_BUILD = re.compile(r"\+[0-9A-Za-z.-]+$")
_RE_PRE = re.compile(r"[.\-]+")


def _version_tuple(v: str):
    """Comparable tuple: (major, minor, patch, prerelease_rank, ...).

    A release sorts ABOVE any of its prereleases (1.2.3 > 1.2.3-rc.1);
    +build metadata is ignored for ordering.
    """
    v = _RE_BUILD.sub("", str(v))
    core, sep, pre = v.partition("-")
    nums = []
    for part in core.split("."):
        if part.isdigit():
            nums.append((0, int(part)))
        else:
            nums.append((1, part))
    while len(nums) < 3:
        nums.append((0, 0))
    if not sep:
        rank = (2,)  # no prerelease: sorts above every prerelease
    else:
        rank = (1,) + tuple(
            (0, int(x)) if x.isdigit() else (1, x) for x in _RE_PRE.split(pre) if x
        )
    return tuple(nums) + (rank,)


def _parse_core(ver: str) -> tuple | None:
    """Version tuple for a spec like '1.2.3' or '1.2' (missing parts = 0).

    Accepts an optional leading 'v'. Clamps to major.minor.patch (drops any
    4th+ numeric segment) and preserves a prerelease rank.
    """
    ver = _RE_BUILD.sub("", str(ver).strip()).lstrip("v")
    core, _, pre = ver.partition("-")
    nums = []
    for part in core.split(".")[:3]:
        if part.isdigit():
            nums.append((0, int(part)))
        else:
            return None
    while len(nums) < 3:
        nums.append((0, 0))
    if pre:
        rank = (1,) + tuple((0, int(x)) if x.isdigit() else (1, x) for x in _RE_PRE.split(pre) if x)
    else:
        rank = (2,)
    return tuple(nums) + (rank,)


def _ver(major: int, minor: int = 0, patch: int = 0) -> tuple:
    """A bare release version tuple (no prerelease)."""
    return ((0, major), (0, minor), (0, patch), (2,))


def _spec_components(ver: str) -> tuple:
    """(major, minor, patch, count_of_numeric_components) for a spec string,
    treating wildcard components (x/X/*) as missing."""
    nums = [int(p) for p in ver.split(".") if p.isdigit()]
    major = nums[0] if len(nums) > 0 else 0
    minor = nums[1] if len(nums) > 1 else 0
    patch = nums[2] if len(nums) > 2 else 0
    return major, minor, patch, len(nums)


def _is_wildcard(ver: str) -> bool:
    parts = ver.lower().split(".")
    return any(p in ("*", "x") for p in parts)


def _caret_bounds(ver: str):
    """^1.2.3 -> >=1.2.3 <2.0.0 ; ^0.2.3 -> <0.3.0 ; ^0.0.3 -> <0.0.4 ;
    ^0.0 -> <0.1.0 ; ^0 -> <1.0.0 ; ^1.x -> >=1.0.0 <2.0.0."""
    major, minor, patch, n = _spec_components(ver)
    floor = _ver(major, minor, patch)
    if major > 0:
        ceil = _ver(major + 1)
    elif minor > 0:
        ceil = _ver(0, minor + 1)
    elif patch > 0:
        ceil = _ver(0, 0, patch + 1)
    elif n >= 3:  # ^0.0.0
        ceil = _ver(0, 0, patch + 1)
    elif n == 2:  # ^0.0
        ceil = _ver(0, 1)
    else:  # ^0 / ^0.x
        ceil = _ver(1)
    return floor, ceil


def _tilde_bounds(ver: str):
    """~1.2.3 -> <1.3.0 ; ~1.2 -> <1.3.0 ; ~1 -> <2.0.0 ; ~0 -> <1.0.0."""
    major, minor, _, n = _spec_components(ver)
    floor = _ver(major, minor)
    if n >= 2:
        ceil = _ver(major, minor + 1)
    else:
        ceil = _ver(major + 1)
    return floor, ceil


def _range_constraints(spec: str) -> list[list[tuple]]:
    """Parse a range spec into alternatives of (op, version_tuple) constraints.

    Supports ^, ~, comparators (>=, >, <=, <, =), exact, partials (1 / 1.2),
    wildcards (1.x/*), space-AND ('>=1.0.0 <2.0.0'), hyphen ranges and
    || (OR). Returns [[]] for 'any'.
    """
    spec = spec.strip()
    # Normalize ">= 1.2.3" / "^ 1.2.3" (space after operator) so the operator
    # and version stay one token. Does not touch "1.2.3 - 2.0.0" ('-' not a
    # range operator here).
    spec = re.sub(r"([~^<>=]+)\s+", r"\1", spec)
    if not spec or spec in ("*", "latest", "x", "^", "~"):
        return [[("any", None)]]

    alternatives: list[list[tuple]] = []
    for alt in spec.split("||"):
        alt = alt.strip()
        if not alt:
            continue
        constraints: list[tuple] = []
        hyphen_handled = False
        if " - " in alt:
            lo, hi = alt.split(" - ", 1)
            # A hyphen range needs plain versions on both sides; otherwise
            # treat it as ordinary tokens (e.g. "1.2.3 - 2.0.0" vs "^1.2.3 - 2.0.0").
            if not re.search(r"[~^<>=xX*]", lo + hi):
                lo_t, hi_t = _parse_core(lo), _parse_core(hi)
                if lo_t is not None and hi_t is not None:
                    constraints.append((">=", lo_t))
                    if re.fullmatch(r"\d+", hi.strip()):
                        # "1.2.3 - 2" -> <3.0.0 (partial upper bound)
                        constraints.append(("<", _ver(hi_t[0][1] + 1)))
                    elif re.fullmatch(r"\d+\.\d+", hi.strip()):
                        # "1.2.3 - 2.1" -> <2.2.0
                        constraints.append(("<", _ver(hi_t[0][1], hi_t[1][1] + 1)))
                    else:
                        constraints.append(("<=", hi_t))
                    hyphen_handled = True
        if not hyphen_handled:
            for tok in alt.split():
                tok = tok.strip()
                if not tok:
                    continue
                m = re.match(r"^([~^<>=]*)(.*)$", tok)
                op, ver = (m.group(1) or "="), m.group(2)
                if op == "^" and _is_wildcard(ver):
                    floor, ceil = _caret_bounds(ver)
                    constraints.append((">=", floor))
                    constraints.append(("<", ceil))
                elif op == "^":
                    base = _parse_core(ver)
                    if base is None:
                        continue
                    floor, ceil = _caret_bounds(ver)
                    constraints.append((">=", base))
                    constraints.append(("<", ceil))
                elif op == "~" and _is_wildcard(ver):
                    floor, ceil = _tilde_bounds(ver)
                    constraints.append((">=", floor))
                    constraints.append(("<", ceil))
                elif op == "~":
                    base = _parse_core(ver)
                    if base is None:
                        continue
                    floor, ceil = _tilde_bounds(ver)
                    constraints.append((">=", base))
                    constraints.append(("<", ceil))
                elif op in (">=", ">", "<=", "<"):
                    parsed = _parse_core(ver)
                    if parsed is not None:
                        constraints.append((op, parsed))
                elif _is_wildcard(ver):
                    major, minor, _, n = _spec_components(ver)
                    floor = _ver(major, minor)
                    constraints.append((">=", floor))
                    if n >= 2:
                        constraints.append(("<", _ver(major, minor + 1)))
                    elif n == 1:
                        constraints.append(("<", _ver(major + 1)))
                else:
                    # exact or partial
                    if re.fullmatch(r"\d+(\.\d+)?", ver.lstrip("v")):
                        nums = [int(p) for p in ver.lstrip("v").split(".")]
                        major, minor = nums[0], (nums[1] if len(nums) > 1 else 0)
                        constraints.append((">=", _ver(major, minor)))
                        if len(nums) == 1:
                            constraints.append(("<", _ver(major + 1)))
                        else:
                            constraints.append(("<", _ver(major, minor + 1)))
                    else:
                        low = _parse_core(ver)
                        if low is not None:
                            constraints.append(("=", low))
                        else:
                            # Unrecognizable token (bad tag, typo): make the
                            # whole alternative unsatisfiable rather than
                            # silently matching everything.
                            constraints.append(("none", None))
        if constraints:
            alternatives.append(constraints)
    return alternatives if alternatives else [[("any", None)]]


def _satisfies(vt, constraints: list[tuple]) -> bool:
    for op, target in constraints:
        if op == "any":
            continue
        if op == "none":
            return False
        if op == "=":
            if vt[:3] != target[:3] or vt[3] != target[3]:
                return False
        elif op == ">=":
            if vt < target:
                return False
        elif op == ">":
            if vt <= target:
                return False
        elif op == "<=":
            if vt > target:
                return False
        elif op == "<":
            if vt >= target:
                return False
    return True


def _best_match(versions: list[str], spec: str) -> str | None:
    """Highest version satisfying the range.

    npm rule: a prerelease version satisfies a range only when the range's
    prerelease comparator shares the same [major, minor, patch] core.
    """
    alternatives = _range_constraints(spec)
    pre_cores = {
        target[:3]
        for alt in alternatives
        for _, target in alt
        if target is not None and target[3][0] == 1
    }
    candidates = []
    for v in versions:
        vt = _version_tuple(v)
        if vt[3][0] == 1 and vt[:3] not in pre_cores:
            continue
        for constraints in alternatives:
            if _satisfies(vt, constraints):
                candidates.append((vt, v))
                break
    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0])
    return candidates[-1][1]


def _resolve_npm_version(ctx: ScanContext, name: str, dep_range) -> str | None:
    try:
        meta = ctx.registry("npm").metadata(name)
        versions = sorted(meta.get("versions", {}).keys())
        dist_tags = meta.get("dist-tags", {})
    except Exception:
        return None
    if not versions:
        return None
    raw = str(dep_range).strip().lstrip("v")
    if re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.\-]+)?", raw):
        return raw if raw in versions else None  # exact pin: no fallback guess
    # dist-tag (e.g. "next", "beta"): resolve to the tag's actual version.
    if raw in dist_tags and dist_tags[raw] in versions:
        return dist_tags[raw]
    return _best_match(versions, raw)


# ---- resolution entry point -------------------------------------------------
def resolve_tree(
    ctx: ScanContext,
    root: Artifact,
    max_depth: int = 10,
    seen: set[str] | None = None,
    depth: int = 0,
) -> list[Artifact]:
    """Collect [root] + recursively-resolved descendants (deduped by key)."""
    if seen is None:
        seen = set()
    key = root.key
    if key in seen:
        return []
    seen.add(key)
    if depth > max_depth:
        return []

    out: list[Artifact] = [root]
    try:
        if root.ecosystem == "npm":
            out.extend(_npm_children(ctx, root, max_depth, seen, depth))
        elif root.ecosystem == "pypi":
            out.extend(_pypi_children(ctx, root))
    except Exception:
        pass
    return out


# ---- npm -------------------------------------------------------------------
def _npm_children(ctx: ScanContext, root: Artifact, max_depth: int, seen: set[str], depth: int) -> list[Artifact]:
    try:
        reg = ctx.registry("npm")
        meta = reg.metadata(root.name)
        version = root.version
        if version is None:
            version = meta.get("dist-tags", {}).get("latest")
        v = meta.get("versions", {}).get(version) if version else None
        deps = (v or {}).get("dependencies") or {}
    except Exception:
        return []

    out: list[Artifact] = []
    for dep_name, dep_range in deps.items():
        child_ver = _resolve_npm_version(ctx, dep_name, dep_range)
        if child_ver is None:
            continue  # unresolvable -> skip, do not raise
        child = Artifact("npm", dep_name, child_ver)
        out.extend(resolve_tree(ctx, child, max_depth, seen, depth + 1))
    return out


# ---- pypi --------------------------------------------------------------------
def _pypi_children(ctx: ScanContext, root: Artifact) -> list[Artifact]:
    try:
        reg = ctx.registry("pypi")
        meta = reg.metadata(root.name)
        requires = meta.get("info", {}).get("requires_dist") or []
    except Exception:
        return []

    out: list[Artifact] = []
    for entry in requires:
        name = re.split(r"\s*[\(\[<>=!~;]", str(entry), 1)[0].strip()
        if not name:
            continue
        out.append(Artifact("pypi", name, "latest"))  # leaves: no recursion
    return out
