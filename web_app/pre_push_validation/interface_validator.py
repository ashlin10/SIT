"""Interface conflict detection: compare hardware interface names referenced in
the source YAML against the interfaces actually present on the target device.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .config_types import collect_referenced_interface_names
from .models import InterfaceConflict


# Interface name prefixes we treat as *hardware* ports (subject to conflict).
_HW_PREFIXES = ("ethernet", "gigabitethernet", "tengigabitethernet",
                "fortygigabitethernet", "hundredgigabitethernet",
                "twentyfivegigabitethernet", "management", "mgmt")


def _is_hardware_port(name: str) -> bool:
    if not isinstance(name, str) or not name:
        return False
    low = name.lower()
    if low.startswith(_HW_PREFIXES):
        return True
    # e.g. "Ethernet1/1" already covered; allow generic "<word><num>/<num>"
    return bool(re.match(r"^[a-z]+[\d]+/[\d]+$", low))


def _target_hardware_names(target_interfaces: List[Dict[str, Any]]) -> List[str]:
    names: List[str] = []
    for it in target_interfaces or []:
        if not isinstance(it, dict):
            continue
        n = it.get("name")
        if isinstance(n, str) and n:
            names.append(n)
    return names


def _suggest(source_name: str, available: List[str]) -> str:
    """Pick a best-effort replacement target for a missing source interface."""
    if not available:
        return ""
    sl = source_name.lower()
    # Same alphabetic prefix preferred (e.g. Ethernet -> Ethernet).
    m = re.match(r"^([a-z]+)", sl)
    prefix = m.group(1) if m else ""
    same_prefix = [a for a in available if a.lower().startswith(prefix)] if prefix else []
    pool = same_prefix or available
    # Prefer the one with the closest trailing index.
    def _idx(n: str):
        nums = re.findall(r"\d+", n)
        return tuple(int(x) for x in nums) if nums else (9999,)
    src_idx = _idx(source_name)
    return sorted(pool, key=lambda a: (abs(sum(_idx(a)) - sum(src_idx)), a))[0]


def detect_interface_conflicts(config: Dict[str, Any],
                               target_interfaces: List[Dict[str, Any]]) -> List[InterfaceConflict]:
    """Return conflicts for every source hardware interface missing on target."""
    referenced = collect_referenced_interface_names(config)
    available = _target_hardware_names(target_interfaces)
    available_set = {a for a in available}
    # Candidate replacements are hardware ports present on the target.
    candidate_targets = sorted({a for a in available if _is_hardware_port(a)})

    conflicts: List[InterfaceConflict] = []
    for name, paths in referenced.items():
        # Only flag hardware ports; logical names / port-channels created by the
        # push itself are not device-dependent.
        if not _is_hardware_port(name):
            continue
        if name in available_set:
            continue
        conflicts.append(InterfaceConflict(
            source_name=name,
            referenced_in=paths,
            available_targets=candidate_targets,
            suggested_target=_suggest(name, candidate_targets),
        ))
    conflicts.sort(key=lambda c: c.source_name)
    return conflicts
