"""Deterministic YAML sanitizer.

Given the original config, a set of accepted fix directives (produced by the
validators) and user-supplied interface mappings, produce a sanitized copy of
the config plus a human-readable change list and a unified diff. The original
config is never mutated.
"""
from __future__ import annotations

import copy
import difflib
from typing import Any, Dict, List, Optional

import yaml

from .config_types import (
    HARDWARE_NAME_STRING_KEYS,
    HARDWARE_REF_LIST_KEYS,
    HARDWARE_REF_OBJECT_KEYS,
    INTERFACE_SECTIONS,
    SKIP_KEYS,
)


def sanitize(config: Dict[str, Any],
             fixes: List[Dict[str, Any]],
             interface_mappings: Dict[str, str],
             speed_changes: Dict[str, Any] = None,
             interface_removals: List[str] = None,
             member_changes: Dict[str, Dict[str, str]] = None,
             etherchannel_id_changes: Dict[str, int] = None) -> Dict[str, Any]:
    """Return {sanitized_config, changes, diff}.

    ``fixes`` is the list of accepted ``Issue.fix`` directives.
    ``interface_mappings`` maps an original hardware interface name to a target.
    ``speed_changes`` maps an interface name to a new ``hardware.speed`` value
        (an empty/None value removes the speed so the port auto-negotiates).
    ``interface_removals`` is a list of interface names to drop from the config
        entirely (including any port-channel member references).
    ``member_changes`` maps a parent interface name (e.g. ``Port-channel2``) to
        a dict of ``{old_member: new_member}`` for migrating membership config.
    ``etherchannel_id_changes`` maps an etherchannel name to a new numeric ID.

    Field-removal pointer fixes are applied first (while list indices are still
    valid), then name-based speed/rename/removal corrections.
    """
    original = copy.deepcopy(config)
    sanitized = copy.deepcopy(config)
    changes: List[str] = []

    # 1. Apply removal fixes first — these are pointer/section based and must run
    #    before any list-mutating interface removals shift indices.
    for fix in (fixes or []):
        if not isinstance(fix, dict):
            continue
        op = fix.get("op")
        if op == "remove_section":
            section = fix.get("section")
            if section in sanitized:
                n = len(sanitized.get(section) or [])
                sanitized.pop(section, None)
                changes.append(f"Removed section '{section}' ({n} item(s))")
        elif op == "remove_routing_key":
            key = fix.get("key")
            routing = sanitized.get("routing")
            if isinstance(routing, dict) and key in routing:
                n = len(routing.get(key) or [])
                routing.pop(key, None)
                changes.append(f"Removed routing.{key} ({n} item(s))")
        elif op == "remove_field_all":
            section = fix.get("section")
            field_path = fix.get("field_path") or []
            n = _remove_field_all(sanitized.get(section), field_path)
            if n:
                changes.append(f"Removed '{'.'.join(field_path)}' from {n} item(s) in {section}")
        elif op == "remove_field_path":
            pointer = fix.get("pointer") or []
            if _remove_by_pointer(sanitized, pointer):
                changes.append(f"Removed '{_ptr_str(pointer)}'")

    # 2. Apply interface speed corrections (by name; index-independent).
    for name, speed in (speed_changes or {}).items():
        if not name:
            continue
        count = _set_interface_speed(sanitized, name, speed)
        if count:
            if speed in (None, "", "AUTO"):
                changes.append(f"Cleared/auto speed on interface '{name}' ({count} item(s))")
            else:
                changes.append(f"Set interface '{name}' speed -> '{speed}' ({count} item(s))")

    # 3. Apply interface renames.
    clean_mappings = {k: v for k, v in (interface_mappings or {}).items() if k and v and k != v}
    for old, new in clean_mappings.items():
        count = _rename_interface(sanitized, old, new)
        if count:
            changes.append(f"Remapped interface '{old}' -> '{new}' ({count} reference(s))")

    # 4. Apply member changes (port-channel / BVI / inline-set member migration).
    for parent_name, mapping in (member_changes or {}).items():
        for old_member, new_member in mapping.items():
            if not old_member or not new_member or old_member == new_member:
                continue
            count = _apply_member_change(sanitized, parent_name, old_member, new_member)
            if count:
                changes.append(
                    f"Migrated member '{old_member}' -> '{new_member}' in '{parent_name}' "
                    f"({count} update(s))"
                )

    # 5. Apply EtherChannel ID changes.
    for ec_name, new_id in (etherchannel_id_changes or {}).items():
        if not ec_name or new_id is None:
            continue
        try:
            new_id_int = int(new_id)
        except (TypeError, ValueError):
            continue
        count = _set_etherchannel_id(sanitized, ec_name, new_id_int)
        if count:
            changes.append(f"Changed EtherChannel ID for '{ec_name}' -> {new_id_int} ({count} update(s))")

    # 6. Apply interface removals last (mutates lists / member references).
    for name in (interface_removals or []):
        if not name:
            continue
        count = _remove_interface(sanitized, name)
        if count:
            changes.append(f"Removed interface '{name}' from config ({count} item(s)/reference(s))")

    diff = _yaml_diff(original, sanitized)
    return {"sanitized_config": sanitized, "changes": changes, "diff": diff}


# ── Member change migration ──

# Fields on a physical interface that indicate membership in a parent aggregate.
_MEMBERSHIP_FIELDS = {"channelGroupId", "lacpMode"}


def _apply_member_change(config: Dict[str, Any], parent_name: str,
                         old_member: str, new_member: str) -> int:
    """Migrate membership from *old_member* to *new_member* inside *parent_name*.

    This performs three actions:
    1. Update ``selectedInterfaces`` (and similar ref lists) on the parent
       aggregate (etherchannel / BVI / inline-set) to reference new_member.
    2. Remove membership fields (``channelGroupId``, ``lacpMode``, …) from the
       old member's physical_interfaces entry.
    3. Copy those membership fields onto the new member's physical_interfaces
       entry (creating one if it doesn't exist).

    Returns the number of discrete updates made.
    """
    n = 0

    # -- 1. Patch selectedInterfaces on the parent --
    for section in INTERFACE_SECTIONS:
        items = config.get(section)
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            if (it.get("name") or "") != parent_name:
                continue
            for ref_key in HARDWARE_REF_LIST_KEYS:
                refs = it.get(ref_key)
                if not isinstance(refs, list):
                    continue
                for ref in refs:
                    if isinstance(ref, dict) and ref.get("name") == old_member:
                        ref["name"] = new_member
                        n += 1

    # -- 2 & 3. Migrate membership fields between physical_interfaces --
    phys: List[Dict[str, Any]] = config.get("physical_interfaces") or []
    if not isinstance(phys, list):
        phys = []

    old_entry: Optional[Dict[str, Any]] = None
    new_entry: Optional[Dict[str, Any]] = None
    for it in phys:
        if isinstance(it, dict):
            nm = it.get("name") or ""
            if nm == old_member:
                old_entry = it
            elif nm == new_member:
                new_entry = it

    # Collect membership fields from old entry.
    membership: Dict[str, Any] = {}
    if old_entry:
        for f in _MEMBERSHIP_FIELDS:
            if f in old_entry:
                membership[f] = old_entry.pop(f)
                n += 1

    # Apply membership fields to new entry.
    if membership:
        if new_entry is None:
            new_entry = {"type": "PhysicalInterface", "name": new_member}
            phys.append(new_entry)
            config["physical_interfaces"] = phys
            n += 1
        for f, v in membership.items():
            new_entry[f] = v
            n += 1

    # Rename any subinterfaces whose parent is old_member -> new_member.
    n += _rename_interface(config, old_member, new_member)

    return n


# ── EtherChannel ID correction ──

def _set_etherchannel_id(config: Dict[str, Any], ec_name: str, new_id: int) -> int:
    """Set the ``etherChannelId`` on an etherchannel + update ``channelGroupId``
    on member physical interfaces and rename the interface if ID changed.
    """
    n = 0
    ec_items = config.get("etherchannel_interfaces")
    if not isinstance(ec_items, list):
        return 0
    old_id = None
    for it in ec_items:
        if isinstance(it, dict) and it.get("name") == ec_name:
            old_id = it.get("etherChannelId")
            it["etherChannelId"] = new_id
            n += 1
            # Rename the interface itself: Port-channel<old> -> Port-channel<new>
            old_pc_name = ec_name
            new_pc_name = f"Port-channel{new_id}"
            if old_pc_name != new_pc_name:
                it["name"] = new_pc_name
                n += 1
            break

    # Update channelGroupId on member physical interfaces.
    if old_id is not None:
        phys = config.get("physical_interfaces")
        if isinstance(phys, list):
            for it in phys:
                if isinstance(it, dict) and it.get("channelGroupId") == old_id:
                    it["channelGroupId"] = new_id
                    n += 1

    # Rename subinterfaces that reference the old port-channel name.
    if old_id is not None and ec_name != f"Port-channel{new_id}":
        old_pc_name = ec_name
        new_pc_name = f"Port-channel{new_id}"
        n += _rename_interface(config, old_pc_name, new_pc_name)

    return n


# ── Interface speed correction ──

def _set_interface_speed(config: Dict[str, Any], name: str, speed: Any) -> int:
    """Set hardware.speed for interface items whose name matches ``name``.

    An empty/None/AUTO speed removes the explicit ``hardware.speed`` field.
    """
    n = 0
    for section in INTERFACE_SECTIONS:
        items = config.get(section)
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            if (it.get("name") or it.get("ifname")) != name:
                continue
            hw = it.get("hardware")
            if speed in (None, "", "AUTO"):
                if isinstance(hw, dict) and "speed" in hw:
                    hw.pop("speed", None)
                    n += 1
            else:
                if not isinstance(hw, dict):
                    hw = {}
                    it["hardware"] = hw
                hw["speed"] = speed
                n += 1
    return n


# ── Interface removal ──

def _remove_interface(config: Dict[str, Any], name: str) -> int:
    """Remove an interface (by name) from all interface sections and drop any
    port-channel member / hardware reference to it.
    """
    n = 0
    for section in INTERFACE_SECTIONS:
        items = config.get(section)
        if not isinstance(items, list):
            continue
        kept = []
        for it in items:
            if isinstance(it, dict):
                iname = it.get("name") or it.get("ifname") or ""
                # match exact interface, and subinterfaces of a removed parent
                if iname == name or (isinstance(iname, str) and iname.startswith(name + ".")):
                    n += 1
                    continue
            kept.append(it)
        config[section] = kept

    # Drop the interface from member-reference lists (e.g. selectedInterfaces).
    def walk(obj: Any) -> None:
        nonlocal n
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if k in HARDWARE_REF_LIST_KEYS and isinstance(v, list):
                    new_list = []
                    for it in v:
                        if isinstance(it, dict) and it.get("name") == name:
                            n += 1
                            continue
                        new_list.append(it)
                    obj[k] = new_list
                elif isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(obj, list):
            for it in obj:
                walk(it)

    for section in INTERFACE_SECTIONS:
        if isinstance(config.get(section), list):
            walk(config[section])
    return n


# ── Interface renaming ──

def _rename_interface(config: Dict[str, Any], old: str, new: str) -> int:
    """Replace every hardware-interface reference to ``old`` with ``new``.

    Scoped to interface sections + routing to avoid colliding with object names.
    Handles subinterface compound names like 'Ethernet1/1.100'.
    """
    counter = {"n": 0}

    def repl(value: str) -> str:
        if value == old:
            counter["n"] += 1
            return new
        # subinterface compound: <parent>.<suffix>
        if isinstance(value, str) and value.startswith(old + "."):
            counter["n"] += 1
            return new + value[len(old):]
        return value

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if k in SKIP_KEYS:
                    continue
                if k in ("name",) and isinstance(v, str):
                    obj[k] = repl(v)
                elif k in HARDWARE_NAME_STRING_KEYS and isinstance(v, str):
                    obj[k] = repl(v)
                elif k in HARDWARE_REF_OBJECT_KEYS and isinstance(v, dict):
                    if isinstance(v.get("name"), str):
                        v["name"] = repl(v["name"])
                elif k in HARDWARE_REF_LIST_KEYS and isinstance(v, list):
                    for it in v:
                        if isinstance(it, dict) and isinstance(it.get("name"), str):
                            it["name"] = repl(it["name"])
                elif isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(obj, list):
            for it in obj:
                walk(it)

    for section in INTERFACE_SECTIONS:
        if isinstance(config.get(section), list):
            walk(config[section])
    if isinstance(config.get("routing"), dict):
        walk(config["routing"])
    return counter["n"]


# ── Field removal helpers ──

def _remove_field_all(items: Any, field_path: List[str]) -> int:
    if not isinstance(items, list) or not field_path:
        return 0
    n = 0
    for it in items:
        if _remove_nested(it, field_path):
            n += 1
    return n


def _remove_nested(obj: Any, path: List[str]) -> bool:
    if not isinstance(obj, dict) or not path:
        return False
    if len(path) == 1:
        if path[0] in obj:
            obj.pop(path[0], None)
            return True
        return False
    child = obj.get(path[0])
    return _remove_nested(child, path[1:])


def _remove_by_pointer(root: Any, pointer: List[Any]) -> bool:
    """Remove the leaf addressed by an absolute pointer list (keys + indices)."""
    if not pointer:
        return False
    cur = root
    for p in pointer[:-1]:
        if isinstance(p, int):
            if isinstance(cur, list) and 0 <= p < len(cur):
                cur = cur[p]
            else:
                return False
        else:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return False
    leaf = pointer[-1]
    if isinstance(leaf, int):
        if isinstance(cur, list) and 0 <= leaf < len(cur):
            cur.pop(leaf)
            return True
    elif isinstance(cur, dict) and leaf in cur:
        cur.pop(leaf, None)
        return True
    return False


def _ptr_str(pointer: List[Any]) -> str:
    out = ""
    for p in pointer:
        if isinstance(p, int):
            out += f"[{p}]"
        else:
            out = f"{out}.{p}" if out else str(p)
    return out


def _yaml_diff(original: Dict[str, Any], sanitized: Dict[str, Any]) -> str:
    a = yaml.safe_dump(original, sort_keys=False).splitlines(keepends=True)
    b = yaml.safe_dump(sanitized, sort_keys=False).splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile="original.yaml", tofile="sanitized.yaml"))
