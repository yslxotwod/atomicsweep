"""The class registry.

One import surface for the TUI, so adding a class is a one-line change and no
screen has to know about a tier module.
"""

from __future__ import annotations

from classes.tier_a import ConsoleServers, OltMgmt, NetconfYang, RouterFamilies
from classes.tier_b import (
    AcsProduct,
    ConnReqMap,
    WispControllers,
    CpeWebUi,
    MassResolve,
)
from classes.tier_c import DevicePki
from classes.tier_d import CLASSES as TIER_D
from classes.tier_e import CLASSES as TIER_E
from classes.tier_f import CLASSES as TIER_F
from classes.tier_g import CLASSES as TIER_G

SWEEP_CLASSES = [
    ConsoleServers(),
    OltMgmt(),
    NetconfYang(),
    RouterFamilies(),
    AcsProduct(),
    ConnReqMap(),
    WispControllers(),
    CpeWebUi(),
    DevicePki(),
]
SWEEP_CLASSES += TIER_D + TIER_E + TIER_F + TIER_G

MASS_RESOLVE = MassResolve

def by_id(class_id: str):
    for k in SWEEP_CLASSES:
        if k.id == class_id:
            return k
    return None

def tiers():
    """[(tier, [classes])] in Tier A, B, C order."""
    out: list[tuple[str, list]] = []
    for k in SWEEP_CLASSES:
        for entry in out:
            if entry[0] == k.tier:
                entry[1].append(k)
                break
        else:
            out.append((k.tier, [k]))
    return out

def gate_report():
    """[(class, ok_or_None, rows)] — None means the class has no control at all.

    A class with no control cannot be trusted to report a negative, so the UI
    shows it as ungated rather than green.
    """
    from core import engine

    report = []
    for k in SWEEP_CLASSES:
        if not k.CONTROLS:
            report.append((k, None, []))
            continue
        ok, rows = engine.gate(k)
        report.append((k, ok, rows))
    return report
