#!/usr/bin/env python3
"""Enforce RED APPLE coverage floors from coverage.py XML."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

FLOORS = {
    "foundry": 0.95,
}
OVERALL_FLOOR = 0.90


def main(path: str) -> int:
    """Check coverage.xml and return a process status."""
    root = ET.parse(path).getroot()
    total = float(root.attrib.get("line-rate", "0"))
    failures: list[str] = []
    if total < OVERALL_FLOOR:
        failures.append(f"overall line coverage {total:.2%} < {OVERALL_FLOOR:.0%}")
    for package, floor in FLOORS.items():
        rates = [
            float(cls.attrib.get("line-rate", "0"))
            for cls in root.iter("class")
            if f"/{package}/" in cls.attrib.get("filename", "")
            or cls.attrib.get("filename", "").endswith(f"/{package}.py")
        ]
        if not rates:
            continue
        rate = sum(rates) / len(rates)
        if rate < floor:
            failures.append(f"{package} line coverage {rate:.2%} < {floor:.0%}")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"coverage ok: overall {total:.2%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.xml"))
