"""
ElderShield application health checks.

These checks are intentionally local and lightweight.
They do not contact external services and never expose secrets.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent


CORE_MODULES = (
    "modules.app_security",
    "modules.case_engine",
    "modules.evidence",
    "modules.intervention",
    "modules.knowledge",
    "modules.report",
    "modules.safe_url",
    "modules.text_rules",
    "modules.url_analyzer",
)


DATA_FILES = (
    "data/official_domains.json",
    "data/india_scam_knowledge.json",
    "data/ui_languages.json",
    "data/emergency_guidance.json",
    "data/scam_patterns.json",
)


def check_core_modules() -> dict[str, Any]:
    """
    Verify that core ElderShield modules can be imported.

    Returns a structured result and never raises an import error.
    """

    failed: list[str] = []

    for module_name in CORE_MODULES:
        try:
            importlib.import_module(module_name)
        except Exception:
            failed.append(module_name)

    return {
        "ok": not failed,
        "checked": len(CORE_MODULES),
        "failed": failed,
    }


def check_data_files() -> dict[str, Any]:
    """
    Verify that required local JSON data files exist.

    This function does not read or expose their contents.
    """

    missing = []

    for relative_path in DATA_FILES:
        path = PROJECT_ROOT / relative_path

        if not path.is_file():
            missing.append(relative_path)

    return {
        "ok": not missing,
        "checked": len(DATA_FILES),
        "missing": missing,
    }


def check_project_structure() -> dict[str, Any]:
    """
    Verify the most important ElderShield directories exist.
    """

    required_directories = (
        "modules",
        "data",
        "tests",
    )

    missing = []

    for directory in required_directories:
        path = PROJECT_ROOT / directory

        if not path.is_dir():
            missing.append(directory)

    return {
        "ok": not missing,
        "checked": len(required_directories),
        "missing": missing,
    }


def run_health_check() -> dict[str, Any]:
    """
    Run all local health checks.

    No network request is made.
    No Gemini API request is made.
    No user evidence is inspected.
    """

    modules = check_core_modules()
    data_files = check_data_files()
    structure = check_project_structure()

    checks = {
        "core_modules": modules,
        "data_files": data_files,
        "project_structure": structure,
    }

    overall_ok = all(
        result.get("ok", False)
        for result in checks.values()
    )

    return {
        "ok": overall_ok,
        "checks": checks,
    }


def health_summary() -> str:
    """
    Return a short human-readable health status.
    """

    result = run_health_check()

    if result["ok"]:
        return "ElderShield health check: OK"

    failed = []

    for name, check in result["checks"].items():
        if not check.get("ok", False):
            failed.append(name)

    return (
        "ElderShield health check: FAILED — "
        + ", ".join(failed)
    )
