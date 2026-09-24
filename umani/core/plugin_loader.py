import importlib
import pkgutil
from pathlib import Path
from ..modules.base import Module


def discover_modules() -> dict[str, type[Module]]:
    modules = {}
    pkg = importlib.import_module("umani.modules")
    pkg_path = Path(pkg.__file__).parent

    for _, name, _ in pkgutil.iter_modules([str(pkg_path)]):
        if name in ("base", "__init__"):
            continue
        mod = importlib.import_module(f"umani.modules.{name}")
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if (isinstance(obj, type)
                    and issubclass(obj, Module)
                    and obj is not Module
                    and obj.__module__ == mod.__name__):
                modules[obj.name] = obj
    return modules


def discover_passive_modules() -> dict[str, type[Module]]:
    """Return only modules marked as passive (no injection, no extra requests)."""
    return {name: cls for name, cls in discover_modules().items()
            if getattr(cls, "module_type", "active") == "passive"}
