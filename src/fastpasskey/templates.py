from __future__ import annotations

from jinja2 import ChoiceLoader, PackageLoader


def install_fastpasskey_templates(environment) -> None:
    """Add package templates after app templates so consumers can override them."""

    package_loader = PackageLoader("fastpasskey", "templates")
    if environment.loader is None:
        environment.loader = package_loader
    else:
        environment.loader = ChoiceLoader([environment.loader, package_loader])
