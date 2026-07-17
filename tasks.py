import shlex
import sys

from invoke import task


PYTHON = shlex.quote(sys.executable)


@task
def format(c) -> None:
    c.run(f"{PYTHON} -m black src tests tasks.py")


@task
def lint(c) -> None:
    c.run(f"{PYTHON} -m black --check src tests tasks.py")
    c.run(f"{PYTHON} -m flake8 src tests tasks.py")


@task
def test(c) -> None:
    c.run(f"{PYTHON} -m pytest")


@task(pre=[lint, test])
def verify(c) -> None:
    """Run formatting, lint, tests, and 100% branch coverage."""
