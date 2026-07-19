import shlex
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

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
def check_python(c) -> None:
    """Run Python formatting, lint, tests, and 100% branch coverage."""


@task
def install_js(c) -> None:
    c.run("npm ci")


@task
def check_js(c) -> None:
    c.run("npm run test:unit")


@task
def install_browser(c, with_deps=False) -> None:
    dependency_flag = " --with-deps" if with_deps else ""
    c.run(f"node ./node_modules/playwright/cli.js install{dependency_flag} chromium")


@task
def browser_e2e(c) -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "tests.e2e_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8765",
        ]
    )
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("FastPasskey e2e server exited before becoming ready")
            try:
                with urlopen("http://127.0.0.1:8765/healthz", timeout=1) as response:
                    if response.status == 200:
                        break
            except URLError:
                time.sleep(0.1)
        else:
            raise RuntimeError("FastPasskey e2e server did not become ready")
        c.run("npm run test:e2e")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@task(pre=[check_python, check_js, browser_e2e])
def verify(c) -> None:
    """Run every Python, JavaScript, and real-browser test."""
