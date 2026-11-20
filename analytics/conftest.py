import os
from pathlib import Path
import subprocess

import pytest

from analytics.engine import ROOT


@pytest.fixture(scope="session")
def cli(tmp_path_factory):
    if binary := os.environ.get("SIGNALLEDGER_BIN"):
        return Path(binary).resolve()
    binary = tmp_path_factory.mktemp("bin") / "signalledger"
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/signalledger"], cwd=ROOT, check=True)
    return binary
