import subprocess
import time
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

TARGETS = Path(__file__).parent / "targets"


@pytest.fixture
def simple_flask():
    proc = subprocess.Popen(
        [sys.executable, str(TARGETS / "simple_flask" / "app.py")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    yield "http://127.0.0.1:5000"
    proc.terminate()
    proc.wait()
