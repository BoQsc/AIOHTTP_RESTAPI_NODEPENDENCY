# simple/tools/impor.py
import sys, os
from pathlib import Path

# find project root where api.py lives
this_file = Path(__file__).resolve()
project_root = next(
    (p for p in [this_file] + list(this_file.parents) if (p / 'api.py').is_file()),
    None
)
if not project_root:
    raise RuntimeError("Cannot find api.py")

# make imports work, and chdir for cert.pem
sys.path.insert(0, str(project_root))
os.chdir(project_root)

# now we can import the fixer
try:
    from simple.tools.windows_fix import suppress_connection_errors
    suppress_connection_errors()
except ImportError:
    pass

# finally import the api
import api

def call_greet():
    print("impor.py calling:", api.greet())

if __name__ == "__main__":
    call_greet()
