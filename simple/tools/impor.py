# simple/tools/impor.py
try:
    from tools.windows_fix import suppress_connection_errors
    suppress_connection_errors()  # Apply fix if available
except ImportError:
    pass  # Silently continue without the fix



import sys
import os
from pathlib import Path

# 1. Locate this file
this_file = Path(__file__).resolve()

# 2. Climb parents looking for api.py
project_root = None
for p in [this_file] + list(this_file.parents):
    if (p / 'api.py').is_file():
        project_root = p
        break

if project_root is None:
    raise RuntimeError("Cannot find api.py in any parent directory")

# 3. Ensure import sees api.py
sys.path.insert(0, str(project_root))

# 4. CD into that folder so cert.pem/key.pem are on the cwd
os.chdir(project_root)

# 5. Now import and run
import api

def call_greet():
    print("impor.py calling:", api.greet())

if __name__ == "__main__":
    call_greet()
