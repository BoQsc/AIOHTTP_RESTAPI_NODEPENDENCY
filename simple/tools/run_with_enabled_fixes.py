# simple/tools/impor.py

import sys
import os
from pathlib import Path

# 1️⃣ Locate this file
this_file = Path(__file__).resolve()

# 2️⃣ Climb parents until we find api.py
project_root = None
for p in [this_file] + list(this_file.parents):
    if (p / 'api.py').is_file():
        project_root = p
        break

if project_root is None:
    raise RuntimeError("Cannot find api.py in any parent directory")

# 3️⃣ Make both api.py and simple/tools visible on import path
sys.path.insert(0, str(project_root))

# 4️⃣ chdir so api.py’s relative loads (cert.pem/key.pem) still work
os.chdir(project_root)

# 5️⃣ Apply the Windows‐specific suppressor if it exists under simple/tools/windows_fix.py
try:
    # since project_root is now on sys.path, this will look for:
    #   <project_root>/simple/tools/windows_fix.py
    from windows_fix import suppress_connection_errors
    suppress_connection_errors()
except ImportError:
    # no windows_fix module? just move on
    pass

# 6️⃣ Finally import and run your API
import api

def call_greet():
    print("impor.py calling:", api.greet())

if __name__ == "__main__":
    call_greet()
