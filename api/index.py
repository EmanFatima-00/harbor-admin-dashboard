import sys
import os
import re

# Add root folder to Python path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

# === AUTO-FIX for Vercel: Force SQLite to use /tmp ===
# Read main.py and patch it on the fly
main_path = os.path.join(ROOT_DIR, "main.py")

with open(main_path, "r", encoding="utf-8") as f:
    code = f.read()

# Replace all sqlite paths to /tmp (which is only writable folder on Vercel)
code = code.replace("sqlite:///./harbor.db", "sqlite:////tmp/harbor.db")
code = code.replace("sqlite:///./", "sqlite:////tmp/")
code = code.replace('sqlite:///./', 'sqlite:////tmp/')
code = code.replace("./harbor.db", "/tmp/harbor.db")
code = re.sub(r"sqlite:///[^\s\"']*harbor\.db", "sqlite:////tmp/harbor.db", code)

# Create a new module from patched code
import types
patched_module = types.ModuleType("main_patched")
# Make /tmp folder
os.makedirs("/tmp", exist_ok=True)

# Execute patched code
exec(code, patched_module.__dict__)

# Get the FastAPI app from patched module
app = patched_module.app
