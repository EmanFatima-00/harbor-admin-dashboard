import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.makedirs("/tmp", exist_ok=True)

import sqlalchemy
old = sqlalchemy.create_engine
def new(url, *a, **k):
    if "sqlite" in str(url):
        url = "sqlite:////tmp/harbor.db"
        k["connect_args"] = {"check_same_thread": False}
    return old(url, *a, **k)
sqlalchemy.create_engine = new

from main import app
