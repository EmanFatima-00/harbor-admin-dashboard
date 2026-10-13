import sys
import os

# Add root folder to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Make sure /tmp exists for SQLite on Vercel
os.makedirs("/tmp", exist_ok=True)

from main import app
