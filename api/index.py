import sys
import os

# Add parent folder to path so we can import main.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app
