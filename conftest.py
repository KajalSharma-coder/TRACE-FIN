import os
import sys

# Ensure root directory is always on sys.path for pytest
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
