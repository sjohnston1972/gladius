"""Make gladius-snmp/app.py importable from the tests directory."""
import os
import sys
import tempfile

# app.py derives its data paths from DEVICES_FILE at import time; point them at
# a throwaway directory so importing the module never touches /data.
os.environ.setdefault("DEVICES_FILE", os.path.join(tempfile.mkdtemp(prefix="snmp-test-"), "devices.json"))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
