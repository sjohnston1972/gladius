import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import storage  # noqa: E402


@pytest.fixture
def data_dir(tmp_path):
    """Point gladius-ping storage at an empty temp data dir for one test."""
    storage.set_data_dir(tmp_path)
    storage.init_storage()
    yield tmp_path
    storage.set_data_dir("data")
