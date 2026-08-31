from importlib.metadata import version

import blc_reverselab


def test_runtime_version_matches_package_metadata():
    assert blc_reverselab.__version__ == version("blc-reverselab")
