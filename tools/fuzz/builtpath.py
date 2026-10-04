"""Where cargo put the binary, for a fuzzer started on its own.

`run.sh` resolves this once and exports `RSASM`, so this is the path a fuzzer
takes when someone runs it by hand -- which is how a finding gets reproduced.
`<root>/target` is only right when nothing redirects it: a `target-dir` in a
cargo configuration, or `CARGO_TARGET_DIR`, sends the build elsewhere and
leaves whatever was there before behind, where every case would be compared
against a binary from an older checkout.
"""

import json
import os
import subprocess


def rsasm_path(root):
    """The `rsasm` cargo builds for `root`, honouring `RSASM` if it is set."""
    from_env = os.environ.get("RSASM")
    if from_env:
        return from_env
    return os.path.join(target_dir(root), "debug", "rsasm")


def target_dir(root):
    if os.environ.get("CARGO_TARGET_DIR"):
        return os.environ["CARGO_TARGET_DIR"]
    try:
        out = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1",
             "--manifest-path", os.path.join(root, "Cargo.toml")],
            capture_output=True, text=True, timeout=60, check=True).stdout
        return json.loads(out)["target_directory"]
    except (OSError, subprocess.SubprocessError, ValueError, KeyError):
        # A cargo that cannot answer leaves the default, which is what the
        # layout is when nothing moved it.
        return os.path.join(root, "target")
