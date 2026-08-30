from pathlib import Path

from blc_reverselab.adapters.jadx import JadxAdapter


def test_jadx_command_contract(tmp_path: Path):
    adapter = JadxAdapter(binary="/opt/jadx/bin/jadx")
    target = tmp_path / "sample.apk"
    output = tmp_path / "out"
    assert adapter.build_command(adapter.binary, target, output) == [
        "/opt/jadx/bin/jadx",
        "--output-dir",
        str(output),
        str(target),
    ]


def test_jadx_recovery_command_enables_deobfuscation_and_mapping(tmp_path: Path):
    mapping = tmp_path / "mapping.txt"
    mapping.write_text("com.example.Real -> a:\n", encoding="utf-8")
    adapter = JadxAdapter(
        binary="/opt/jadx/bin/jadx",
        deobfuscate=True,
        mappings_path=mapping,
    )
    target = tmp_path / "sample.apk"
    output = tmp_path / "out"
    command = adapter.build_command(adapter.binary, target, output)

    assert "--deobf" in command
    assert "--use-source-name-as-class-name-alias" in command
    assert "--rename-flags" in command
    assert "--use-headers-for-detect-resource-extensions" in command
    assert command[command.index("--mappings-path") + 1] == str(mapping)
    assert command[-1] == str(target)


def test_jadx_unavailable_is_nonfatal(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("blc_reverselab.adapters.jadx.shutil.which", lambda _: None)
    target = tmp_path / "sample.apk"
    target.write_bytes(b"not-important")
    result = JadxAdapter().analyze(target, tmp_path / "out")
    assert result.available is False
    assert result.status == "unavailable"
