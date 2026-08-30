from pathlib import Path

from blc_reverselab.adapters.ghidra import GhidraAdapter, parse_function_inventory


def test_ghidra_command_contract(tmp_path: Path):
    adapter = GhidraAdapter(binary="/opt/ghidra/support/analyzeHeadless", timeout_seconds=123)
    target = tmp_path / "libgame.so"
    project_dir = tmp_path / "projects"
    inventory = tmp_path / "functions.tsv"
    command = adapter.build_command(adapter.binary, target, project_dir, "blc_test", inventory)
    assert command[:3] == [adapter.binary, str(project_dir), "blc_test"]
    assert command[command.index("-import") + 1] == str(target)
    assert command[command.index("-analysisTimeoutPerFile") + 1] == "123"
    assert command[command.index("-postScript") + 1] == "BLCExportFunctions.java"
    assert command[command.index("-postScript") + 2] == str(inventory)
    assert "-deleteProject" in command


def test_parse_function_inventory_identifies_generic_jni_and_shape(tmp_path: Path):
    inventory = tmp_path / "functions.tsv"
    inventory.write_text(
        "001000\tFUN_001000\tfalse\tfalse\t42\t17\t2\n"
        "002000\tJava_com_example_Game_nativeTick\tfalse\tfalse\t128\t44\t1\n"
        "003000\tJNI_OnLoad\tfalse\tfalse\t64\t20\t0\n"
        "004000\tputs\ttrue\ttrue\t0\t0\t1\n",
        encoding="utf-8",
    )
    functions, sample, fingerprints = parse_function_inventory(inventory)
    assert len(functions) == 4
    assert sum(1 for item in functions if item.generic_name) == 1
    assert sum(1 for item in functions if item.jni_candidate) == 2
    assert functions[0].instruction_count == 17
    assert functions[0].parameter_count == 2
    assert functions[0].shape_id
    assert functions[-1].external is True
    assert functions[-1].thunk is True
    assert len(sample) == 4
    assert len(fingerprints) == 3


def test_legacy_five_column_inventory_still_parses(tmp_path: Path):
    inventory = tmp_path / "legacy.tsv"
    inventory.write_text("001000\tFUN_001000\tfalse\tfalse\t42\n", encoding="utf-8")
    functions, _, _ = parse_function_inventory(inventory)
    assert functions[0].instruction_count == 0
    assert functions[0].parameter_count == 0


def test_ghidra_unavailable_is_nonfatal(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("blc_reverselab.adapters.ghidra.shutil.which", lambda _: None)
    target = tmp_path / "libgame.so"
    target.write_bytes(b"binary")
    result = GhidraAdapter().analyze(target, tmp_path / "out")
    assert result.available is False
    assert result.status == "unavailable"
