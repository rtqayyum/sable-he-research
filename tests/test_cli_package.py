from sable.cli import main


def test_cli_version(capsys):
    assert main(["version"]) == 0
    out = capsys.readouterr().out
    assert "sable-he-research" in out


def test_cli_quickstart(capsys):
    assert main(["quickstart", "--x", "3", "--y", "5"]) == 0
    out = capsys.readouterr().out
    assert "passes=True" in out


def test_cli_run_boolean_implies(capsys):
    assert main(["run", "implies", "--x", "1", "--y", "0"]) == 0
    out = capsys.readouterr().out
    assert "passes=True" in out


def test_operation_gate_implies_round_trip():
    from sable.params import PRESETS
    from sable.sable import compact_c7, decrypt_c7, encrypt, expand, keygen_c7
    from sable import operations as A

    params = PRESETS["c7_standard_toy_clean"]
    kp = keygen_c7(params, seed=321, mode="coordinate")
    x = expand(kp, encrypt(kp, 1, seed=1))
    y = expand(kp, encrypt(kp, 0, seed=2))
    out = decrypt_c7(kp, compact_c7(kp, A.gate_implies(x, y)))
    assert out == 0
