from pathlib import Path

from sable import proofs
from sable.cli import main
from sable.params import PRESETS


def test_proof_status_and_game():
    info = proofs.proof_info()
    assert info["schema"].startswith("sable-phase6")
    game = proofs.security_game_spec()
    assert "IND-CPA" in game["game"]
    assert "security_claim" in game


def test_obligations_and_ledger():
    obligations = proofs.proof_obligations()
    assert len(obligations) >= 10
    assert any(o.identifier == "O12" for o in obligations)
    ledger = proofs.sample_ledger(PRESETS["c7_standard_toy_noisy"], depth=1, additions=1)
    assert ledger.expansion_key_rows > 0
    assert ledger.compaction_key_rows > 0


def test_write_proof_package(tmp_path: Path):
    result = proofs.write_proof_package(tmp_path, preset="c7_standard_toy_noisy", depth=1, additions=1)
    assert result["status"] == "written"
    assert (tmp_path / "proof_manifest.json").exists()
    assert (tmp_path / "security_game.json").exists()
    assert (tmp_path / "sample_ledger.json").exists()
    assert (tmp_path / "README.md").exists()


def test_phase6_cli(tmp_path: Path, capsys):
    assert main(["proof-info"]) == 0
    assert "formal proof" in capsys.readouterr().out.lower()
    assert main(["security-game"]) == 0
    assert "security game" in capsys.readouterr().out
    assert main(["proof-obligations"]) == 0
    output = capsys.readouterr().out
    assert "O1" in output and "O12" in output
    assert main(["proof-ledger", "--preset", "c7_standard_toy_noisy"]) == 0
    assert "expansion_key_rows" in capsys.readouterr().out
    assert main(["proof-package", "--output", str(tmp_path / "proof_bundle")]) == 0
    assert (tmp_path / "proof_bundle" / "proof_manifest.json").exists()
