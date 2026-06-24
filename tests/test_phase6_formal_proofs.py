from pathlib import Path

from sable import proofs
from sable.cli import main


def test_phase6_metadata():
    info = proofs.proof_info()
    version_tuple = tuple(int(x) for x in info["version"].split(".")[:3])
    assert version_tuple >= (0, 7, 0)
    assert info["phase"] == "formal-proof-strengthening"
    assert "certified 128/192/256-bit parameters" in info["not_claimed"]


def test_security_game_and_obligations():
    game = proofs.security_game_spec()
    assert "IND-CPA" in game["game"]
    obligations = proofs.proof_obligations()
    assert len(obligations) >= 8
    assert any(o.identifier == "O8" for o in obligations)
    assert len(proofs.hybrid_steps()) >= 5


def test_sample_ledger_values():
    ledger = proofs.sample_ledger("c7_standard_toy_noisy", fl_clients=5, model_length=7)
    d = ledger.to_jsonable()
    assert d["expansion_key_rows"] == d["N"] ** 2
    assert d["compaction_key_rows"] == d["N"] * d["m_c"]
    assert d["input_ciphertext_rows"] == 5 * 7 * d["replicas"]


def test_write_proof_package(tmp_path: Path):
    result = proofs.write_proof_package(tmp_path / "proofpkg")
    assert result["status"] == "written"
    assert (tmp_path / "proofpkg" / "proof_manifest.json").exists()
    assert (tmp_path / "proofpkg" / "README.md").exists()


def test_cli_phase6(tmp_path: Path, capsys):
    assert main(["proof-info"]) == 0
    assert "formal proof" in capsys.readouterr().out.lower()
    assert main(["security-game"]) == 0
    assert "security game" in capsys.readouterr().out.lower()
    assert main(["proof-obligations"]) == 0
    assert "O1" in capsys.readouterr().out
    assert main(["proof-ledger", "--preset", "c7_standard_toy_noisy", "--fl-clients", "2", "--model-length", "3"]) == 0
    assert "proof sample ledger" in capsys.readouterr().out
    assert main(["proof-package", "--output", str(tmp_path / "pkg")]) == 0
    assert (tmp_path / "pkg" / "proof_manifest.json").exists()
