"""Generate a SABLE-HE proof-review bundle."""

from sable import proofs

if __name__ == "__main__":
    manifest = proofs.write_proof_package("sable_phase6_proof_package", preset="c7_standard_toy_noisy")
    print(manifest)
