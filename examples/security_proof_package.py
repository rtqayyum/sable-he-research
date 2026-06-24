"""Generate a formal SABLE-HE proof package."""
from sable.proofs import write_proof_package

result = write_proof_package("sable_proof_package", preset="c7_standard_toy_noisy")
print(result)
