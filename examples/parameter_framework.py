"""Generate a Phase 7 SABLE-HE candidate parameter package."""

from sable.parameter_sets import write_parameter_package

if __name__ == "__main__":
    manifest = write_parameter_package("sable_phase7_parameter_package")
    print(manifest)
