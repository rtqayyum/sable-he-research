from sable.attack_estimators_phase8 import write_attack_package

manifest = write_attack_package("sable_phase8_attack_package")
print(manifest["schema"])
print("files", len(manifest["files"]))
