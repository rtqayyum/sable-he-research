"""Generate SABLE-HE candidate parameter tables."""
from sable.parameter_sets import candidate_summary_rows, format_summary_table, write_parameter_package

rows = candidate_summary_rows()
print(format_summary_table(rows))
manifest = write_parameter_package("sable_phase7_parameter_package")
print(manifest)
