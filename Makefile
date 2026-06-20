.PHONY: test estimate security correctness depth sweep attack-sweep bench

test:
	python -m pytest -q

estimate:
	PYTHONPATH=src python -m sable.estimator --preset toy_noisy --depth 1

security:
	PYTHONPATH=src python -m sable.security_estimator --preset toy_noisy

correctness:
	python experiments/run_correctness.py --preset toy_noisy --function mul --trials 100 --seed 7

depth:
	python experiments/run_depth_sweep.py --preset toy_depth2 --max-depth 2 --trials 50 --seed 9

sweep:
	python experiments/run_parameter_sweep.py

attack-sweep:
	python experiments/run_attack_sweep.py

bench:
	python benchmarks/benchmark_boolean.py --preset toy_noisy --gate and --trials 20


attack:
	PYTHONPATH=src python -m sable.attacks --preset toy_noisy

feasibility:
	python experiments/run_security_feasibility_grid.py

baseline:
	python experiments/run_baseline_model.py --preset toy_depth2


c2-attack-surface:
	PYTHONPATH=src python experiments/run_c2_attack_surface.py --preset c2_toy_noisy

seeded-estimate:
	PYTHONPATH=src python experiments/run_seeded_estimator.py

seeded-correctness:
	PYTHONPATH=src python experiments/run_seeded_c2.py


c5-arithmetic:
	python experiments/run_c5_arithmetic_suite.py --preset c4_projective_toy_clean --trials 5 --json-output docs/c5_arithmetic_suite_output.json --csv-output docs/c5_arithmetic_suite_output.csv

c5-compare:
	python experiments/run_c5_compare_baselines.py --preset c4_projective_toy_noisy --json-output docs/c5_baseline_comparison.json --csv-output docs/c5_baseline_comparison.csv

c5-surface:
	python experiments/run_c5_surface.py --preset c4_projective_toy_noisy --json-output docs/c5_surface_output.json
