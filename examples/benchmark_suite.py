"""Generate a small SABLE-HE benchmark package."""
from pathlib import Path
from sable.benchmarking import write_benchmark_package

if __name__ == "__main__":
    paths = write_benchmark_package(Path("phase9_benchmark_package"), repetitions=1)
    for name, path in paths.items():
        print(f"{name}: {path}")
