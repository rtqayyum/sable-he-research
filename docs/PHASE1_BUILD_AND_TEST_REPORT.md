# Phase 1 Build and Test Report

Date: 2026-06-22
Version: 0.2.1

## Validation performed

```text
python -m pytest -q
104 passed
```

## Distribution artifacts

```text
sable_he_research-0.2.1-py3-none-any.whl
sable_he_research-0.2.1.tar.gz
```

## Wheel smoke test

```bash
python -m venv venv_test
. venv_test/bin/activate
pip install dist/sable_he_research-0.2.1-py3-none-any.whl
sable-he --version
sable-he fl-demo
```

Output:

```text
sable-he-research 0.2.1
SABLE-HE FL demo 0.2.1 (Public research release)
preset=fl_demo_clean q=1000003 scale=1000
sample_counts=[80, 20, 100]
encrypted FedAvg result=[0.158, -0.366, 1.155]
plaintext reference   =[0.158, -0.366, 1.155]
```
