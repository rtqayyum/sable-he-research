# Installation

```bash
python -m pip install sable-he-research
```

Development install:

```bash
git clone https://github.com/rtqayyum/sable-he-research.git
cd sable-he-research
python -m pip install -e ".[dev,numpy]"
python -m pytest -q
```

Optional extras:

```bash
python -m pip install "sable-he-research[numpy]"
python -m pip install "sable-he-research[pqc]"
```
