# Build and Test Report

Package: `sable-he-research`
Version: `0.1.0`

## Built artifacts

```text
dist/sable_he_research-0.1.0-py3-none-any.whl
dist/sable_he_research-0.1.0.tar.gz
```

## Source test result

```text
99 passed
```

## Wheel install smoke test

A fresh virtual environment installed the wheel and successfully ran:

```bash
sable-he --version
sable-he info
sable-he demo --operation mul --x 3 --y 5
sable-he self-test
```

The demo returned the expected toy result for `(3 * 5) mod 7 = 1`.

## Notes

The wheel is pure Python and has no runtime third-party dependencies. The development test dependency is `pytest`.
