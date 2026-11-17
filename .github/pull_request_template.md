## Summary

Describe the user-visible change and why it is needed.

## Compatibility and safety

- [ ] I have not added a second parser, executor, report writer or config loader.
- [ ] Network tests use loopback or synthetic fixtures only.
- [ ] I have not included credentials, client data or third-party scan results.
- [ ] CLI/config/report compatibility impact is documented.

## Verification

- [ ] `python -m pytest -q`
- [ ] `python -m ruff check src tests scripts`
- [ ] `python -W error -m compileall -q src scripts tests`
- [ ] `python scripts/check_docs.py`
- [ ] `python scripts/validate_assets.py`

## Notes

Add screenshots, logs or migration notes only after removing sensitive data.
