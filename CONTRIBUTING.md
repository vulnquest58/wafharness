# Contributing

## Run the tests

```bash
python -m pip install -e ".[dev]"
python -m pytest -o addopts=""
```

The suite is offline: every live transport is faked. Do not add tests that
contact a host, and do not add a fixture captured from a target you are not
allowed to test.

## Adding a stack

A stack is data, not a branch. Add a `Stack` to `wafharness/stacks.py` with a
pipeline of existing transforms, then say in `notes` where the behaviour comes
from. If the behaviour needs a transform that does not exist, add the transform
and its inverse in `transforms.py` / `encoders.py` first, with tests.

Do not add vendor-specific code to the engine. If a vendor needs a special case,
the model is missing a primitive.

## Safety

- `find`, `matrix`, `frames` and `explain` must stay offline.
- New live paths need a visible rate limit and an explicit confirmation gate.
- Never commit real target data, captured responses, cookies, hostnames or
  credentials.
- Findings are hypotheses until confirmed on a system you are authorised to
  test; keep the README's "Honest limits" section honest.

## Before a release

```bash
python -m pytest -o addopts=""
python -m compileall -q wafharness tests
python -m pip wheel . --no-deps --no-build-isolation -w dist
```

Update the test count in `README.md` and add a `CHANGELOG.md` entry.
