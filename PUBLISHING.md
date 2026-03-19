# Publishing Packtrix to PyPI

This guide takes you from the source code to `pip install packtrix` working
for anyone in the world. You only need to do the one-time setup steps once.

---

## What you need

- A PyPI account — create one free at https://pypi.org/account/register/
- Python 3.10+
- `build` and `twine` (installed in step 2 below)

---

## Step 1 — Make sure the project is clean

```bash
cd ~/packtrix      # your project folder

# Confirm the package imports and the CLI works
python3 -m packtrix --version
python3 -m packtrix analyze --demo
```

---

## Step 2 — Install the publishing tools

```bash
pip install build twine
```

- **build** — creates the wheel (`.whl`) and source distribution (`.tar.gz`)
- **twine** — uploads them to PyPI securely

---

## Step 3 — Build the distribution packages

```bash
python3 -m build
```

This creates a `dist/` folder with two files:

```
dist/
├── packtrix-1.0.0.tar.gz        ← source distribution (sdist)
└── packtrix-1.0.0-py3-none-any.whl  ← wheel (what pip actually installs)
```

Check them before uploading:

```bash
twine check dist/*
```

You should see `PASSED` for both files. Fix any warnings before continuing.

---

## Step 4 — Create a PyPI API token

1. Log in at https://pypi.org
2. Go to **Account settings → API tokens**
3. Click **Add API token**
4. Name it `packtrix-upload`, scope it to **Entire account** (first time)
5. Copy the token — it starts with `pypi-` and is shown only once

Save it somewhere safe (password manager).

---

## Step 5 — Upload to PyPI

```bash
twine upload dist/*
```

When prompted:

```
Enter your username: __token__
Enter your password: pypi-xxxxxxxxxxxxxxxxxxxxxxxx   ← paste your token here
```

> **Tip:** Skip the prompt by setting environment variables:
> ```bash
> export TWINE_USERNAME=__token__
> export TWINE_PASSWORD=pypi-xxxxxxxxxxxxxxxxxxxxxxxx
> twine upload dist/*
> ```

---

## Step 6 — Install and verify

Wait about 60 seconds for PyPI to index the upload, then:

```bash
# In a fresh terminal or new venv
pip install packtrix
packtrix --version
packtrix analyze --demo
packtrix dashboard
```

If it works — you are done. Packtrix is now publicly installable by anyone.

---

## Updating the package (future releases)

1. Bump the version in **two places**:
   - `packtrix/__init__.py` — `__version__ = "1.1.0"`
   - `pyproject.toml` — `version = "1.1.0"`

2. Add an entry to `CHANGELOG.md`

3. Delete the old build:
   ```bash
   rm -rf dist/ build/ packtrix.egg-info/
   ```

4. Rebuild and upload:
   ```bash
   python3 -m build
   twine check dist/*
   twine upload dist/*
   ```

---

## Optional — Test on TestPyPI first

TestPyPI (https://test.pypi.org) is a sandbox. Use it to practice the upload
without affecting the real package index.

```bash
# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Install from TestPyPI to verify
pip install --index-url https://test.pypi.org/simple/ packtrix
```

Create a separate account + token at https://test.pypi.org/account/register/

---

## Optional — Store credentials in ~/.pypirc

Create this file so you never have to type the token interactively:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-xxxxxxxxxxxxxxxxxxxxxxxx

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-xxxxxxxxxxxxxxxxxxxxxxxx
```

Set permissions so only you can read it:

```bash
chmod 600 ~/.pypirc
```

---

## Optional — GitHub Actions CI/CD (auto-publish on tag)

Create `.github/workflows/publish.yml`:

```yaml
name: Publish to PyPI

on:
  push:
    tags:
      - "v*"          # triggers on: git tag v1.1.0 && git push --tags

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install build tools
        run: pip install build twine

      - name: Build
        run: python3 -m build

      - name: Check
        run: twine check dist/*

      - name: Upload to PyPI
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: twine upload dist/*
```

Add your PyPI token as a GitHub secret named `PYPI_API_TOKEN` under
**Settings → Secrets and variables → Actions**.

After that, publishing is just:

```bash
git tag v1.1.0
git push --tags
```

---

## Quick reference

| Task | Command |
|---|---|
| Build distribution | `python3 -m build` |
| Check packages | `twine check dist/*` |
| Upload to PyPI | `twine upload dist/*` |
| Upload to TestPyPI | `twine upload --repository testpypi dist/*` |
| Install released | `pip install packtrix` |
| Install with live mode | `pip install "packtrix[live]"` |
| Install dev tools | `pip install "packtrix[dev]"` |
| Install everything | `pip install "packtrix[all]"` |
| Editable local install | `pip install -e .` |
