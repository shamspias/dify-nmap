# 🤝 Contributing to Dify Nmap Plugin

Thank you for considering contributing to the **Nmap Scanner Plugin for Dify**!
We welcome contributions of all kinds — from fixing bugs, improving documentation, and suggesting new features, to writing code and helping with testing.

---

## 📋 How to Contribute

### 1. Fork & Clone

```bash
git fork https://github.com/shamspias/dify-nmap.git
cd dify-nmap
```

### 2. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 3. Make Your Changes

* Follow the [Code Style](#-code-style) guidelines
* Add or update tests if applicable
* Update documentation when relevant

### 4. Run Validation

Before committing, check your changes:

```bash
python validate_plugin.py
```

### 5. Commit Your Changes

Use clear, conventional commit messages:

```bash
git commit -m "feat(scanner): add support for custom NSE scripts"
```

### 6. Push & Open PR

```bash
git push origin feature/your-feature-name
```

Then open a Pull Request (PR) on GitHub with:

* A clear description of the change
* Screenshots/logs if applicable
* Any references to issues being fixed (e.g., `Fixes #12`)

---

## 🧑‍💻 Code Style

* **Python**: Follow [PEP 8](https://peps.python.org/pep-0008/)
* Use **type hints** for function signatures
* Write **docstrings** for all public functions and classes
* Keep imports organized and minimal

### Example

```python
def scan_target(target: str, ports: str = "1-1000") -> dict:
    """
    Run an Nmap scan on a target.

    Args:
        target (str): IP or hostname to scan.
        ports (str): Port range to scan (default: "1-1000").

    Returns:
        dict: Parsed Nmap scan results.
    """
    ...
```

---

## 🧪 Testing

* Write unit tests for new features and bug fixes
* Place tests under the `tests/` directory
* Run the test suite before submitting PRs:

```bash
pytest -v
```

---

## 📖 Documentation

* Update the **README.md** or **wiki** when adding new tools, parameters, or features
* Follow Markdown best practices (tables, code blocks, headers)
* Add usage examples whenever possible

---

## 🐛 Reporting Issues

* Use [GitHub Issues](https://github.com/shamspias/dify-nmap/issues)
* Include:

  * Steps to reproduce
  * Expected vs. actual behavior
  * Environment details (OS, Docker, Python, Nmap version)
  * Logs or screenshots if applicable

---

## 🌍 Community Guidelines

* Be respectful and constructive
* Provide clear and actionable feedback
* Collaborate openly — we’re all here to learn and improve

---

## 📝 Commit Message Format

We follow **Conventional Commits**:

```
<type>(scope): short description
```

**Types:**

* `feat` → New feature
* `fix` → Bug fix
* `docs` → Documentation only changes
* `style` → Code style (no logic changes)
* `refactor` → Code refactoring
* `test` → Adding/updating tests
* `chore` → Maintenance tasks

**Example:**

```
feat(scanner): add OS fingerprinting option
fix(config): handle missing sudo_password gracefully
docs(readme): update installation steps
```

---

## 🛡️ Security Issues

If you discover a security vulnerability:

* **Do not** open a public issue
* Instead, report it privately via email: [info@shamspias.com](mailto:info@shamspias.com)

I will work with you to resolve the issue responsibly.

---

## 💡 Suggestions

Feature requests and enhancement ideas are welcome! Please:

1. Check existing issues to avoid duplicates
2. Open a **Feature Request** issue with:

   * Problem statement
   * Proposed solution
   * Alternatives considered

---

## 🙌 Acknowledgment

Every contribution is valued — from small fixes to major features.
Your help makes this project stronger and more useful to the community.

---

### 🔗 Resources

* [Nmap Documentation](https://nmap.org/book/man.html)
* [Dify Documentation](https://docs.dify.ai/)
* [Python-nmap](https://pypi.org/project/python-nmap/)
