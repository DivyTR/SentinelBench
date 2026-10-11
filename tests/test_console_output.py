import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = [ROOT / "sentinelbench.py", *sorted((ROOT / "core").glob("*.py"))]


def test_printed_strings_are_ascii():
    # On Windows, piping output (e.g. into Tee-Object) makes Python encode
    # stdout as cp1252; a single non-ASCII character such as a check mark
    # crashed the first full-suite run before it started.
    offenders = []
    for path in SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "print":
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                            and not sub.value.isascii():
                        offenders.append(f"{path.name}:{sub.lineno}: {sub.value!r}")
    assert not offenders, "\n".join(offenders)
