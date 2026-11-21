"""Run AEGIS YARA rules against local samples.

Usage: python -I tests/test_yara_rules.py <sample-dir>
The cheat samples are not committed to the repository. Point this at a folder
holding them; each file is matched and the hits are printed. Files whose
SHA-256 matches a rule's `sha256` meta must hit that rule, or the test fails.
"""
import hashlib
import pathlib
import sys

import yara

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = yara.compile(filepaths={p.stem: str(p) for p in (ROOT / "rules" / "yara").glob("*.yar")})


def expected_rules():
    exp = {}
    for path in (ROOT / "rules" / "yara").glob("*.yar"):
        for rule in yara.compile(filepath=str(path)):
            for key, value in rule.meta.items():
                if key == "sha256":
                    exp.setdefault(value, set()).add(rule.identifier)
    return exp


def main(sample_dir: str) -> int:
    exp = expected_rules()
    failures = 0
    for f in sorted(pathlib.Path(sample_dir).rglob("*")):
        if not f.is_file():
            continue
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        hits = {m.rule for m in RULES.match(str(f))}
        want = exp.get(digest, set())
        missing = want - hits
        status = "FAIL" if missing else "ok"
        failures += bool(missing)
        print(f"{status:4} {f.name}: {sorted(hits) or '-'}" + (f" missing {sorted(missing)}" if missing else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
