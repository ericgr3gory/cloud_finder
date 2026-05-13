#!/usr/bin/env python3

from pathlib import Path
import json

DICT_DIR = Path("~/.hashcat/dictionaries").expanduser()
OUTPUT_FILE = Path("~/python-hashes/wordlists.json").expanduser()


def make_id(file_path: Path) -> str:
    """
    Create ID from filename:
    - remove extension
    - keep full base name (no prefix stripping unless you want to add rules later)
    """
    return file_path.stem


def main():
    wordlists = []

    for file in sorted(DICT_DIR.iterdir()):
        if not file.is_file():
            continue

        # optional: only include text-like wordlists
        if file.suffix.lower() not in {".txt", ".lst", ".found"}:
            continue

        entry = {
            "id": make_id(file),
            "file": str(Path("~/.hashcat/dictionaries") / file.name),
        }

        wordlists.append(entry)

    output = {"wordlists": wordlists}

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Wrote {len(wordlists)} entries to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
