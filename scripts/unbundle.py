"""Development helper: split a bundle file into many source files.

Bundle format: lines of the form `=== FILE: relative/path ===` start a new file;
everything until the next marker is that file's content. Paths are relative to
the directory given as the second argument.
"""
import os
import sys

bundle, root = sys.argv[1], sys.argv[2]
current, buf, written = None, [], []


def flush():
    if current is None:
        return
    path = os.path.join(root, current)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = "".join(buf).strip("\n") + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    written.append(current)


with open(bundle, encoding="utf-8") as f:
    for line in f:
        if line.startswith("=== FILE: ") and line.rstrip().endswith(" ==="):
            flush()
            current = line.rstrip()[len("=== FILE: "):-4].strip()
            buf = []
        else:
            buf.append(line)
flush()
print(f"wrote {len(written)} files")
for w in written:
    print("  " + w)
