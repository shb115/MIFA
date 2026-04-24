"""monte_diff.py — Monte-Carlo hex-character-frequency helper over the BAKSHEESH
`0x{4,8}_*r_100000.txt` samples shipped in this directory."""

import collections

def analyze_hex_file(file_path):
    """
    Analyze the hexadecimal strings in the given text file.

    Args:
        file_path (str): path to the .txt file to analyze.
    """
    # Any I/O / decode error here propagates to the caller so a run
    # from the wrong CWD or with a damaged file exits non-zero instead
    # of silently printing "Error: …" lines a casual reader might miss.
    char_counts = collections.Counter()
    line_count = 0

    with open(file_path, 'r') as f:
        for line in f:
            line_count += 1
            # strip the "0x" prefix and trailing "," and lowercase
            processed_line = line.strip().replace('0x', '').replace(',', '').lower()
            char_counts.update(processed_line)

    if line_count == 0:
        print(f"'{file_path}' is empty.")
        return

    print(f"Analysis of '{file_path}'")
    print(f"Total lines: {line_count}\n")

    # --- Total counts ---
    print("--- Total character counts ---")
    hex_chars = "0123456789abcdef"
    for char in hex_chars:
        count = char_counts.get(char, 0)
        print(f"'{char}': {count}")

    # --- Per-line averages ---
    print("\n--- Average characters per line ---")
    for char in hex_chars:
        count = char_counts.get(char, 0)
        average = count / line_count
        print(f"'{char}': {average:.4f}")

    # --- Summary (LS vs non-LS) ---
    print("\n--- Summary ---")
    ls_chars = {'0', '8'}
    ls_sum = sum(count for char, count in char_counts.items() if char in ls_chars)

    # non-LS = total minus LS
    total_char_sum = sum(char_counts.values())
    non_ls_sum = total_char_sum - ls_sum

    # per-line averages
    ls_average_per_line = ls_sum / line_count
    non_ls_average_per_line = non_ls_sum / line_count

    print(f"LS characters ('0', '8') total: {ls_sum}")
    print(f"Non-LS characters (the rest) total: {non_ls_sum}")
    print(f"Avg LS characters per line: {ls_average_per_line:.4f}")
    print(f"Avg Non-LS characters per line: {non_ls_average_per_line:.4f}")

# --- Entry point ---
if __name__ == "__main__":
    import os as _os, sys as _sys

    # Pin the input files to the directory next to this script so the
    # invocation works regardless of the caller's CWD.  Previously a
    # relative path meant a run from the repo root silently printed
    # "Error: '0x4_4r_100000.txt' not found" for every file and exited 0.
    _here = _os.path.dirname(_os.path.abspath(__file__))
    files_to_process = [
        _os.path.join(_here, '0x4_4r_100000.txt'),
        _os.path.join(_here, '0x4_5r_100000.txt'),
        _os.path.join(_here, '0x8_4r_100000.txt'),
    ]

    for file_path in files_to_process:
        try:
            analyze_hex_file(file_path)
        except FileNotFoundError as _exc:
            print(f"ERROR: required sample file missing: {_exc}", file=_sys.stderr)
            _sys.exit(1)
        except OSError as _exc:
            print(f"ERROR: {_exc}", file=_sys.stderr)
            _sys.exit(1)
        print("\n" + "="*50 + "\n")   # separator between files
