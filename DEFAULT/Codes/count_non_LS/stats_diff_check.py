"""stats_diff_check.py — Tabulates hex-character frequencies (LS vs non-LS) across the
pre-computed `0x{1,2}_*r_100000.txt` sample files in this directory,
writing two `*_results.txt` files into DEFAULT/Results/count_non_LS/.

On any error (missing file, permission denied, etc.) this script
raises / prints to stderr and exits non-zero — it does NOT embed the
error message into the results file, so reproduce.sh's `run_section`
wrapper sees the failure and flags the section as FAILED.
"""

import collections
import os
import sys


def get_hex_file_analysis_string(file_path):
    """
    Analyzes hex strings in the specified text file and returns the formatted result string.
    Raises on any I/O / parse failure (caller should let it propagate).
    """
    char_counts = collections.Counter()
    line_count = 0

    # Display name uses basename only so the output is stable no matter
    # which directory the script is invoked from.
    display_name = os.path.basename(file_path)

    with open(file_path, 'r') as f:
        for line in f:
            line_count += 1
            # Remove "0x" prefix and "," suffix, then convert to lowercase
            processed_line = line.strip().replace('0x', '').replace(',', '').lower()
            char_counts.update(processed_line)

    if line_count == 0:
        raise ValueError(f"File '{display_name}' is empty")

    # Calculation
    hex_chars = "0123456789abcdef"
    ls_chars = {'0', '6', '9', 'f'}

    ls_sum = sum(count for char, count in char_counts.items() if char in ls_chars)
    total_char_sum = sum(char_counts.values())
    non_ls_sum = total_char_sum - ls_sum

    ls_avg = ls_sum / line_count
    non_ls_avg = non_ls_sum / line_count

    # Construct Output String
    lines = []
    lines.append(f"Analysis Results for '{display_name}'")
    lines.append(f"Total lines: {line_count}\n")

    lines.append("--- Total Character Counts ---")
    for char in hex_chars:
        count = char_counts.get(char, 0)
        lines.append(f"'{char}': {count}")

    lines.append("\n--- Average Character Counts per Line ---")
    for char in hex_chars:
        count = char_counts.get(char, 0)
        average = count / line_count
        lines.append(f"'{char}': {average:.4f}")

    lines.append("\n--- Summary ---")
    lines.append(f"Sum of LS characters ('0', '6', '9', 'f'): {ls_sum}")
    lines.append(f"Sum of Non-LS characters (others): {non_ls_sum}")
    lines.append(f"Average LS characters per line: {ls_avg:.4f}")
    lines.append(f"Average Non-LS characters per line: {non_ls_avg:.4f}")

    return "\n".join(lines)


def process_group_and_save(file_list, output_filename):
    """
    Processes a list of files and saves their combined analysis results
    to a single output file.  Writes atomically via OUTPUT.partial +
    os.replace so a Ctrl-C mid-write cannot leave a truncated file that
    later diffs as "Files differ".
    """
    print(f"Processing group to create '{output_filename}'...")
    all_results = []

    for file_path in file_list:
        print(f"  - Analyzing {file_path}...")
        result_str = get_hex_file_analysis_string(file_path)

        # Add the result and a separator
        all_results.append(result_str)
        separator = "\n" + "=" * 50 + "\n"
        all_results.append(separator)

    # Atomic write.
    tmp = output_filename + ".partial"
    try:
        with open(tmp, 'w') as f:
            f.write("\n".join(all_results))
        os.replace(tmp, output_filename)
    except BaseException:
        # BaseException so Ctrl-C also cleans up the partial.
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    print(f"Successfully saved results to '{output_filename}'\n")


if __name__ == "__main__":
    # 1. Define file groups.  Input .txt files live next to this
    # script.  Output goes to the path given by argv[1], or to a
    # `stats_diff_output/` subdirectory next to this script by
    # default — so a casual run never mutates the committed
    # DEFAULT/Results/ tree.  Pass `../../Results/count_non_LS` as
    # argv[1] explicitly if you want to overwrite the committed
    # results files.
    here = os.path.dirname(os.path.abspath(__file__))
    default_out = os.path.join(here, "stats_diff_output")
    out_dir = sys.argv[1] if len(sys.argv) > 1 else default_out
    os.makedirs(out_dir, exist_ok=True)

    # Group 1: 0x1 input files -> 0x1_5-7r_results.txt
    group_0x1_files = [os.path.join(here, name) for name in [
        '0x1_5r_100000.txt',
        '0x1_6r_100000.txt',
        '0x1_7r_100000.txt',
    ]]

    # Group 2: 0x2 input files -> 0x2_4-6r_results.txt
    group_0x2_files = [os.path.join(here, name) for name in [
        '0x2_4r_100000.txt',
        '0x2_5r_100000.txt',
        '0x2_6r_100000.txt',
    ]]

    # 2. Process and save.  Failures raise, hit main-level try/except,
    # and cause a non-zero exit.
    try:
        process_group_and_save(group_0x1_files, os.path.join(out_dir, '0x1_5-7r_results.txt'))
        process_group_and_save(group_0x2_files, os.path.join(out_dir, '0x2_4-6r_results.txt'))
    except FileNotFoundError as exc:
        print(f"ERROR: required sample file missing: {exc}", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
