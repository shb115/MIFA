import collections
import os

def get_hex_file_analysis_string(file_path):
    """
    Analyzes hex strings in the specified text file and returns the formatted result string.
    """
    char_counts = collections.Counter()
    line_count = 0

    try:
        with open(file_path, 'r') as f:
            for line in f:
                line_count += 1
                # Remove "0x" prefix and "," suffix, then convert to lowercase
                processed_line = line.strip().replace('0x', '').replace(',', '').lower()
                char_counts.update(processed_line)

        if line_count == 0:
            return f"File '{file_path}' is empty.\n"

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
        lines.append(f"Analysis Results for '{file_path}'")
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

    except FileNotFoundError:
        return f"Error: File '{file_path}' not found.\n"
    except Exception as e:
        return f"An error occurred while processing '{file_path}': {e}\n"

def process_group_and_save(file_list, output_filename):
    """
    Processes a list of files and saves their combined analysis results to a single output file.
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

    # Save to file
    try:
        with open(output_filename, 'w') as f:
            f.write("\n".join(all_results))
        print(f"Successfully saved results to '{output_filename}'\n")
    except Exception as e:
        print(f"Failed to save '{output_filename}': {e}\n")

if __name__ == "__main__":
    # 1. Define File Groups
    
    # Group 1: 0x1 Files -> will be saved to '0x1_results.txt'
    group_0x1_files = [
        '0x1_5r_100000.txt',
        '0x1_6r_100000.txt',
        '0x1_7r_100000.txt'
    ]

    # Group 2: 0x2 Files -> will be saved to '0x2_results.txt'
    group_0x2_files = [
        '0x2_4r_100000.txt',
        '0x2_5r_100000.txt',
        '0x2_6r_100000.txt'
    ]

    # 2. Process and Save
    process_group_and_save(group_0x1_files, '0x1_5-7r_results.txt')
    process_group_and_save(group_0x2_files, '0x2_4-6r_results.txt')