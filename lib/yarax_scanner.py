import os
import sys
from yarax import Scanner, Rules
from pathlib import Path
from typing import List, Dict

def compile_rules(rule_dir: str) -> Rules:
    """
    Compile Yara rules from a directory.
    
    Args:
        rule_dir: Path to directory containing rule files
    
    Returns:
        Compiled Rules object
    """
    rules = Rules()
    
    if not os.path.exists(rule_dir):
        print(f"[-] Rule directory {rule_dir} not found")
        sys.exit(1)
    
    # Track if we found any rule files
    rule_files_found = False
    
    # Compile rules from directory
    for root, _, files in os.walk(rule_dir):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                rule_files_found = True
                rule_path = os.path.join(root, file)
                try:
                    rules.add_file(rule_path)
                    print(f"[+] Compiled rules from {rule_path}")
                except Exception as e:
                    print(f"[-] Error compiling {rule_path}: {str(e)}")
    
    if not rule_files_found:
        print(f"[-] No .yar or .yara files found in {rule_dir}")
        sys.exit(1)
    
    return rules

def scan_files(target_dir: str, rules: Rules) -> Dict[str, List[str]]:
    """
    Scan all files in a directory using compiled Yara rules.
    
    Args:
        target_dir: Directory containing files to scan
        rules: Compiled Yara rules
    
    Returns:
        Dictionary mapping filenames to lists of matched rule names
    """
    scanner = Scanner(rules)
    results = {}
    
    if not os.path.exists(target_dir):
        print(f"[-] Target directory {target_dir} not found")
        return results
    
    for root, _, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                matches = scanner.scan_file(file_path)
                if matches:
                    results[file_path] = [match.rule for match in matches]
                    print(f"[+] Found matches in {file_path}:")
                    for match in matches:
                        print(f"    - {match.rule}")
                else:
                    print(f"[*] No matches in {file_path}")
            except Exception as e:
                print(f"[-] Error scanning {file_path}: {str(e)}")
    
    return results

def main():
    # Configuration
    RULE_DIR = "signature"
    TARGET_DIR = "files_to_scan"  # Change this to your target directory
    
    # Compile rules
    print("[*] Compiling Yara rules from signature directory...")
    rules = compile_rules(RULE_DIR)
    
    # Scan files
    print("\n[*] Starting file scan...")
    results = scan_files(TARGET_DIR, rules)
    
    # Print summary
    print("\n[*] Scan Summary:")
    total_files = len([f for f in Path(TARGET_DIR).rglob('*') if f.is_file()])
    matched_files = len(results)
    print(f"Total files scanned: {total_files}")
    print(f"Files with matches: {matched_files}")
    
    if matched_files > 0:
        print("\nDetailed matches:")
        for file_path, matched_rules in results.items():
            print(f"\n{file_path}:")
            for rule in matched_rules:
                print(f"  - {rule}")

if __name__ == "__main__":
    main()