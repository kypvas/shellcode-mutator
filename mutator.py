#!/usr/bin/env python3
"""
Shellcode Signature Patcher - YARA evasion via targeted byte patching.

Scans shellcode for YARA signatures and XORs only the specific bytes that
trigger detections. A small runtime stub (~130 bytes) patches bytes back
before execution.

Usage:
    python mutator.py input.bin -o output.bin
    python mutator.py input.bin -o output.bin -v
    python mutator.py input.bin --scan-only
"""

import argparse
import sys
import os
from pathlib import Path
import json

from engine import YaraScanner, PatternDetector


class ShellcodePatcher:
    """Shellcode signature patcher - scans for YARA signatures and patches them."""

    def __init__(self, arch: str = 'x64', verbose: bool = False):
        self.arch = arch
        self.verbose = verbose
        self.yara_scanner = YaraScanner()
        self.pattern_detector = PatternDetector()

        self.stats = {
            'original_size': 0,
            'final_size': 0,
            'yara_matches_before': 0,
            'yara_matches_after': 0,
            'signature_patches': 0,
            'bytes_patched': 0,
            'patcher_stub_size': 0
        }

    def log(self, message: str, level: str = 'info'):
        """Log a message with color coding."""
        if self.verbose or level == 'error':
            prefix = {'info': '[*]', 'success': '[+]', 'warning': '[!]', 'error': '[-]'}
            colors = {
                'info': '\033[96m',      # Cyan
                'success': '\033[92m',   # Green
                'warning': '\033[93m',   # Yellow
                'error': '\033[91m',     # Red
            }
            reset = '\033[0m'
            color = colors.get(level, '\033[96m')
            print(f"{color}{prefix.get(level, '[*]')}{reset} {message}")

    def scan(self, shellcode: bytes) -> dict:
        """Scan shellcode for YARA matches and patterns."""
        self.log(f"Scanning {len(shellcode)} bytes of shellcode...")

        yara_matches = self.yara_scanner.scan(shellcode)
        patterns = self.pattern_detector.detect_all(shellcode)
        analysis = self.pattern_detector.analyze(shellcode)

        result = {
            'size': len(shellcode),
            'arch': self.arch,
            'yara_matches': [
                {
                    'rule': m.rule_name,
                    'namespace': m.namespace,
                    'strings': [
                        {'offset': s['offset'], 'identifier': s['identifier'],
                         'data': s['data'].hex()}
                        for s in m.strings
                    ]
                }
                for m in yara_matches
            ],
            'patterns': [
                {
                    'offset': p.offset,
                    'length': p.length,
                    'type': p.pattern_type,
                    'confidence': p.confidence,
                    'description': p.description
                }
                for p in patterns
            ],
            'entropy': analysis['overall_entropy'],
            'transformation_targets': analysis['transformation_targets']
        }

        return result

    def get_stats(self) -> dict:
        """Return statistics from the last operation."""
        return self.stats


def _print_yara_match_details(matches):
    """Print detailed YARA match information including rule names and matched patterns."""
    for match in matches:
        if hasattr(match, 'rule_name'):
            rule_name = match.rule_name
            namespace = getattr(match, 'namespace', 'unknown')
            strings = getattr(match, 'strings', [])
        elif isinstance(match, dict):
            rule_name = match.get('rule', match.get('rule_name', 'unknown'))
            namespace = match.get('namespace', 'unknown')
            strings = match.get('strings', [])
        else:
            print(f"      - {match}")
            continue

        print(f"\n      Rule: {rule_name}")
        print(f"      Namespace: {namespace}")

        if strings:
            print(f"      Matched patterns ({len(strings)}):")
            for i, s in enumerate(strings[:10]):
                if isinstance(s, dict):
                    identifier = s.get('identifier', s.get('name', f'pattern_{i}'))
                    offset = s.get('offset', 0)
                    data = s.get('data', b'')
                else:
                    identifier = getattr(s, 'identifier', getattr(s, 'name', f'pattern_{i}'))
                    offset = getattr(s, 'offset', 0)
                    data = getattr(s, 'data', getattr(s, 'matched_data', b''))

                if isinstance(data, bytes):
                    hex_data = data[:16].hex()
                    if len(data) > 16:
                        hex_data += '...'
                else:
                    hex_data = str(data)[:32]

                print(f"        - {identifier} @ offset 0x{offset:04x}: {hex_data}")

            if len(strings) > 10:
                print(f"        ... and {len(strings) - 10} more patterns")


def main():
    parser = argparse.ArgumentParser(
        description='Shellcode Signature Patcher - YARA evasion via targeted byte patching',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    python mutator.py payload.bin -o patched.bin
    python mutator.py payload.bin -o patched.bin -v
    python mutator.py payload.bin --scan-only --json
    cat payload.bin | python mutator.py - -o patched.bin

How it works:
    1. Scans shellcode for YARA signature matches
    2. XORs only the specific bytes that trigger signatures
    3. Prepends a tiny runtime stub (~130 bytes) that patches bytes back
    4. Shellcode executes normally after runtime patching

Notes:
    - Original shellcode functionality is preserved
    - Only signature bytes are modified (minimal changes)
    - Works with any x64 shellcode
        '''
    )

    parser.add_argument('input', nargs='?', default=None, help='Input shellcode file (use - for stdin)')
    parser.add_argument('-o', '--output', help='Output file for patched shellcode')
    parser.add_argument('--arch', choices=['x64', 'x86'], default='x64',
                        help='Architecture (default: x64)')
    parser.add_argument('--scan-only', action='store_true',
                        help='Only scan for signatures, do not patch')
    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('--rules-dir', help='Additional YARA rules directory')
    parser.add_argument('--list-rules', action='store_true',
                        help='List all loaded YARA rules and exit')

    args = parser.parse_args()

    # List rules and exit
    if args.list_rules:
        scanner = YaraScanner()
        if args.rules_dir and os.path.isdir(args.rules_dir):
            for rule_file in Path(args.rules_dir).glob('*.yar'):
                try:
                    scanner.add_rule_file(str(rule_file))
                except Exception as e:
                    print(f"Warning: Could not load {rule_file}: {e}", file=sys.stderr)
            for rule_file in Path(args.rules_dir).glob('*.yara'):
                try:
                    scanner.add_rule_file(str(rule_file))
                except Exception as e:
                    print(f"Warning: Could not load {rule_file}: {e}", file=sys.stderr)
        print(f"\n{'='*60}")
        print(f"LOADED YARA RULE SETS: {len(scanner.compiled_rules)}")
        print(f"{'='*60}")
        total_rules = 0
        for namespace, rules in scanner.compiled_rules:
            rule_names = [r.identifier for r in rules]
            total_rules += len(rule_names)
            print(f"\n[{namespace}] - {len(rule_names)} rules:")
            for name in rule_names:
                print(f"  - {name}")
        print(f"\n{'='*60}")
        print(f"TOTAL: {total_rules} individual YARA rules loaded")
        print(f"{'='*60}")
        sys.exit(0)

    # Validate input
    if args.input is None:
        print("Error: Input file required (use --list-rules to see loaded rules)", file=sys.stderr)
        sys.exit(1)

    # Read input shellcode
    if args.input == '-':
        shellcode = sys.stdin.buffer.read()
    else:
        if not os.path.exists(args.input):
            print(f"Error: Input file '{args.input}' not found", file=sys.stderr)
            sys.exit(1)
        with open(args.input, 'rb') as f:
            shellcode = f.read()

    if len(shellcode) == 0:
        print("Error: Empty input", file=sys.stderr)
        sys.exit(1)

    # Initialize patcher
    patcher = ShellcodePatcher(arch=args.arch, verbose=args.verbose)

    # Load additional rules
    rules_loaded_from_dir = 0
    if args.rules_dir and os.path.isdir(args.rules_dir):
        for rule_file in list(Path(args.rules_dir).glob('*.yar')) + list(Path(args.rules_dir).glob('*.yara')):
            try:
                patcher.yara_scanner.add_rule_file(str(rule_file))
                rules_loaded_from_dir += 1
                if args.verbose:
                    print(f"[+] Loaded rules from: {rule_file.name}")
            except Exception as e:
                print(f"Warning: Could not load {rule_file}: {e}", file=sys.stderr)

    total_rule_sets = len(patcher.yara_scanner.compiled_rules)
    total_rules = sum(len([r.identifier for r in rules]) for _, rules in patcher.yara_scanner.compiled_rules)

    # Color codes
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    if args.verbose:
        print(f"\n{CYAN}[*]{RESET} YARA Configuration:")
        print(f"{DIM}    Rule sets loaded:{RESET} {GREEN}{total_rule_sets}{RESET}")
        print(f"{DIM}    Total rules:{RESET} {GREEN}{total_rules}{RESET}")
        if rules_loaded_from_dir > 0:
            print(f"{DIM}    From --rules-dir:{RESET} {GREEN}{rules_loaded_from_dir}{RESET} files")
        print(f"\n{CYAN}[*]{RESET} Scanning {GREEN}{len(shellcode)}{RESET} bytes against {GREEN}{total_rules}{RESET} YARA rules...")

    # Scan only mode
    if args.scan_only:
        result = patcher.scan(shellcode)
        result['rules_scanned'] = total_rules
        result['rule_sets'] = [name for name, _ in patcher.yara_scanner.compiled_rules]
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"\n{'='*60}")
            print(f"SHELLCODE ANALYSIS REPORT")
            print(f"{'='*60}")
            print(f"Size: {result['size']} bytes")
            print(f"Architecture: {result['arch']}")
            print(f"Entropy: {result['entropy']:.2f} bits/byte")
            print(f"\nRules Scanned: {total_rules} rules from {total_rule_sets} rule sets")
            for name, rules in patcher.yara_scanner.compiled_rules:
                rule_count = len([r.identifier for r in rules])
                print(f"  - [{name}]: {rule_count} rules checked")
            print(f"\nYARA Matches: {len(result['yara_matches'])}")
            for match in result['yara_matches']:
                print(f"  - {match['rule']} ({match['namespace']})")
                for s in match['strings'][:3]:
                    print(f"      {s['identifier']} @ 0x{s['offset']:04x}")
            print(f"\nPatterns Detected: {len(result['patterns'])}")
            for pattern in result['patterns'][:10]:
                print(f"  - [{pattern['type']}] {pattern['description']} (confidence: {pattern['confidence']:.2f})")
            print(f"\nTransformation Targets: {len(result['transformation_targets'])} regions")
            print(f"{'='*60}")
        sys.exit(0)

    # Patching mode - require output
    if not args.output:
        print("Error: Output file required (use -o)", file=sys.stderr)
        sys.exit(1)

    # Initialize stats
    patcher.stats['original_size'] = len(shellcode)
    patcher.stats['yara_matches_before'] = len(patcher.yara_scanner.scan(shellcode))

    # Apply signature patching
    from engine.signature_patcher import patch_signatures

    if args.verbose:
        print(f"\n{MAGENTA}[*] Applying Signature Patching...{RESET}")
        print(f"{DIM}[*]   Scanning for YARA signatures...{RESET}")

    patch_result = patch_signatures(shellcode, patcher.yara_scanner, verbose=args.verbose)

    if patch_result.patch_count > 0:
        patched = patch_result.patched_shellcode
        patcher.stats['signature_patches'] = patch_result.patch_count
        patcher.stats['bytes_patched'] = patch_result.total_bytes_patched
        patcher.stats['patcher_stub_size'] = patch_result.stub_size

        if args.verbose:
            print(f"{GREEN}[+] Patched {patch_result.patch_count} signature regions ({patch_result.total_bytes_patched} bytes){RESET}")
            print(f"{DIM}[*] Patcher stub size: {patch_result.stub_size} bytes{RESET}")

        # Re-scan to verify
        final_yara = patcher.yara_scanner.scan(patched)
        patcher.stats['yara_matches_after'] = len(final_yara)
        patcher.stats['yara_matches_after_details'] = final_yara
        patcher.stats['final_size'] = len(patched)

        if args.verbose:
            yara_color = GREEN if len(final_yara) == 0 else YELLOW
            print(f"{yara_color}[+] YARA matches after patching: {len(final_yara)}{RESET}")
    else:
        patched = shellcode
        patcher.stats['yara_matches_after'] = patcher.stats['yara_matches_before']
        patcher.stats['final_size'] = len(shellcode)
        if args.verbose:
            print(f"{DIM}[*] No signatures found to patch{RESET}")

    # Write output
    with open(args.output, 'wb') as f:
        f.write(patched)

    stats = patcher.get_stats()

    # Output results
    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        # Determine result color based on YARA matches
        if stats['yara_matches_after'] == 0:
            result_color = GREEN
            header_color = GREEN
        elif stats['yara_matches_after'] < stats['yara_matches_before']:
            result_color = YELLOW
            header_color = YELLOW
        else:
            result_color = YELLOW
            header_color = MAGENTA

        print(f"\n{header_color}{'='*60}{RESET}")
        print(f"{header_color}{BOLD}PATCHING COMPLETE{RESET}")
        print(f"{header_color}{'='*60}{RESET}")
        print(f"{DIM}Original size:{RESET} {stats['original_size']} bytes")
        print(f"{DIM}Patched size:{RESET}  {GREEN}{stats['final_size']}{RESET} bytes")
        size_change = stats['final_size'] - stats['original_size']
        size_color = GREEN if size_change >= 0 else YELLOW
        print(f"{DIM}Size change:{RESET}   {size_color}{size_change:+d}{RESET} bytes (stub overhead)")
        print(f"\n{DIM}Rules Checked:{RESET} {CYAN}{total_rules}{RESET} rules from {CYAN}{total_rule_sets}{RESET} rule sets")
        print(f"{DIM}YARA matches before:{RESET} {YELLOW}{stats['yara_matches_before']}{RESET}")
        yara_after_color = GREEN if stats['yara_matches_after'] == 0 else YELLOW
        print(f"{DIM}YARA matches after:{RESET}  {yara_after_color}{stats['yara_matches_after']}{RESET}")
        print(f"\n{DIM}Output written to:{RESET}   {GREEN}{args.output}{RESET}")
        print(f"{header_color}{'='*60}{RESET}")

        if stats['yara_matches_after'] == 0:
            print(f"\n{GREEN}{BOLD}[+] SUCCESS: All YARA signatures evaded!{RESET}")
        elif stats['yara_matches_after'] < stats['yara_matches_before']:
            print(f"\n{YELLOW}[!] PARTIAL: Reduced signatures from {stats['yara_matches_before']} to {stats['yara_matches_after']}{RESET}")
            if 'yara_matches_after_details' in stats and stats['yara_matches_after_details']:
                print(f"\n{DIM}    Remaining signatures:{RESET}")
                _print_yara_match_details(stats['yara_matches_after_details'])
        else:
            if 'yara_matches_after_details' in stats and stats['yara_matches_after_details']:
                print(f"\n{YELLOW}[-] WARNING: {stats['yara_matches_after']} signatures still matching:{RESET}")
                _print_yara_match_details(stats['yara_matches_after_details'])


if __name__ == '__main__':
    main()
