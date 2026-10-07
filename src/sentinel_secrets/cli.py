import argparse
import subprocess
import sys

from .git_walker import walk_history, walk_working_tree
from .baseline import filter_findings, fingerprint, load_baseline, save_baseline
from .report import format_console, format_json

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='sentinel-secrets',
        description='Scan a Git repository for exposed secrets.',
    )
    
    parser.add_argument(
        'repo_path',
        help='Path to the Git repository to scan',
    )
    
    parser.add_argument(
        '--baseline',
        default=None,
        help='Path to a baseline JSON file',
    )

    parser.add_argument(
        '--update-baseline',
        default=None,
        metavar='PATH',
        help='Add every current finding to this baseline file and exit',
    )
    
    parser.add_argument(
        '--output',
        choices=['console', 'json'],
        default='console',
        help='Output format',
    )
    
    history_group = parser.add_mutually_exclusive_group()
    
    history_group.add_argument(
        '--history',
        dest='history',
        action='store_true',
        help='Scan Git history (default)',
    )
    
    history_group.add_argument(
        '--no-history',
        dest='history',
        action='store_false',
        help='Skip Git history scanning',
    )
    
    parser.set_defaults(history=True)
    
    return parser


def _error(message: str) -> int:
    print(f'sentinel-secrets: error: {message}', file=sys.stderr)
    return 2


def _use_utf8_output() -> None:
    # Redirected output otherwise uses the platform encoding (cp1252 on
    # Windows), which can't represent every filename a finding can name.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')


def main(argv: list[str] | None = None) -> int:
    _use_utf8_output()
    args = build_parser().parse_args(argv)

    # Exit code 1 means "findings exist", so a failed scan must not use it.
    try:
        findings = walk_working_tree(args.repo_path)

        if args.history:
            findings += walk_history(args.repo_path)
    except FileNotFoundError:
        return _error('git is not installed or not on PATH')
    except subprocess.CalledProcessError as error:
        return _error((error.stderr or '').strip() or 'git failed')

    if args.update_baseline:
        existing = load_baseline(args.update_baseline)
        updated = existing | {fingerprint(finding) for finding in findings}
        save_baseline(args.update_baseline, updated)

        added = len(updated) - len(existing)
        print(f'Added {added} finding(s) to {args.update_baseline}')
        return 0

    if args.baseline:
        baseline = load_baseline(args.baseline)
    else:
        baseline = set()
        
    findings = filter_findings(findings, baseline)
    
    if args.output == 'json':
        print(format_json(findings))
    else:
        print(format_console(findings))
        
    return 1 if findings else 0

if __name__ == '__main__':
    sys.exit(main())