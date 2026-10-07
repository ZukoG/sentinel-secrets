import argparse
import sys

from .git_walker import walk_history, walk_working_tree
from .baseline import filter_findings, load_baseline
from .report import format_console, format_json

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Scan a Git repository for exposed secrets.'
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    
    findings = walk_working_tree(args.repo_path)
    
    if args.history:
        findings += walk_history(args.repo_path)
        
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