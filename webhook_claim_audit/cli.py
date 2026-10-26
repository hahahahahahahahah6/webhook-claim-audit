"""Command line interface."""
import argparse
import json
import sys
from . import __version__
from .core import audit


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, self.prog + ': error: ' + message + '\n')


def main(argv=None):
    parser = Parser(prog='webhook-claim-audit')
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', nargs='+', action='extend', default=[])
    parser.add_argument('--fail-on', choices=('HIGH', 'MEDIUM'), default='MEDIUM')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.ignore, args.fail_on)
    except (OSError, ValueError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result['status'])
        for finding in result['findings']:
            print(finding['rule'] + ' ' + finding['severity'] +
                  (' ' + finding['path'] if args.verbose else ''))
        if args.verbose:
            for item in result['evidence']:
                print('evidence ' + item['path'] + ':' + str(item['line']))
    return 2 if result['status'] == 'FAIL' else 0
