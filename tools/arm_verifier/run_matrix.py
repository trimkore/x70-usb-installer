"""Reproduce the diagnostic matrix in an existing private workspace."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    cases = [
        ('clean', 'baseline', 'zip', False),
        ('original', 'baseline', 'zip', False),
        ('clean', 'baseline', 'install', False),
        ('original', 'baseline', 'install', False),
        ('original', 'baseline', 'install', True),
        ('original', 'key-denied', 'install', False),
        ('original', 'manifest-denied', 'install', False),
        ('original', 'package-denied', 'install', False),
        ('clean', 'status-denied', 'install', False),
        ('original', 'stale-status', 'install', True),
    ]
    for package, scenario, entry, xml in cases:
        name = f'{package}-{scenario}-{entry}' + ('-xml-shim' if xml else '')
        output = workspace / 'analysis' / 'emulation' / 'final' / (name + '.json')
        command = [sys.executable, str(Path(__file__).with_name('harness.py')),
                   '--workspace', str(workspace), '--package', package,
                   '--scenario', scenario, '--entry', entry, '--out', str(output)]
        if xml:
            command.append('--xml-shim')
        subprocess.run(command, check=True)
        result = json.loads(output.read_text(encoding='utf-8'))
        if not result['source_unchanged'] or not result['disposable_copy_unchanged']:
            raise RuntimeError('Input integrity check failed')


if __name__ == '__main__':
    main()
