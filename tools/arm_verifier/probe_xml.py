"""Offline native ICU/XML fixtures; requires a private, extracted workspace."""
import argparse
import json
from pathlib import Path
import tempfile
from harness import Harness, UC_ARM_REG_SP
from native_icu import attach


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', required=True, type=Path)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    entries = [e for v in json.loads((workspace / 'analysis/evidence.json').read_text())['views'] for e in v['entries']]
    vold = Path(next(e['extracted'] for e in entries if e['name'] == 'system/bin/vold'))
    fixtures = {'valid': b'<sys_info><project>xe1115h</project></sys_info>',
                'empty': b'', 'unclosed': b'<sys_info><project>xe1115h</project>'}
    for name, contents in fixtures.items():
        with tempfile.TemporaryDirectory(prefix='x70-native-xml-') as tmp:
            root = Path(tmp)
            (root / 'data').mkdir()
            (root / 'data/Manifest.xml').write_bytes(contents)
            package = root / 'unused-package'
            package.write_bytes(b'')
            h = Harness(vold, workspace / 'analysis/trace/vold-symbols.txt', root, package)
            exports, data, _ = attach(h, entries, vold)
            status = h.alloc(4)
            initialization = h.run(exports['udata_setCommonData_51'], [data, status])
            if initialization['outcome']['kind'] != 'returned' or h.u32(status):
                raise RuntimeError('Native ICU initialization did not complete')
            h.stopped = None
            h.returns = {}
            h.uc.reg_write(UC_ARM_REG_SP, 0x710ff000)
            parsed = h.run(0x392f6, [h.cstr('/data/Manifest.xml'), h.cstr('GB2312'), 1])
            result = {'fixture': name, 'xml_result': parsed['outcome'], 'trace': parsed}
            if parsed['outcome']['kind'] == 'returned' and parsed['outcome']['result']:
                h.stopped = None
                h.returns = {}
                h.uc.reg_write(UC_ARM_REG_SP, 0x710ff000)
                rooted = h.run(0x3a928, [parsed['outcome']['result']])
                result['root_result'] = rooted['outcome']
                result['root_trace'] = rooted
            output = workspace / 'analysis/emulation/icu' / ('fixture-' + name + '.json')
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, indent=2), encoding='utf-8')
            print(name, result['xml_result'], result.get('root_result'))
            assert result.get('root_result', {}).get('kind') == 'returned'
            assert (result['root_result']['result'] != 0) == (name != 'empty')


if __name__ == '__main__':
    main()
