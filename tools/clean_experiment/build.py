"""Build a deterministic, unsigned two-entry OFFLINE experiment, never an installer release."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import subprocess
import tempfile
import zipfile

import forensic_zip as forensic
from elf_data import Elf
from verifier import manifest_stage, verify

NAMES = ('Manifest_SYS.xml', 'META-INF/com/google/android/update-binary')


def sha_file(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):
            h.update(block)
    return h.hexdigest()


def build_zip(target, payloads):
    if tuple(payloads) != NAMES:
        raise ValueError('exactly the two selected names in canonical order required')
    # Exclusive creation; never update or append to an existing archive.
    with target.open('xb') as stream, zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_STORED) as archive:
        for name, data in payloads.items():
            info = zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
            info.create_system=3
            info.external_attr=0o100644 << 16
            archive.writestr(info,data)


def validate_clean(path, payloads, extract_root):
    data=path.read_bytes()
    evidence=forensic.parse(data)
    if len(evidence['views']) != 1 or len(evidence['end_records']) != 1:
        raise ValueError('expected one ZIP directory/end record')
    view=evidence['views'][0]
    if view['base'] != 0 or view['end'] != len(data) or view['eocd']+22 != len(data):
        raise ValueError('comment, trailing bytes or relocated directory')
    if view['central_end'] != view['eocd'] or view['overlaps']:
        raise ValueError('directory gap/overlap')
    entries=view['entries']
    if tuple(e['name'] for e in entries) != NAMES:
        raise ValueError('duplicate, extra or reordered entry')
    cursor=0
    for e in entries:
        if e['issues'] or e['local_offset'] != cursor or e['method'] != 0 or e['flags']:
            raise ValueError('incorrect offsets, unsupported flags or noncontiguous payload')
        cursor=e['data_end']
    if cursor != view['central_start']:
        raise ValueError('extra bytes between payload and directory')
    forensic.extract(data,view,extract_root,max_entry=16*1024**2,max_total=32*1024**2)
    for e in entries:
        if e.get('extraction') != 'verified CRC and size':
            raise ValueError('CRC/extraction failed: '+e['name'])
        if e['sha256'] != hashlib.sha256(payloads[e['name']]).hexdigest():
            raise ValueError('extracted payload differs')
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None or archive.comment:
            raise ValueError('ZIP CRC or comment failure')
    return dict(status='pass',size=len(data),sha256=hashlib.sha256(data).hexdigest(),
                central_directories=1,comment_bytes=0,trailing_bytes=0,
                central_start=view['central_start'],central_end=view['central_end'],eocd=view['eocd'],
                entries=[{k:e[k] for k in ('name','local_offset','size','crc','sha256')} for e in entries])


def seven_zip_test(executable,path,log):
    run=subprocess.run([str(executable),'t','-bd','-bb0',str(path)],capture_output=True,text=True)
    text=run.stdout+run.stderr
    log.write_text(text,encoding='utf-8')
    ok=run.returncode==0 and 'Everything is Ok' in text and 'warning' not in text.lower()
    if not ok:
        raise ValueError('7-Zip test failed or produced warnings; see local log')
    return dict(status='pass',exit_code=run.returncode,extra_data_warnings=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--seven-zip',type=Path,required=True)
    parser.add_argument('--check-existing',action='store_true',help='recheck existing artifact without rewriting it')
    args=parser.parse_args()
    workspace=args.workspace.resolve()
    original=workspace/'input/update.zip'
    out=workspace/'output/clean-experiment'
    if not out.resolve().is_relative_to(workspace) or (out.exists() and not args.check_existing):
        raise ValueError('output must be a new directory inside the workspace')
    if not args.seven_zip.is_file():
        raise ValueError('7-Zip executable required before building')
    evidence=json.loads((workspace/'analysis/evidence.json').read_text())
    baseline=json.loads((workspace/'analysis/trace/verifier-model.json').read_text())
    if original.stat().st_size != forensic.EXPECTED_SIZE or sha_file(original) != forensic.EXPECTED_SHA:
        raise ValueError('original size/SHA256 does not match forensic original')
    selected=max(evidence['views'],key=lambda v:v['eocd'])
    if selected['end'] != original.stat().st_size or tuple(e['name'] for e in selected['entries']) != NAMES:
        raise ValueError('recorded selected view is not the expected final two-entry view')
    payloads={}
    with original.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as data:
        for e in selected['entries']:
            source=Path(e['extracted']).resolve()
            if not source.is_relative_to((workspace/'analysis').resolve()):
                raise ValueError('extracted evidence path outside local analysis')
            blob=source.read_bytes()
            if hashlib.sha256(blob).hexdigest() != e['sha256']:
                raise ValueError('extracted file hash changed: '+e['name'])
            if e['method'] != 0 or data[e['local']['data_start']:e['data_end']] != blob:
                raise ValueError('extracted payload differs from original selected entry')
            payloads[e['name']]=blob
    if b'<systemVersionCode>453</systemVersionCode>' not in payloads[NAMES[0]]:
        raise ValueError('unexpected manifest build')
    binary=payloads[NAMES[1]]
    if binary[:6] != b'\x7fELF\x01\x01' or binary[18:20] != b'\x28\0':
        raise ValueError('expected ELF32 little-endian ARM updater')
    all_entries=[e for v in evidence['views'] for e in v['entries']]
    def resource(name):
        e=next(e for e in all_entries if e['name']==name)
        path=Path(e['extracted']).resolve()
        if not path.is_relative_to((workspace/'analysis').resolve()) or sha_file(path)!=e['sha256']:
            raise ValueError('resource provenance/hash mismatch: '+name)
        return path
    key=resource('system/etc/keys')
    vold=resource('system/bin/vold')
    props=resource('system/build.prop').read_text()
    product=next(line.split('=',1)[1].strip() for line in props.splitlines() if line.startswith('ro.build.product='))
    constant=Elf(vold).read(0x5b708,20)
    if constant.hex()!=baseline['signature']['native_padding_hash_constant']:
        raise ValueError('padding constant differs from traced binary')
    out.mkdir(parents=True,exist_ok=args.check_existing)
    clean=out/'update.zip'
    try:
        if args.check_existing:
            with tempfile.TemporaryDirectory() as tmp:
                candidate=Path(tmp)/'candidate.zip'
                build_zip(candidate,payloads)
                if not clean.is_file() or clean.read_bytes()!=candidate.read_bytes():
                    raise ValueError('existing artifact is not the deterministic build')
                structure=validate_clean(clean,payloads,Path(tmp)/'extract')
        else:
            build_zip(clean,payloads)
            structure=validate_clean(clean,payloads,out/'extracted')
        seven=seven_zip_test(args.seven_zip,clean,out/'7zip-test.txt')
        original_result=verify(original,key,product,constant)
        clean_result=verify(clean,key,product,constant)
        if original_result['stages']['rsa_signature'].get('sha1')!=baseline['signature']['sha1']:
            raise ValueError('original model diverges from recorded signed digest')
        result=dict(original=original_result,clean=clean_result,clean_structure=structure,seven_zip=seven,
                    independent_clean_manifest=manifest_stage(clean,product),
                    note='Independent clean ZIP/manifest checks do not imply those gates were reached after authentication.')
        (out/'results.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps(result,indent=2))
    finally:
        after=sha_file(original)
        (out/'original-integrity.json').write_text(json.dumps(dict(size=original.stat().st_size,sha256=after,
                                                                  unchanged=after==forensic.EXPECTED_SHA),indent=2))
        if after!=forensic.EXPECTED_SHA:
            raise ValueError('original integrity check failed')


if __name__=='__main__':
    main()
