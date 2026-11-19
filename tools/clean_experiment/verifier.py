"""Offline model derived from model_verifier.py and the package Thumb trace.

No target code is loaded or executed. This models the observed v2 key and regular
update.zip route only, not runtime I/O, Java preflight or installed-device trust.
"""
import hashlib
import mmap
import re
import struct
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

from forensic_zip import directory, digest, extract


def load_key(path):
    text = path.read_text()
    m = re.fullmatch(r'\s*v2\s*\{64,(0x[\da-fA-F]+),\{([^}]+)\},\{([^}]+)\}\}\s*', text)
    if not m:
        raise ValueError('model supports only the observed single v2 RSA-2048 key')
    words = [int(x) for x in m[2].split(',')]
    rr = [int(x) for x in m[3].split(',')]
    if len(words) != 64 or len(rr) != 64 or any(not 0 <= x < 2**32 for x in words + rr):
        raise ValueError('invalid key limbs')
    n = sum(x << (32*i) for i, x in enumerate(words))
    if n <= 0 or sum(x << (32*i) for i, x in enumerate(rr)) != pow(2,4096,n):
        raise ValueError('invalid Montgomery RR')
    if int(m[1],16) * words[0] % 2**32 != 2**32-1:
        raise ValueError('invalid Montgomery n0inv')
    return n


def md5_stage(data, project=b'xe1115h'):
    if len(data) < 196:
        return dict(status='fail', return_code=-1, reason='cannot seek 196 bytes before EOF')
    trailer = data[-196:]
    if b'\0' not in trailer:
        return dict(status='unsupported', reason='unterminated C trailer: native behavior not safely modeled')
    text = trailer.split(b'\0',1)[0]
    pos = text.find(b'##project:')
    if pos < 0:
        return dict(status='continue_without_md5', return_code=1, signature_suffix=0, reason='project marker absent')
    if text[pos+10:pos+10+len(project)] != project:
        return dict(status='fail', return_code=-1, reason='project prefix mismatch')
    pos = text.find(b'##md5:')
    if pos < 0:
        return dict(status='continue_without_md5', return_code=1, signature_suffix=0, reason='MD5 marker absent')
    value = digest(data,0,len(data)-196,'md5')
    ok = text[pos+6:pos+38] == value.encode()
    return dict(status='pass' if ok else 'fail', return_code=0 if ok else -1,
                signature_suffix=196, range=[0,len(data)-196], computed=value)


def signature_stage(data, suffix, modulus, padding_constant):
    end = len(data)-suffix
    if end < 6:
        return dict(status='fail', reason='short footer')
    footer = data[end-6:end]
    result = dict(status='fail', footer_hex=footer.hex(), logical_end=end)
    distance, magic, comment = struct.unpack('<H2sH',footer)
    if magic != b'\xff\xff':
        return dict(result, reason='footer marker is not ff ff; RSA not attempted')
    if ((distance-6) & 0xffffffff) <= 255:
        return dict(result, reason='signature distance too short')
    eocd = end-comment-22
    if eocd < 0 or data[eocd:eocd+4] != b'PK\x05\x06':
        return dict(result, reason='footer-derived EOCD missing')
    if data.find(b'PK\x05\x06',eocd+4,end) >= 0:
        return dict(result, reason='additional EOCD in checked logical region')
    if comment < 240 or end < 262:
        return dict(status='unsupported', reason='signature pointer outside native allocation')
    sha = bytes.fromhex(digest(data,0,eocd+20,'sha1'))
    recovered = pow(int.from_bytes(data[end-262:end-6],'big'),65537,modulus).to_bytes(256,'big')
    info = bytes.fromhex('3021300906052b0e03021a05000414')+sha
    expected = b'\0\1'+b'\xff'*(253-len(info))+b'\0'+info
    native_block = recovered[:-20]+bytes(a^b for a,b in zip(recovered[-20:],sha))
    native_ok = hashlib.sha1(native_block).digest() == padding_constant
    return dict(result, status='pass' if native_ok else 'fail', reason='native RSA padding hash comparison',
                signed_range=[0,eocd+20], sha1=sha.hex(), signature_range=[end-262,end-6],
                pkcs1_sha1_match=recovered==expected, native_padding_match=native_ok)


def native_zip(data):
    if data[:4] != b'PK\x03\x04':
        raise ValueError('initial local header missing')
    eocd = data.rfind(b'PK\x05\x06',0,len(data)-18)
    if eocd < 0:
        raise ValueError('EOCD missing')
    count = struct.unpack_from('<H',data,eocd+8)[0]
    size, start = struct.unpack_from('<II',data,eocd+12)
    entries = directory(data,start,size,count,0)
    if any(e['issues'] for e in entries):
        raise ValueError('entry validation issues')
    return dict(status='pass', eocd=eocd, central_start=start,
                entries=[e['name'] for e in entries])


def manifest_stage(path, product):
    # zipfile.ZipFile guesses a concatenation adjustment for gaps before EOCD.
    # Native mzOpenZipArchive uses the literal offsets, including on the original.
    with path.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
        info=native_zip(data)
        pos=info['eocd']
        count=struct.unpack_from('<H',data,pos+8)[0]
        size,start=struct.unpack_from('<II',data,pos+12)
        matches=[e for e in directory(data,start,size,count,0) if e['name']=='Manifest_SYS.xml']
        if len(matches)!=1:
            raise ValueError('model requires exactly one selected manifest')
        entry=matches[0]
        with tempfile.TemporaryDirectory() as tmp:
            extract(data,dict(entries=matches),Path(tmp),max_entry=1024**2,max_total=1024**2)
            if entry.get('extraction')!='verified CRC and size':
                raise ValueError('manifest extraction/CRC failed')
            raw=Path(entry['extracted']).read_bytes()
    # Exact observed manifest is ASCII, so GB2312 vs UTF-8 makes no difference.
    # Do not pretend ElementTree reproduces libxml2 for arbitrary encodings/DTD.
    if not raw.isascii() or b'<!DOCTYPE' in raw.upper():
        return dict(status='unsupported', reason='model only supports observed ASCII manifest without DTD')
    root = ET.fromstring(raw)
    project = root.findtext('project')
    ok = root.tag == 'sys_info' and project is not None and product in project
    return dict(status='pass' if ok else 'fail', reason='sys_info root and project substring',
                build=root.findtext('systemVersionCode'), version_checked=False)


def verify(path, key_path, product, padding_constant):
    stages = {k:dict(status='not_reached') for k in ('trailer_md5','key_loading','rsa_signature','zip','manifest')}
    result = dict(stages=stages, first_failing_gate=None, updater_dispatch_reachable=False,
                  updater_executed=False, scope='package-version offline model; successful I/O assumed')
    with path.open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
        result.update(size=len(data),sha256=digest(data))
        stages['trailer_md5'] = md5_stage(data)
        if stages['trailer_md5']['status'] in ('fail','unsupported'):
            result['first_failing_gate']='trailer_md5'; return result
        try:
            modulus = load_key(key_path)
            stages['key_loading'] = dict(status='pass', type='v2 RSA-2048 SHA1')
        except (OSError,ValueError) as exc:
            stages['key_loading']=dict(status='fail',reason=str(exc))
            result['first_failing_gate']='key_loading'; return result
        stages['rsa_signature']=signature_stage(data,stages['trailer_md5']['signature_suffix'],modulus,padding_constant)
        if stages['rsa_signature']['status'] != 'pass':
            result['first_failing_gate']='rsa_signature'; return result
        try:
            stages['zip']=native_zip(data)
        except (ValueError,struct.error) as exc:
            stages['zip']=dict(status='fail',reason=str(exc))
            result['first_failing_gate']='zip'; return result
    try:
        stages['manifest']=manifest_stage(path,product)
    except (OSError,ValueError,KeyError,zipfile.BadZipFile,ET.ParseError) as exc:
        stages['manifest']=dict(status='fail',reason=str(exc))
    if stages['manifest']['status'] != 'pass':
        result['first_failing_gate']='manifest'
    else:
        result['updater_dispatch_reachable']=True
    return result
