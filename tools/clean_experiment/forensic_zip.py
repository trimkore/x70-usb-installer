"""Read-only, standard-library ZIP forensics. Never invokes archive content."""
import argparse
import binascii
import difflib
import hashlib
import json
import mmap
from pathlib import Path
import re
import stat
import struct
import zlib

EXPECTED_SIZE = 922335035
EXPECTED_SHA = '2a41a4d0dc3b30a6d3e58216b6155fef38a04c4cd46871e512603d220bdc1329'
SIGS = {'eocd': b'PK\x05\x06', 'central': b'PK\x01\x02', 'local': b'PK\x03\x04',
        'zip64_end': b'PK\x06\x06', 'zip64_locator': b'PK\x06\x07', 'digital_signature': b'PK\x05\x05'}

def offsets(data, sig):
    start = 0
    while True:
        pos = data.find(sig, start)
        if pos < 0:
            return
        yield pos
        start = pos + 1

def digest(data, start=0, end=None, algorithm='sha256'):
    end = len(data) if end is None else end
    h = hashlib.new(algorithm)
    for p in range(start, end, 1024 * 1024):
        h.update(data[p:min(p + 1024 * 1024, end)])
    return h.hexdigest()

def safe_name(name):
    # Windows aliases, ADS, UNC, drive letters, device names, traversal.
    parts = name.replace('\\', '/').rstrip('/').split('/')
    if not parts or any(not p or p in ('.', '..') or p[-1:] in (' ', '.') or
                        re.search(r'[\x00-\x1f<>:"|?*]', p) or
                        re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', p)
                        for p in parts):
        raise ValueError('unsafe extraction path')
    return Path(*parts)

def local(data, pos):
    if pos < 0 or pos + 30 > len(data) or data[pos:pos+4] != SIGS['local']:
        raise ValueError('local header missing/out of bounds')
    v = struct.unpack_from('<4s5H3I2H', data, pos)
    end = pos + 30 + v[9] + v[10]
    if end > len(data):
        raise ValueError('local variable header out of bounds')
    return dict(offset=pos, flags=v[2], method=v[3], crc=v[6], compressed=v[7],
                size=v[8], name_hex=data[pos+30:pos+30+v[9]].hex(), data_start=end)

def directory(data, start, size, count, base):
    end = start + size
    if start < 0 or end > len(data) or count > 1000000:
        raise ValueError('central directory bounds/count')
    entries = []
    p = start
    for index in range(count):
        if p + 46 > end or data[p:p+4] != SIGS['central']:
            raise ValueError(f'central header missing at {p}')
        v = struct.unpack_from('<4s6H3I5H2I', data, p)
        q = p + 46 + v[10] + v[11] + v[12]
        if q > end:
            raise ValueError('central variable header out of bounds')
        raw = data[p+46:p+46+v[10]]
        e = dict(index=index, central=p, name=raw.decode('utf-8' if v[3]&2048 else 'cp437', errors='replace'),
                 flags=v[3], method=v[4], crc=v[7], compressed=v[8], size=v[9],
                 local_offset=v[16]+base, external=v[15], issues=[])
        if 0xffffffff in (v[8], v[9], v[16]) or v[13]:
            e['issues'].append('ZIP64 or split entry unsupported; not extracted')
        try:
            h = local(data, e['local_offset'])
            e['local'] = h
            for key in ('flags', 'method'):
                if h[key] != e[key]: e['issues'].append('local/central '+key+' mismatch')
            if h['name_hex'] != raw.hex(): e['issues'].append('local/central name mismatch')
            if not e['flags'] & 8:
                for key in ('crc', 'compressed', 'size'):
                    if h[key] != e[key]: e['issues'].append('local/central '+key+' mismatch')
            finish = h['data_start'] + e['compressed']
            e['data_end'] = finish
            if finish > start: e['issues'].append('payload crosses central directory')
            if e['flags'] & 8:
                d = finish + (4 if data[finish:finish+4] == b'PK\x07\x08' else 0)
                if d+12 > start or struct.unpack_from('<3I', data, d) != (e['crc'], e['compressed'], e['size']):
                    e['issues'].append('data descriptor mismatch/missing')
                else: e['descriptor_end'] = d+12
        except (ValueError, struct.error) as exc:
            e['issues'].append(str(exc))
        entries.append(e)
        p = q
    if p != end:
        raise ValueError(f'central size mismatch: parsed {p-start}, declared {size}')
    return entries

def parse(data):
    inventory = {k: list(offsets(data, v)) for k,v in SIGS.items()}
    result = dict(signatures=inventory, end_records=[], views=[], local_candidates=[])
    for pos in inventory['local']:
        try: result['local_candidates'].append(local(data, pos))
        except (ValueError, struct.error) as exc: result['local_candidates'].append(dict(offset=pos,error=str(exc)))
    for pos in inventory['eocd']:
        r = dict(offset=pos, errors=[])
        result['end_records'].append(r)
        if pos+22 > len(data):
            r['errors'].append('truncated EOCD'); continue
        _, disk, cd_disk, n_disk, n, size, off, comment = struct.unpack_from('<4s4H2IH',data,pos)
        r.update(count=n, central_size=size, central_offset=off, comment_size=comment, end=pos+22+comment)
        if r['end'] > len(data) or disk or cd_disk or n_disk != n or n == 65535 or size == 0xffffffff or off == 0xffffffff:
            r['errors'].append('invalid bounds, split archive, or unsupported ZIP64 EOCD'); continue
        # Test literal offsets AND concatenated/self-extracting archive relocation.
        for base in sorted({0, pos-size-off}):
            try:
                entries = directory(data, off+base, size, n, base)
                if off+base+size > pos: raise ValueError('directory overlaps EOCD')
                if not entries: raise ValueError('empty view is not extracted')
                view = dict(id=len(result['views']), eocd=pos, end=r['end'], base=base,
                            central_start=off+base, central_end=off+base+size, entries=entries)
                spans = sorted((e['local_offset'],e.get('descriptor_end',e.get('data_end',e['local_offset'])),e['index']) for e in entries)
                view['overlaps'] = [(a[2],b[2],b[0],min(a[1],b[1])) for i,a in enumerate(spans) for b in spans[i+1:] if b[0]<a[1]]
                result['views'].append(view)
            except (ValueError, struct.error) as exc:
                r['errors'].append(f'base {base}: {exc}')
    result['view_intersections'] = []
    for i,a in enumerate(result['views']):
        for b in result['views'][i+1:]:
            lo=max(min(e['local_offset'] for e in a['entries']),min(e['local_offset'] for e in b['entries']))
            hi=min(a['end'],b['end'])
            if lo<hi: result['view_intersections'].append(dict(views=[a['id'],b['id']],start=lo,end=hi))
    referenced = {e['local_offset'] for v in result['views'] for e in v['entries']}
    result['unreferenced_local_candidates'] = [p for p in inventory['local'] if p not in referenced]
    return result

def extract(data, view, root, max_entry=4*1024**3, max_total=12*1024**3):
    total = 0
    for e in view['entries']:
        try:
            if e['issues']: raise ValueError('; '.join(e['issues']))
            name = safe_name(e['name'])
            mode = e['external'] >> 16
            if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR)):
                raise ValueError('links/special files refused')
            if e['flags'] & 1: raise ValueError('encrypted entry unsupported')
            if e['size'] > max_entry or total+e['size'] > max_total: raise ValueError('extraction limit')
            total+=e['size']  # Reserve even for corrupt entries that leave partial evidence.
            # A separate numbered namespace preserves duplicates and case aliases.
            target = root / f"entry-{e['index']:05d}" / name
            if not target.resolve().is_relative_to(root.resolve()): raise ValueError('path escapes root')
            if e['name'].endswith('/'):
                target.mkdir(parents=True); e['extraction']='directory'; continue
            if e['method'] not in (0,8): raise ValueError('unsupported compression method')
            target.parent.mkdir(parents=True,exist_ok=True)
            dec = zlib.decompressobj(-15) if e['method']==8 else None
            crc=0; written=0; sha=hashlib.sha256()
            with target.open('xb') as out:
                for p in range(e['local']['data_start'], e['data_end'],65536):
                    block=data[p:min(p+65536,e['data_end'])]
                    if dec: block=dec.decompress(block,min(max_entry,e['size'])-written+1)
                    written+=len(block)
                    if written>e['size'] or written>max_entry: raise ValueError('expanded size limit')
                    out.write(block); sha.update(block); crc=binascii.crc32(block,crc)
                if dec and (not dec.eof or dec.unused_data or dec.unconsumed_tail): raise ValueError('invalid deflate boundary')
            if written!=e['size'] or crc!=e['crc']: raise ValueError('size/CRC mismatch')
            e.update(extraction='verified CRC and size',sha256=sha.hexdigest(),extracted=str(target))
        except (ValueError,OSError,zlib.error) as exc:
            e['extraction']='FAILED: '+str(exc)
    return total
