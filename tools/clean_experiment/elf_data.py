"""ELF data reader reused from the local trace_native.py; never loads code."""
from pathlib import Path
import struct

class Elf:
    def __init__(self,path):
        self.data=Path(path).read_bytes(); b=self.data
        phoff=struct.unpack_from('<I',b,28)[0]; size,count=struct.unpack_from('<HH',b,42)
        self.loads=[]
        for i in range(count):
            t,off,va,pa,fs,ms,flags,align=struct.unpack_from('<8I',b,phoff+i*size)
            if t==1:self.loads.append((va,off,fs))
    def read(self,va,n):
        for start,off,size in self.loads:
            if start<=va and va+n<=start+size:return self.data[off+va-start:off+va-start+n]
        return b''
    def u32(self,va):
        b=self.read(va,4); return struct.unpack('<I',b)[0] if len(b)==4 else None
    def string(self,va):
        b=self.read(va,1)
        if not b:return ''
        out=bytearray()
        for i in range(500):
            c=self.read(va+i,1)
            if c==b'\0':break
            if not c or (c[0]<32 and c[0] not in (9,10,13)) or c[0]>126:return ''
            out+=c
        return out.decode() if len(out)>=3 else ''
