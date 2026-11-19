"""Pinned ICU module mapping for CPU-only probes, never a host dynamic load."""
import hashlib
import struct
from pathlib import Path

PINS = {
 'system/lib/libc.so': 'dcb24102f4523d6c2970c1d9c8476e67acbcc7bcbc9b0ea08dbd0f92eb82ffa7',
 'system/lib/libicuuc.so': 'c84bb4458d7271561e1668ebb86967b2166ca2ed476d39397d0fbec161663259',
 'system/lib/libgabi++.so': '6ad9f04258548affa353cfd764f8a4463cbd573a2671312ef47f198d37db73ce',
 'system/usr/icu/icudt51l.dat': '969555364a79de1d2efc6fb1ef4aaeefc1d9328012164ecdf9f1691fa53e2cde',
}

class Elf:
 def __init__(self, data):
  self.data=data
  if data[:6]!=b'\x7fELF\x01\x01' or struct.unpack_from('<H',data,18)[0]!=40:raise ValueError('Expected ELF32 LE ARM')
  off=struct.unpack_from('<I',data,32)[0];size,n=struct.unpack_from('<HH',data,46)
  self.sections=[struct.unpack_from('<10I',data,off+i*size) for i in range(n)]
  self.symbols=[]
  for sec in self.sections:
   if sec[1]!=11:continue
   strings=self.sections[sec[6]]
   for i in range(sec[4],sec[4]+sec[5],sec[9]):
    name,value,size,info,other,index=struct.unpack_from('<IIIBBH',data,i);at=strings[4]+name
    self.symbols.append(dict(name=data[at:data.index(0,at)].decode(),value=value,size=size,kind=info&15,index=index))
 def segments(self):
  off=struct.unpack_from('<I',self.data,28)[0];size,n=struct.unpack_from('<HH',self.data,42)
  for i in range(n):yield struct.unpack_from('<8I',self.data,off+i*size)
 def relocations(self):
  for sec in self.sections:
   if sec[1]!=9:continue
   for i in range(sec[4],sec[4]+sec[5],8):
    target,info=struct.unpack_from('<II',self.data,i);yield target,info&255,info>>8
 def initializers(self):
  for sec in self.sections:
   if sec[1]==6:
    for tag,value in struct.iter_unpack('<II',self.data[sec[4]:sec[4]+sec[5]]):
     if tag in (12,25) and value:yield tag,value


def attach(h,entries,vold):
 from unicorn import UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
 files={}
 for name,pin in PINS.items():
  entry=next(e for e in entries if e['name']==name);data=Path(entry['extracted']).read_bytes()
  if hashlib.sha256(data).hexdigest()!=pin or entry['sha256']!=pin:raise ValueError('ICU provenance mismatch: '+name)
  files[name]=data
 exports={s['name']:s['value'] for s in Elf(vold.read_bytes()).symbols if s['index']}
 for symbol,alias in {'__aeabi_idiv':'idiv','__aeabi_idivmod':'idivmod','__aeabi_uidiv':'uidiv','__aeabi_uidivmod':'uidivmod'}.items():
  address=next((address for address,name in h.hooks.items() if name in (alias,'unsupported_import:'+symbol)),None)
  if address is not None:h.hooks[address]=alias;exports[symbol]=address
 modules=[]
 for i,name in enumerate(('system/lib/libicuuc.so','system/lib/libgabi++.so','system/lib/libc.so')):
  base=0x60000000+i*0x00800000;elf=Elf(files[name]);pages={}
  data_only=name=='system/lib/libc.so'
  if not data_only and list(elf.initializers()):raise ValueError('Native module initializer needs explicit support: '+name)
  for typ,off,va,pa,fs,ms,flags,align in elf.segments():
   if typ!=1:continue
   perms=(UC_PROT_READ if flags&4 else 0)|(UC_PROT_WRITE if flags&2 else 0)|(UC_PROT_EXEC if flags&1 else 0)
   if data_only:perms &= ~UC_PROT_EXEC
   for page in range((base+va)&~4095,(base+va+ms+4095)&~4095,4096):pages[page]=pages.get(page,0)|perms
   if flags&1 and not data_only:h.exec_ranges.append((base+va,base+va+ms))
  for page,perms in pages.items():h.uc.mem_map(page,4096,perms)
  for typ,off,va,pa,fs,ms,flags,align in elf.segments():
   if typ==1:h.uc.mem_write(base+va,elf.data[off:off+fs])
  for sym in elf.symbols:
   if sym['index'] and (not data_only or sym['name'] in ('_toupper_tab_','_C_toupper_')):exports.setdefault(sym['name'],base+sym['value'])
  modules.append((name,base,elf))
  h.events.append(dict(event='native_module',origin='package_matched_native_library',name=name,base=hex(base),sha256=PINS[name],data_only=data_only,initializers='not run; only static toupper data exposed' if data_only else []))
 # Unresolved objects have unmapped addresses: any use stops, never dummy data.
 unresolved={};next_guard=0x69000000
 for name,base,elf in modules:
  for target,typ,index in elf.relocations():
   address=base+target;addend=h.u32(address)
   if typ==23:value=base+addend
   elif typ in (2,21,22):
    sym=elf.symbols[index];symbol=sym['name']
    value=base+sym['value'] if sym['index'] else exports.get(symbol)
    if value is None:
     if symbol not in unresolved:unresolved[symbol]=next_guard;next_guard+=4096
     value=unresolved[symbol]
    if typ==2:value+=addend
   else:raise ValueError('Unsupported relocation '+str(typ))
   h.put32(address,value)
 # Resolve vold data imports, including native ICU callback pointers and the
 # package libc static uppercase table. No libc initializer-dependent data exposed.
 original=Elf(vold.read_bytes())
 for target,typ,index in original.relocations():
  if typ==21:
   sym=original.symbols[index]
   if not sym['index'] and sym['name'] in exports:h.put32(target,exports[sym['name']])
 # Replace only ICU imports, with jumps to the matching native implementations.
 for address,name in list(h.hooks.items()):
  if name.startswith('unsupported_import:ucnv_'):
   symbol=name.split(':',1)[1]
   if symbol not in exports:raise ValueError('ICU missing '+symbol)
   h.hooks[address]='native_redirect:'+str(exports[symbol])
 h.events.append(dict(event='unresolved_native_dependencies',origin='loader_guard_configuration',symbols={k:hex(v) for k,v in unresolved.items()},policy='Unmapped addresses; any use stops execution'))
 data=files['system/usr/icu/icudt51l.dat'];base=0x58000000
 h.uc.mem_map(base,(len(data)+4095)&~4095,UC_PROT_READ);h.uc.mem_write(base,data)
 h.events.append(dict(event='icu_data',origin='package_data_readonly_NX_mapping',address=hex(base),size=len(data),sha256=PINS['system/usr/icu/icudt51l.dat']))
 h.extra_read_roots=('/system/usr/icu/','/usr/icu/')
 destination=h.root/'system/usr/icu/icudt51l.dat';destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(data)
 return exports,base,unresolved
