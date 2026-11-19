"""CPU-only ARM verifier experiment. No guest syscall passthrough or payload execution.

Only the pinned, package-version vold is supported. libc/file operations and
hash compression are host shims; verifier control flow, ZIP, extraction and RSA
execute ARM instructions. XML may be explicitly shimmed; results disclose this.
"""
import argparse
import collections
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile
import time
import xml.etree.ElementTree as ET

from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_BLOCK, UC_HOOK_INTR, UC_HOOK_MEM_INVALID, UC_MEM_READ_UNMAPPED, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR, UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC

REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
STAGES={0x15058:'status_write',0x14a90:'file_size',0x17404:'rsa',0x15474:'install',0x145e8:'md5',0x15bf0:'load_keys',0x15850:'signature',0x17e70:'zip',0x14bc8:'manifest',0x150c8:'dispatch'}
PAGE=4096
PINNED_VOLD='81f66d4556225a9174efc5fbe5bc047acdbff7850d50dc9435e0cd8ca3ddc40e'


class Unsupported(RuntimeError): pass


class Harness:
    def __init__(self,binary,symbols,root,package,scenario='baseline',xml_shim=False):
        self.uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
        self.root=root.resolve();self.package=package;self.scenario=scenario;self.xml_shim=xml_shim
        self.events=[];self.counts=collections.Counter();self.fd={};self.nextfd=20;self.allocations={};self.heap=0x10000000
        self.hash_bytes=collections.Counter();self.hashes={};self.file_maps=[];self.file_pages=set();self.returns={};self.stopped=None;self.xml_nodes={}
        self.recent=collections.deque(maxlen=20)
        self.visible_status=997 if scenario=='stale-status' else 0
        self.first_failure=None
        self.stage_inputs={}
        b=binary.read_bytes()
        if hashlib.sha256(b).hexdigest()!=PINNED_VOLD:raise ValueError('unsupported verifier binary; address map is pinned')
        phoff=struct.unpack_from('<I',b,28)[0];phsize,phnum=struct.unpack_from('<HH',b,42)
        self.exec_ranges=[]
        pages={}
        for i in range(phnum):
            typ,off,va,pa,fs,ms,flags,align=struct.unpack_from('<8I',b,phoff+i*phsize)
            if typ!=1:continue
            perms=(UC_PROT_READ if flags&4 else 0)|(UC_PROT_WRITE if flags&2 else 0)|(UC_PROT_EXEC if flags&1 else 0)
            for p in range(va&~4095,(va+ms+4095)&~4095,4096):pages[p]=pages.get(p,0)|perms
            if flags&1:self.exec_ranges.append((va,va+ms))
        for p,perms in pages.items():self.uc.mem_map(p,PAGE,perms)
        for i in range(phnum):
            typ,off,va,pa,fs,ms,flags,align=struct.unpack_from('<8I',b,phoff+i*phsize)
            if typ==1:self.uc.mem_write(va,b[off:off+fs])
        self.uc.mem_map(0x10000000,0x08000000,UC_PROT_READ|UC_PROT_WRITE)
        self.uc.mem_map(0x70000000,PAGE,UC_PROT_READ|UC_PROT_EXEC)
        self.uc.mem_map(0x71000000,0x100000,UC_PROT_READ|UC_PROT_WRITE)
        self.uc.reg_write(UC_ARM_REG_SP,0x710ff000)
        self.uc.reg_write(UC_ARM_REG_C1_C0_2,0xf00000)
        self.uc.reg_write(UC_ARM_REG_FPEXC,0x40000000)
        self.errno=self.alloc(4)
        self.hooks={}
        names={m[2]:int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8})\s+g\s+DF\s+\S+\s+[0-9a-f]+\s+(\S+)',symbols.read_text(),re.M)}
        libc=['malloc','calloc','realloc','free','memset','memcpy','memmove','__memcpy_chk','strlen','__strlen_chk','strcmp','strncmp','memcmp','strstr','strchr','strcpy','strncpy','__strncpy_chk','strdup','fopen','fclose','fseek','ftell','fread','fwrite','fscanf','fgetc','getc','feof','open','creat','read','write','close','lseek','fstat','mmap','munmap','unlink','remove','chmod','fchmod','access','__errno','strerror','fprintf','printf','puts','__sprintf_chk','sprintf','snprintf','pipe','fork','execv','execve','execvp','system','reboot','exit','_exit','__stack_chk_fail','qsort','fflush','time','stat','lstat']
        for name in libc:
            if names.get(name):self.hooks[names[name]&~1]=name
        self.hooks.update({0x8090:'android_log',0x80a8:'property_get',0x8174:'property_set',
                           0x14400:'md5_init',0x1440c:'md5_update',0x14420:'md5_final',
                           0x17730:'sha1_init',0x17768:'sha1_update',0x177a0:'sha1_final',0x17844:'sha1_one',
                           0x178a0:'sha256_init',0x178f4:'sha256_update',0x17a98:'sha256_final',0x17b38:'sha256_one'})
        # Name every unresolved import so a missing shim stops explicitly.
        shoff=struct.unpack_from('<I',b,32)[0];shsize,shnum=struct.unpack_from('<HH',b,46)
        sections=[struct.unpack_from('<10I',b,shoff+i*shsize) for i in range(shnum)]
        for sec in sections:
            if sec[1]!=9:continue
            dyn=sections[sec[6]];strings=sections[dyn[6]]
            for off in range(sec[4],sec[4]+sec[5],8):
                target,info=struct.unpack_from('<II',b,off)
                if info&255!=22:continue
                symoff=dyn[4]+(info>>8)*dyn[9];nameoff=struct.unpack_from('<I',b,symoff)[0]+strings[4]
                name=b[nameoff:b.index(0,nameoff)].decode()
                address=0x8090+12*((target-0x62f14)//4)
                aliases={'__aeabi_uidiv':'uidiv','__aeabi_uidivmod':'uidivmod','__aeabi_idiv':'idiv','__android_log_buf_print':'android_log','__android_log_print':'android_log_print'}
                if address not in self.hooks:self.hooks[address]=aliases.get(name,name if name in libc or name in ('property_get','property_set') else 'unsupported_import:'+name)
        if xml_shim:self.hooks.update({0x392f6:'xml_read',0x3a928:'xml_root',0x3c526:'xml_content',0x3a3bc:'xml_free_doc',0x413c2:'strcmp'})
        self.uc.hook_add(UC_HOOK_BLOCK,self.block)
        self.uc.hook_add(UC_HOOK_INTR,self.intr)
        self.uc.hook_add(UC_HOOK_MEM_INVALID,self.invalid)

    def alloc(self,n):
        if n>32*1024**2:raise Unsupported('allocation too large')
        p=self.heap;self.heap+=(max(n,1)+15)&~15
        if self.heap>=0x18000000:raise Unsupported('heap budget exceeded')
        self.allocations[p]=n;return p

    def string(self,p):
        if not p:return b''
        result=bytearray()
        for i in range(65536):
            c=self.readmem(p+i,1)
            if c==b'\0':return bytes(result)
            result+=c
        raise Unsupported('unterminated guest string')

    def cstr(self,s):
        if isinstance(s,str):s=s.encode()
        p=self.alloc(len(s)+1);self.uc.mem_write(p,s+b'\0');return p

    def readmem(self,p,n):
        for base,length,path,offset in self.file_maps:
            if base<=p and p+n<=base+length:
                for page in range(p&~4095,(p+n+4095)&~4095,4096):self.map_page(page,base,path,offset)
        return bytes(self.uc.mem_read(p,n))

    def map_page(self,page,base,path,offset):
        if page in self.file_pages:return
        with path.open('rb') as f:f.seek(page-base+offset);data=f.read(PAGE)
        self.uc.mem_map(page,PAGE,UC_PROT_READ);self.uc.mem_write(page,data);self.file_pages.add(page)

    def invalid(self,uc,access,address,size,value,unused):
        if access==UC_MEM_READ_UNMAPPED:
            for base,length,path,offset in self.file_maps:
                if base<=address and address+size<=base+length:
                    self.map_page(address&~4095,base,path,offset);return True
        self.stopped=dict(kind='unsupported_memory',access=access,address=hex(address),pc=hex(uc.reg_read(UC_ARM_REG_PC)))
        return False

    def intr(self,uc,number,unused):
        self.stopped=dict(kind='blocked_guest_interrupt',number=number,pc=hex(uc.reg_read(UC_ARM_REG_PC)))
        uc.emu_stop()

    def arg(self,i):
        return self.uc.reg_read(REGS[i]) if i<4 else self.u32(self.uc.reg_read(UC_ARM_REG_SP)+4*(i-4))

    def u32(self,p):return struct.unpack('<I',self.readmem(p,4))[0]
    def put32(self,p,n):self.uc.mem_write(p,struct.pack('<I',n&0xffffffff))
    def signed(self,n):return n if n<2**31 else n-2**32
    def ret(self,n=0):
        self.uc.reg_write(UC_ARM_REG_R0,n&0xffffffff);self.uc.reg_write(UC_ARM_REG_PC,self.uc.reg_read(UC_ARM_REG_LR))

    def path(self,guest,write=False):
        name=guest.decode('utf-8','strict')
        if name=='/mnt/udisk/update/update.zip':
            if write:raise Unsupported('package write blocked')
            return self.package
        allowed={'/system/etc/keys','/data/Manifest.xml','/data/updater','/sys/devices/platform/debug_control/percent_write','/sys/devices/platform/debug_control/percent_read'}
        if name not in allowed:raise Unsupported('unmapped guest path: '+name)
        if write and name=='/system/etc/keys':raise Unsupported('key write blocked')
        p=(self.root/name.lstrip('/')).resolve()
        if not p.is_relative_to(self.root):raise Unsupported('path escape')
        return p

    def open_file(self,p,mode):
        guest=self.string(p);writing=any(x in mode for x in 'wa+')
        path=self.path(guest,writing)
        if (self.scenario=='manifest-denied' and guest==b'/data/Manifest.xml' and writing) or (self.scenario=='key-denied' and guest==b'/system/etc/keys') or (self.scenario=='status-denied' and b'percent_' in guest):
            self.events.append(dict(event='io_open',origin='host_fault_injection',path=guest.decode(),mode=mode,return_code=-1,errno=13))
            self.put32(self.errno,13);return 0
        if self.scenario=='package-denied' and guest==b'/mnt/udisk/update/update.zip':
            self.events.append(dict(event='io_open',origin='host_fault_injection',path=guest.decode(),mode=mode,return_code=-1,errno=13))
            self.put32(self.errno,13);return 0
        try:
            f=path.open(mode)
        except OSError:
            self.put32(self.errno,2);return 0
        fd=self.nextfd;self.nextfd+=1;self.fd[fd]=(f,path,guest)
        self.events.append(dict(event='io_open',origin='host_io_shim',path=guest.decode(),mode=mode,return_code=fd));return fd

    def format(self,fmt,start):
        index=start
        def sub(m):
            nonlocal index
            t=m[0]
            if t=='%%':return '%'
            value=self.arg(index);index+=1
            if t.endswith('s'):return self.string(value).decode('utf-8','replace')
            if t.endswith(('x','X')):return format(value, '02x' if '02' in t else 'x')
            return str(self.signed(value) if t.endswith('d') else value)
        return re.sub(r'%%|%[-+0-9.*hlz]*[sduxcXp]',sub,fmt.decode('utf-8','replace')).encode()

    def fscanf(self):
        stream=self.fd[self.arg(0)][0];fmt=self.string(self.arg(1)).decode();start=stream.tell();data=stream.read(8192).decode('ascii');pos=0;i=0;count=0;arg=2
        while i<len(fmt):
            if fmt[i].isspace():
                while pos<len(data) and data[pos].isspace():pos+=1
                i+=1;continue
            if fmt[i]!='%':
                if pos>=len(data) or data[pos]!=fmt[i]:break
                pos+=1;i+=1;continue
            typ=fmt[i+1];i+=2
            if typ=='c':
                if pos>=len(data):break
                self.uc.mem_write(self.arg(arg),data[pos].encode());pos+=1
            else:
                m=re.match(r'\s*([+-]?(?:0[xX][0-9a-fA-F]+|[0-9a-fA-F]+))',data[pos:])
                if not m:break
                val=int(m[1],16 if typ=='x' or m[1].lower().startswith('0x') else 10)
                self.put32(self.arg(arg),val);pos+=len(m[0])
            arg+=1;count+=1
        stream.seek(start+pos);return count

    def xml_read(self):
        path=self.path(self.string(self.arg(0)))
        if self.scenario=='xml-fail':return 0
        root=ET.fromstring(path.read_bytes())
        def node(element):
            p=self.alloc(64);self.put32(p+8,self.cstr(element.tag));self.xml_nodes[p]=''.join(element.itertext())
            children=[node(c) for c in element]
            if children:self.put32(p+12,children[0])
            for a,b in zip(children,children[1:]):self.put32(a+24,b)
            return p
        p=node(root);doc=self.alloc(32);self.xml_nodes[doc]=p;return doc

    def shim(self,name):
        a,b,c,d=[self.arg(i) for i in range(4)]
        self.counts[name]+=1
        if name=='time':
            value=1700000000
            if a:self.put32(a,value)
            self.events.append(dict(event='time',origin='host_runtime_shim',return_code=value))
            return self.ret(value)
        if name in ('uidiv','uidivmod','idiv'):
            x,y=(self.signed(a),self.signed(b)) if name=='idiv' else (a,b)
            if y==0:raise Unsupported('division by zero')
            q=abs(x)//abs(y)*(1 if x*y>=0 else -1)
            if name=='uidivmod':self.uc.reg_write(UC_ARM_REG_R1,x-q*y)
            return self.ret(q)
        if name in ('malloc','calloc'):
            return self.ret(self.alloc(a*b if name=='calloc' else a))
        if name=='realloc':
            p=self.alloc(b)
            if a:self.uc.mem_write(p,self.readmem(a,min(b,self.allocations[a])))
            return self.ret(p)
        if name in ('free','munmap','fflush','chmod','fchmod','xml_free_doc'):return self.ret()
        if name=='memset':self.uc.mem_write(a,bytes([b&255])*c);return self.ret(a)
        if name in ('memcpy','memmove','__memcpy_chk'):self.uc.mem_write(a,self.readmem(b,c));return self.ret(a)
        if name in ('strlen','__strlen_chk'):return self.ret(len(self.string(a)))
        if name in ('strcmp','strncmp','memcmp'):
            x,y=(self.readmem(a,c),self.readmem(b,c)) if name=='memcmp' else (self.string(a),self.string(b))
            if name=='strncmp':x,y=x[:c],y[:c]
            return self.ret((x>y)-(x<y))
        if name in ('strstr','strchr'):
            x=self.string(a);needle=self.string(b) if name=='strstr' else bytes([b&255]);i=(x+b'\0').find(needle)
            return self.ret(0 if i<0 else a+i)
        if name in ('strcpy','strncpy','__strncpy_chk'):
            x=self.string(b)+b'\0'
            if name!='strcpy':x=x[:c].ljust(c,b'\0')
            self.uc.mem_write(a,x);return self.ret(a)
        if name=='strdup':return self.ret(self.cstr(self.string(a)))
        if name=='__errno':return self.ret(self.errno)
        if name=='strerror':return self.ret(self.cstr('sandbox I/O failure'))
        if name=='fopen':return self.ret(self.open_file(a,self.string(b).decode().replace('b','')+'b'))
        if name in ('open','creat'):
            flags=b if name=='open' else 0x241
            mode='rb' if flags&3==0 else ('w+b' if flags&0x200 or name=='creat' else 'r+b')
            fd=self.open_file(a,mode);return self.ret(fd if fd else -1)
        if name in ('fclose','close'):
            if a in self.fd:
                f,path,guest=self.fd.pop(a);f.close()
                if guest in (b'/data/Manifest.xml',b'/data/updater'):
                    self.events.append(dict(event='extracted_file_closed',origin='native_extraction_host_io',path=guest.decode(),size=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
            return self.ret()
        if name in ('fseek','lseek'):
            f=self.fd[a][0];f.seek(self.signed(b),c);return self.ret(f.tell() if name=='lseek' else 0)
        if name=='ftell':return self.ret(self.fd[a][0].tell())
        if name in ('fstat','stat','lstat'):
            path=self.fd[a][1] if name=='fstat' else self.path(self.string(a))
            if not path.exists():return self.ret(-1)
            size=path.stat().st_size;self.uc.mem_write(b,b'\0'*104);self.put32(b+16,0o100644);self.uc.mem_write(b+48,struct.pack('<Q',size));return self.ret()
        if name in ('read','fread'):
            fd,ptr,length=(a,b,c) if name=='read' else (d,a,b*c)
            offset=self.fd[fd][0].tell();raw=self.fd[fd][0].read(length);self.uc.mem_write(ptr,raw)
            if length in (6,196):self.events.append(dict(event='read_input',origin='host_io_shim_for_native_read',path=self.fd[fd][2].decode(),offset=offset,requested=length,returned=len(raw),bytes=raw.hex()))
            return self.ret(len(raw) if name=='read' else len(raw)//max(b,1))
        if name in ('write','fwrite'):
            fd,ptr,length=(a,b,c) if name=='write' else (d,a,b*c)
            if fd not in self.fd:raise Unsupported('write to unmodeled fd')
            f,path,guest=self.fd[fd];raw=self.readmem(ptr,length);f.write(raw);f.flush()
            if b'percent_write' in guest:
                self.visible_status=int(raw.split(b'\0',1)[0])
                self.events.append(dict(event='percent_write',origin='native_write_request_host_mock_sysfs',bytes=raw.hex(),status=self.visible_status,return_code=length,caller_return_address=hex(self.uc.reg_read(UC_ARM_REG_LR)&~1)))
            return self.ret(length if name=='write' else c)
        if name=='fscanf':return self.ret(self.fscanf())
        if name in ('fgetc','getc'):
            x=self.fd[a][0].read(1);return self.ret(x[0] if x else -1)
        if name=='feof':return self.ret(int(self.fd[a][0].tell()==self.fd[a][1].stat().st_size))
        if name=='mmap':
            fd,offset=self.arg(4),self.arg(5)
            if c & 6:raise Unsupported('writable/executable file map blocked')
            base=0x20000000;self.file_maps.append((base,b,self.fd[fd][1],offset));return self.ret(base)
        if name in ('unlink','remove'):
            path=self.path(self.string(a),True)
            if path.exists():path.unlink()
            return self.ret()
        if name=='access':return self.ret(0 if self.path(self.string(a)).exists() else -1)
        if name=='android_log_print':
            text=self.format(self.string(c),3).decode('utf-8','replace');self.events.append(dict(event='log',origin='native_format_string_host_formatting',text=text));return self.ret(len(text))
        if name in ('fprintf','printf','puts','android_log'):
            fmt,start=(self.string(b),2) if name=='fprintf' else ((self.string(d),4) if name=='android_log' else (self.string(a),1))
            text=self.format(fmt,start).decode('utf-8','replace');self.events.append(dict(event='log',origin='native_format_string_host_formatting',caller_return_address=hex(self.uc.reg_read(UC_ARM_REG_LR)&~1),text=text));return self.ret(len(text))
        if name in ('sprintf','__sprintf_chk','snprintf'):
            fmt,start=(self.string(d),4) if name=='__sprintf_chk' else ((self.string(c),3) if name=='snprintf' else (self.string(b),2))
            raw=self.format(fmt,start);self.uc.mem_write(a,raw+b'\0');return self.ret(len(raw))
        if name=='property_get':
            key=self.string(a).decode();value=('wrong-product' if self.scenario=='product-mismatch' else 'xe1115h') if key=='ro.build.product' else self.string(c).decode()
            self.uc.mem_write(b,value.encode()+b'\0');return self.ret(len(value))
        if name=='property_set':self.events.append(dict(event='property_set_mock',key=self.string(a).decode(),value=self.string(b).decode()));return self.ret()
        if name=='pipe':self.put32(a,900);self.put32(a+4,901);return self.ret()
        if name=='fork':
            self.events.append(dict(event='fork',origin='host_control_flow_shim',return_code=0,note='Forced child path; no process created'))
            return self.ret(0) # Explore child branch only; never create a host process.
        if name in ('execv','execve','execvp'):
            argv=[]
            for i in range(16):
                p=self.u32(b+4*i)
                if not p:break
                argv.append(dict(pointer=hex(p),bytes=self.string(p).hex(),text=self.string(p).decode('utf-8','replace')))
            self.stopped=dict(kind='updater_dispatch_intercepted',path=self.string(a).decode(),argv=argv)
            self.events.append(dict(event='updater_dispatch',origin='native_execv_arguments_intercepted',return_code=None,payload_executed=False,**self.stopped))
            self.uc.emu_stop();return
        if name in ('system','reboot','exit','_exit','__stack_chk_fail'):raise Unsupported('blocked '+name)
        if name=='qsort':raise Unsupported('qsort shim not implemented')
        if name.startswith(('md5_','sha1_','sha256_')):
            algo,op=name.split('_');key=0 if algo=='md5' else a
            if op=='init':self.hashes[key]=hashlib.new(algo);self.hash_bytes[key]=0;return self.ret(a)
            if op=='update':
                ptr,length=(a,b) if algo=='md5' else (b,c)
                self.hashes[key].update(self.readmem(ptr,length));self.hash_bytes[key]+=length;return self.ret()
            if op=='final':
                raw=self.hashes[key].digest();self.events.append(dict(event='hash_final',origin='host_hash_compression_native_input_loop',algorithm=algo,input_bytes=self.hash_bytes[key],digest=raw.hex()));dest=a if algo=='md5' else self.alloc(len(raw));self.uc.mem_write(dest,raw);return self.ret(dest)
            if op=='one':self.uc.mem_write(c,hashlib.new(algo,self.readmem(a,b)).digest());return self.ret(c)
        if name=='xml_read':
            value=self.xml_read();self.events.append(dict(event='xml_parse',origin='host_ElementTree_shim',path=self.string(a).decode(),encoding_argument=self.string(b).decode(),options=c,return_code=value));return self.ret(value)
        if name=='xml_root':return self.ret(self.xml_nodes[a])
        if name=='xml_content':return self.ret(self.cstr(self.xml_nodes[a]))
        raise Unsupported('unimplemented hook '+name)

    def block(self,uc,address,size,unused):
        self.recent.append(hex(address))
        try:
            if address in self.returns:
                stage=self.returns.pop(address);value=self.signed(self.arg(0))
                record=dict(event='stage_return',origin='native_arm_control',stage=stage,return_code=value,address=hex(address))
                if stage=='load_keys':record['key_count']=self.u32(int(self.stage_inputs[stage]['registers'][1],16))
                self.events.append(record)
                failed=(stage in ('md5','file_size') and value<0) or (stage=='load_keys' and value==0) or (stage in ('signature','zip','manifest') and value!=0)
                if failed and self.first_failure is None:
                    self.first_failure=dict(stage=stage,return_code=value,caller_branch_region=hex(address),inputs=self.stage_inputs.get(stage),origin='native_arm_return_and_caller_gate')
            if address==0x70000000:
                self.stopped=dict(kind='returned',result=self.signed(self.arg(0)));uc.emu_stop();return
            if not any(a<=address<z for a,z in self.exec_ranges):raise Unsupported('execution outside verifier blocked')
            failure_targets={0x14aa0:('file_size','0x14a9e','fopen returned NULL'),0x154f4:('md5','0x154f2','md5 return < 0'),0x15524:('load_keys','0x15522','NULL keys'),0x15598:('signature','0x15596','signature return != 0'),0x155b6:('zip','0x155b4','ZIP return != 0'),0x1568e:('manifest','0x15682','manifest return != 0')}
            if address in failure_targets:
                stage,branch,condition=failure_targets[address];self.events.append(dict(event='failing_branch',origin='native_arm_branch_target',stage=stage,address=hex(address),branch_address=branch,condition=condition))
            if address==0x158fe:
                footer=self.readmem(self.uc.reg_read(UC_ARM_REG_SP)+0x20,6)
                self.events.append(dict(event='failing_branch',origin='native_arm_branch_target',stage='signature',address=hex(address),branch_address='0x158f4' if footer[2]!=255 else '0x158fc',condition='footer marker byte differs from 0xff',footer=footer.hex()))
            if address==0x15058:
                self.events.append(dict(event='status_request',origin='native_arm_control',address=hex(address),status=self.arg(0)))
            if address in STAGES:
                stage=STAGES[address]
                values=dict(registers=[hex(self.arg(i)) for i in range(4)])
                if stage in ('file_size','install','md5','load_keys','signature','zip','dispatch'):values['path']=self.string(self.arg(0)).decode('utf-8','replace')
                if stage=='md5':values.update(project=self.string(self.arg(1)).decode(),suffix=self.arg(2))
                if stage=='signature':values.update(key_count=self.arg(2),suffix=self.arg(3))
                if stage=='status_write':values['requested_status']=self.arg(0)
                if stage=='rsa':values.update(signature_length=self.arg(2),signature_sha256=hashlib.sha256(self.readmem(self.arg(1),self.arg(2))).hexdigest())
                if stage=='manifest':values.update(product=self.string(self.arg(1)).decode())
                if stage=='dispatch':values.update(system_type=self.arg(2))
                self.stage_inputs[stage]=values
                self.events.append(dict(event='stage_enter',origin='native_arm_control_with_declared_shims',stage=stage,address=hex(address),inputs=values,mock_visible_status=self.visible_status))
                self.returns[self.uc.reg_read(UC_ARM_REG_LR)&~1]=stage
            if address in self.hooks:self.shim(self.hooks[address])
        except Exception as exc:
            self.stopped=dict(kind='unsupported',reason=f'{type(exc).__name__}: {exc}',pc=hex(address));uc.emu_stop()

    def run(self,entry=0x15474,args=None):
        args=args or [self.cstr('/mnt/udisk/update/update.zip')]
        for i,a in enumerate(args):self.uc.reg_write(REGS[i],a)
        self.uc.reg_write(UC_ARM_REG_LR,0x70000001)
        start=time.monotonic()
        try:
            self.uc.emu_start(entry|1,0,timeout=120000000,count=100000000)
        except UcError as exc:
            if self.stopped is None:self.stopped=dict(kind='unicorn_error',reason=str(exc),pc=hex(self.uc.reg_read(UC_ARM_REG_PC)))
        for f,_,_ in self.fd.values():f.close()
        artifacts={}
        for name in ('data/Manifest.xml','data/updater'):
            path=self.root/name
            if path.exists():artifacts[name]=dict(size=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.events.append(dict(event='stop',origin='harness',outcome=self.stopped,artifacts=artifacts))
        for stage in dict.fromkeys(reversed(list(self.returns.values()))):
            self.events.append(dict(event='stage_interrupted',origin='harness_execution_boundary',stage=stage,return_code=None,reason=(self.stopped or {}).get('kind','unsupported_stop')))
        for i,event in enumerate(self.events):event['sequence']=i
        return dict(schema_version=1,first_failing_branch=next((e for e in self.events if e['event']=='failing_branch'),None),artifacts=artifacts,outcome=self.stopped or {'kind':'unsupported_stop','pc':hex(self.uc.reg_read(UC_ARM_REG_PC))},first_failing_gate=self.first_failure,events=self.events,shim_calls=dict(self.counts),recent_blocks=list(self.recent),seconds=time.monotonic()-start,xml_shim=self.xml_shim,
                    isolation='CPU only; no guest syscall passthrough; guest data NX; allowlisted disposable files; exec intercepted')


def main():
    p=argparse.ArgumentParser();p.add_argument('--workspace',type=Path,required=True);p.add_argument('--package',choices=['original','clean'],required=True);p.add_argument('--scenario',default='baseline',choices=['baseline','package-denied','key-denied','manifest-denied','status-denied','stale-status','product-mismatch','xml-fail']);p.add_argument('--xml-shim',action='store_true');p.add_argument('--out',type=Path,required=True);p.add_argument('--entry',default='install',choices=['install','zip'])
    args=p.parse_args();w=args.workspace.resolve();e=json.loads((w/'analysis/evidence.json').read_text())
    args.out=args.out.resolve()
    if args.out.suffix!='.json' or not args.out.is_relative_to((w/'analysis').resolve()):
        raise ValueError('diagnostics must be a .json file under workspace/analysis')
    entries=[x for v in e['views'] for x in v['entries']]
    def file(name):return Path(next(x['extracted'] for x in entries if x['name']==name))
    source=w/('input/update.zip' if args.package=='original' else 'output/clean-experiment/update.zip')
    def digest(path):
        h=hashlib.sha256()
        with path.open('rb') as f:
            for chunk in iter(lambda:f.read(8*1024*1024),b''):h.update(chunk)
        return h.hexdigest()
    source_hash=digest(source)
    with tempfile.TemporaryDirectory(prefix='x70-arm-') as tmp:
        root=Path(tmp)
        for path in ['system/etc','data','sys/devices/platform/debug_control']: (root/path).mkdir(parents=True)
        package=root/'package.zip';shutil.copyfile(source,package)
        if digest(package)!=source_hash:raise ValueError('disposable copy hash mismatch')
        shutil.copyfile(file('system/etc/keys'),root/'system/etc/keys')
        (root/'sys/devices/platform/debug_control/percent_write').write_bytes(b'0\0\0\0')
        h=Harness(file('system/bin/vold'),w/'analysis/trace/vold-symbols.txt',root,package,args.scenario,args.xml_shim)
        result=h.run() if args.entry=='install' else h.run(0x17e70,[h.cstr('/mnt/udisk/update/update.zip'),h.alloc(32)])
        result.update(package=args.package,scenario=args.scenario,entry=args.entry,verifier_sha256=hashlib.sha256(file('system/bin/vold').read_bytes()).hexdigest())
        result.update(package_sha256=source_hash,source_unchanged=digest(source)==source_hash,disposable_copy_unchanged=digest(package)==source_hash,assumption='Installed verifier/key provisionally assumed equal; not established',status_scope='Mock sysfs only; no real-car status captured',host_shims='libc, file I/O, arithmetic imports, hash compression, time, properties, pipe/fork; XML only if requested')
        args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps({k:result[k] for k in ('package','scenario','entry','outcome','seconds','shim_calls','recent_blocks')},indent=2))


if __name__=='__main__':main()
