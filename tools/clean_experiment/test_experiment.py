"""Synthetic fixtures only: no firmware, device evidence or signing key."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from build import NAMES, build_zip, validate_clean
from verifier import md5_stage, signature_stage, verify, load_key, manifest_stage


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.payloads={NAMES[0]:b'<sys_info><project>fixture</project><systemVersionCode>453</systemVersionCode></sys_info>',
                       NAMES[1]:b'non-executable synthetic payload'*32}

    def test_deterministic_exact_members_crc_offsets(self):
        a,b=self.root/'a.zip',self.root/'b.zip'
        build_zip(a,self.payloads); build_zip(b,self.payloads)
        self.assertEqual(a.read_bytes(),b.read_bytes())
        report=validate_clean(a,self.payloads,self.root/'extract')
        self.assertEqual(report['central_directories'],1)
        self.assertEqual([e['name'] for e in report['entries']],list(NAMES))
        self.assertTrue(all(e['sha256']==hashlib.sha256(self.payloads[e['name']]).hexdigest() for e in report['entries']))

    def test_existing_target_never_overwritten(self):
        p=self.root/'a.zip'; p.write_bytes(b'keep')
        with self.assertRaises(FileExistsError): build_zip(p,self.payloads)
        self.assertEqual(p.read_bytes(),b'keep')

    def test_manifest_uses_literal_offsets_despite_gap_before_eocd(self):
        p=self.root/'gap.zip'; build_zip(p,self.payloads)
        data=p.read_bytes()
        p.write_bytes(data[:-22]+b'not an archive entry'*30+data[-22:])
        self.assertEqual(manifest_stage(p,'fixture')['status'],'pass')
        with self.assertRaises(ValueError): validate_clean(p,self.payloads,self.root/'extract')

    def test_extra_and_unsafe_members_refused(self):
        for name in ('extra','../escape'):
            with self.assertRaises(ValueError): build_zip(self.root/'a.zip',dict(self.payloads,**{name:b'x'}))

    def test_crc_corruption_and_trailing_data_refused(self):
        for variant in ('crc','trailing','comment','offset'):
            p=self.root/(variant+'.zip'); build_zip(p,self.payloads)
            data=bytearray(p.read_bytes())
            if variant=='crc': data[30+len(NAMES[0])]^=1
            if variant=='trailing': data+=b'extra'
            if variant=='comment': data[-2:]=struct.pack('<H',1); data+=b'x'
            if variant=='offset': struct.pack_into('<I',data,len(data)-6,1)
            p.write_bytes(data)
            with self.assertRaises(ValueError): validate_clean(p,self.payloads,self.root/variant)

    def test_md5_absence_is_continue_not_authentication(self):
        result=md5_stage(b'x'*400+b'\0'*196)
        self.assertEqual(result['return_code'],1)
        self.assertEqual(result['signature_suffix'],0)
        self.assertEqual(signature_stage(b'x'*400+b'\0'*196,0,3,b'\0'*20)['status'],'fail')

    def test_md5_range_case_and_project_prefix(self):
        prefix=b'fixture'*100
        marker=b'##project:xe1115h-extra\n##md5:'+hashlib.md5(prefix).hexdigest().encode()+b'\n'
        blob=prefix+marker.ljust(196,b'\0')
        self.assertEqual(md5_stage(blob)['range'],[0,len(prefix)])
        self.assertEqual(md5_stage(blob)['return_code'],0)
        self.assertEqual(md5_stage(b'changed'+blob[7:])['return_code'],-1)
        self.assertEqual(md5_stage(blob.replace(b'xe1115h',b'unknown'))['return_code'],-1)
        self.assertEqual(md5_stage(b'x'*400)['status'],'unsupported')

    def test_failure_short_circuits_later_gates(self):
        p=self.root/'a.zip'; build_zip(p,self.payloads)
        missing=self.root/'missing-key'
        r=verify(p,missing,'fixture',b'\0'*20)
        self.assertEqual(r['first_failing_gate'],'key_loading')
        self.assertEqual(r['stages']['rsa_signature']['status'],'not_reached')
        # Synthetic arithmetic key parameters only; no private key or signatures.
        n=(1<<2047)+12345
        words=[(n>>(32*i))&0xffffffff for i in range(64)]
        rr=pow(2,4096,n)
        limbs=[(rr>>(32*i))&0xffffffff for i in range(64)]
        key=self.root/'key.txt'
        key.write_text('v2 {64,0x%x,{%s},{%s}}'%((-pow(n,-1,2**32))%2**32,','.join(map(str,words)),','.join(map(str,limbs))))
        self.assertEqual(load_key(key),n)
        r=verify(p,key,'fixture',b'\0'*20)
        self.assertEqual(r['first_failing_gate'],'rsa_signature')
        self.assertEqual(r['stages']['zip']['status'],'not_reached')
        self.assertEqual(r['stages']['manifest']['status'],'not_reached')
        self.assertFalse(r['updater_dispatch_reachable'])
        self.assertFalse(r['updater_executed'])
        self.assertEqual(manifest_stage(p,'fixture')['status'],'pass')


if __name__=='__main__': unittest.main()
