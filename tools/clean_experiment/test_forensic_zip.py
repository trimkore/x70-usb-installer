import io
import struct
import tempfile
import unittest
from pathlib import Path
import zipfile
import forensic_zip as x

def fixture(items=None, compression=zipfile.ZIP_DEFLATED):
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w',compression) as z:
        for name,value in (items or [('a.txt',b'hello')]): z.writestr(name,value)
    return b.getvalue()

class ParserTests(unittest.TestCase):
    def test_normal_extract(self):
        data=fixture(); r=x.parse(data)
        self.assertEqual(len(r['views']),1)
        with tempfile.TemporaryDirectory() as t:
            v=r['views'][0]; x.extract(data,v,Path(t))
            self.assertEqual(Path(v['entries'][0]['extracted']).read_bytes(),b'hello')

    def test_concatenation(self):
        first=fixture(); second=fixture([('b.txt',b'second')])
        r=x.parse(first+second)
        self.assertEqual(len(r['views']),2)
        self.assertEqual(r['views'][1]['base'],len(first))

    def test_embedded_stored_zip(self):
        r=x.parse(fixture([('inner.zip',fixture())],zipfile.ZIP_STORED))
        self.assertEqual(len(r['views']),2)
        self.assertTrue(r['view_intersections'])

    def test_false_and_truncated_eocd(self):
        data=fixture()+b'PK\x05\x06'
        r=x.parse(data)
        self.assertEqual(len(r['views']),1)
        self.assertIn('truncated',r['end_records'][-1]['errors'][0])

    def test_traversal_and_windows_aliases(self):
        for name in ('../evil','/abs','C:/evil','a\\..\\b','a:stream','CON','a/aux.txt','a.','a//b','a\x00b'):
            with self.subTest(name=name), self.assertRaises(ValueError): x.safe_name(name)
        data=fixture([('../evil',b'x')]); v=x.parse(data)['views'][0]
        with tempfile.TemporaryDirectory() as t:
            x.extract(data,v,Path(t)); self.assertIn('FAILED',v['entries'][0]['extraction'])

    def test_crc_corruption(self):
        data=bytearray(fixture(compression=zipfile.ZIP_STORED)); data[35]^=1
        v=x.parse(data)['views'][0]
        with tempfile.TemporaryDirectory() as t:
            x.extract(data,v,Path(t)); self.assertIn('CRC',v['entries'][0]['extraction'])

    def test_local_name_mismatch(self):
        data=bytearray(fixture()); data[30]=ord('z')
        self.assertIn('local/central name mismatch',x.parse(data)['views'][0]['entries'][0]['issues'])

    def test_directory_bounds(self):
        data=bytearray(fixture()); p=data.find(b'PK\x05\x06'); struct.pack_into('<I',data,p+12,0xffffff00)
        self.assertFalse(x.parse(data)['views'])

    def test_duplicates_preserved(self):
        data=fixture([('a',b'one'),('a',b'two')]); v=x.parse(data)['views'][0]
        with tempfile.TemporaryDirectory() as t:
            x.extract(data,v,Path(t))
            self.assertEqual([Path(e['extracted']).read_bytes() for e in v['entries'][0:2]],[b'one',b'two'])

    def test_symlink_refused(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:
            info=zipfile.ZipInfo('link'); info.create_system=3; info.external_attr=0o120777<<16; z.writestr(info,'target')
        data=b.getvalue(); v=x.parse(data)['views'][0]
        with tempfile.TemporaryDirectory() as t:
            x.extract(data,v,Path(t)); self.assertIn('links',v['entries'][0]['extraction'])

    def test_size_limit(self):
        data=fixture([('a',b'x'*10000)]); v=x.parse(data)['views'][0]
        with tempfile.TemporaryDirectory() as t:
            x.extract(data,v,Path(t),max_entry=10); self.assertIn('limit',v['entries'][0]['extraction'])

    def test_data_descriptor(self):
        class Stream(io.BytesIO):
            def seekable(self): return False
            def seek(self,*args): raise OSError('unseekable')
        b=Stream()
        with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z: z.writestr('a',b'abc')
        v=x.parse(b.getvalue())['views'][0]
        self.assertFalse(v['entries'][0]['issues'])
        self.assertIn('descriptor_end',v['entries'][0])

    def test_overlapping_entries(self):
        data=bytearray(fixture([('a',b'one'),('b',b'two')]))
        cds=list(x.offsets(data,b'PK\x01\x02'))
        struct.pack_into('<I',data,cds[1]+42,0)
        self.assertTrue(x.parse(data)['views'][0]['overlaps'])

    def test_zip64_is_explicitly_unsupported(self):
        data=bytearray(fixture()); p=data.find(b'PK\x05\x06')
        struct.pack_into('<H',data,p+10,65535)
        r=x.parse(data)
        self.assertFalse(r['views'])
        self.assertIn('ZIP64',r['end_records'][0]['errors'][0])

    def test_broken_descriptor(self):
        data=bytearray(fixture())
        # Declare descriptor mode in both headers but omit the descriptor.
        struct.pack_into('<H',data,6,8)
        cd=data.find(b'PK\x01\x02'); struct.pack_into('<H',data,cd+8,8)
        self.assertIn('data descriptor mismatch/missing',x.parse(data)['views'][0]['entries'][0]['issues'])

if __name__=='__main__': unittest.main()
