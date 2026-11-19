import pathlib, subprocess, tempfile, unittest, os
BINARY = os.environ['X70_TEST_BINARY']
class DryRun(unittest.TestCase):
    def run_at(self, root):
        return subprocess.run([BINARY, '--dry-run', str(root)], capture_output=True, text=True)
    def test_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertNotEqual(self.run_at(d).returncode, 0)
    def test_missing(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertNotEqual(self.run_at(pathlib.Path(d)/'absent').returncode, 0)
    def test_sorted_recursive_and_no_shell(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d); (p/'sub').mkdir()
            for f in ['z.apk','sub/a.apk','$(touch INJECTED).apk','ignored.txt']:
                (p/f).touch()
            r=self.run_at(p)
            self.assertEqual(r.returncode,0,r.stderr)
            lines=[x for x in r.stdout.splitlines() if 'Would install' in x]
            self.assertEqual(len(lines),3); self.assertEqual(lines,sorted(lines))
            self.assertFalse((p/'INJECTED').exists())
    def test_symlink_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d); (p/'real.apk').touch(); (p/'link.apk').symlink_to(p/'real.apk')
            (p/'loop').symlink_to(p,target_is_directory=True)
            r=self.run_at(p); self.assertEqual(r.returncode,0)
            self.assertEqual(r.stdout.count('Would install'),1)
    def test_limit_prevents_install_plan(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            for i in range(257): (p/f'{i}.apk').touch()
            r=self.run_at(p); self.assertNotEqual(r.returncode,0)
            self.assertNotIn('Would install',r.stdout)
    def test_newline_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d)/'bad\n.apk').touch()
            self.assertNotEqual(self.run_at(d).returncode,0)
    def test_depth_limit(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            for _ in range(10): p=p/'sub'; p.mkdir()
            (p/'a.apk').touch()
            self.assertNotEqual(self.run_at(d).returncode,0)
    def test_bad_arguments(self):
        for args in [[], ['3','invalid','x'], ['3','1','x']]:
            self.assertEqual(subprocess.run([BINARY]+args,capture_output=True).returncode,2)
if __name__=='__main__': unittest.main()
