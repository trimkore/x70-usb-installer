"""Synthetic CPU/isolation tests. No proprietary firmware required."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import harness


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / 'package.zip'
        self.package.write_bytes(b'fixture')

    def make(self, code=b'\x07\x20\x70\x47', symbols=''):
        data = bytearray(0x100 + len(code))
        data[:4] = b'\x7fELF'
        struct.pack_into('<I', data, 28, 52)
        struct.pack_into('<HH', data, 42, 32, 1)
        struct.pack_into('<8I', data, 52, 1, 0x100, 0x1000, 0, len(code), len(code), 5, 4096)
        data[0x100:] = code
        binary = self.root / 'synthetic.elf'
        binary.write_bytes(data)
        sym = self.root / 'symbols.txt'
        sym.write_text(symbols)
        with patch.object(harness, 'PINNED_VOLD', hashlib.sha256(data).hexdigest()):
            return harness.Harness(binary, sym, self.root, self.package)

    def test_native_thumb_returns(self):
        result = self.make().run(0x1000, [0])
        self.assertEqual(result['outcome'], {'kind': 'returned', 'result': 7})
        self.assertIsNone(result['first_failing_gate'])

    def test_raw_syscall_is_stopped(self):
        h = self.make(b'\x00\xdf\x70\x47')
        with patch.dict(harness.STAGES, {0x1000: 'zip'}):
            result = h.run(0x1000, [0])
        self.assertEqual(result['outcome']['kind'], 'blocked_guest_interrupt')
        unfinished = next(e for e in result['events'] if e['event'] == 'stage_interrupted')
        self.assertEqual(unfinished['stage'], 'zip')
        self.assertIsNone(unfinished['return_code'])
        self.assertIsNone(result['first_failing_gate'])

    def test_package_and_keys_cannot_be_written(self):
        h = self.make()
        for path in (b'/mnt/udisk/update/update.zip', b'/system/etc/keys', b'/dev/block/mmcblk0', b'/data/../../escape'):
            with self.subTest(path=path), self.assertRaises(harness.Unsupported):
                h.path(path, write=True)
        self.assertEqual(self.package.read_bytes(), b'fixture')

    def test_heap_is_not_executable(self):
        h = self.make()
        p = h.alloc(4)
        h.uc.mem_write(p, b'\x07\x20\x70\x47')
        result = h.run(p, [0])
        self.assertEqual(result['outcome']['kind'], 'unsupported_memory')

    def test_exec_is_intercepted_before_payload(self):
        h = self.make(symbols='00001000 g DF .text 00000004 execv\n')
        argv = h.alloc(8)
        target = h.cstr('/data/updater')
        h.put32(argv, target)
        result = h.run(0x1000, [target, argv])
        self.assertEqual(result['outcome']['kind'], 'updater_dispatch_intercepted')
        event = next(e for e in result['events'] if e['event'] == 'updater_dispatch')
        self.assertFalse(event['payload_executed'])
        self.assertIsNone(event['return_code'])

    def test_stage_return_recorded_at_stop(self):
        h = self.make()
        with patch.dict(harness.STAGES, {0x1000: 'zip'}):
            result = h.run(0x1000, [h.cstr('/mnt/udisk/update/update.zip')])
        self.assertEqual(result['first_failing_gate']['stage'], 'zip')
        self.assertEqual(result['first_failing_gate']['return_code'], 7)
        self.assertEqual([e['event'] for e in result['events']], ['stage_enter', 'stage_return', 'stop'])
        self.assertEqual([e['sequence'] for e in result['events']], list(range(3)))

    def test_status_log_preserves_bytes_after_nul(self):
        h = self.make()
        path = self.root / 'status'
        path.write_bytes(b'0000')
        stream = path.open('r+b')
        self.addCleanup(stream.close)
        h.fd[20] = (stream, path, b'/sys/devices/platform/debug_control/percent_write')
        data = h.cstr(b'0\x00\x05')
        for reg, value in zip(harness.REGS, (20, data, 4, 0)):
            h.uc.reg_write(reg, value)
        h.uc.reg_write(harness.UC_ARM_REG_LR, 0x70000001)
        h.shim('write')
        self.assertEqual(h.visible_status, 0)
        self.assertEqual(h.events[-1]['bytes'], '30000500')
        self.assertEqual(h.events[-1]['return_code'], 4)

    def test_icu_paths_stay_read_only_and_bounded(self):
        h = self.make()
        h.extra_read_roots = ('/system/usr/icu/', '/usr/icu/')
        self.assertEqual(h.path(b'/usr/icu/data'), self.root / 'usr/icu/data')
        for name, write in ((b'/usr/icu/data', True), (b'/usr/icu/../../package.zip', False)):
            with self.assertRaises(harness.Unsupported):
                h.path(name, write)

    def test_signed_division_remainder(self):
        h = self.make()
        h.uc.reg_write(harness.UC_ARM_REG_R0, (-7) & 0xffffffff)
        h.uc.reg_write(harness.UC_ARM_REG_R1, 3)
        h.uc.reg_write(harness.UC_ARM_REG_LR, 0x70000001)
        h.shim('idivmod')
        self.assertEqual(h.signed(h.arg(0)), -2)
        self.assertEqual(h.signed(h.arg(1)), -1)

    def test_multiple_maps_do_not_alias(self):
        h = self.make()
        stream = self.package.open('rb')
        self.addCleanup(stream.close)
        h.fd[20] = (stream, self.package, b'/mnt/udisk/update/update.zip')
        h.put32(h.uc.reg_read(harness.UC_ARM_REG_SP), 20)
        addresses = []
        for _ in range(2):
            for reg, value in zip(harness.REGS, (0, 4096, 1, 2)):
                h.uc.reg_write(reg, value)
            h.uc.reg_write(harness.UC_ARM_REG_LR, 0x70000001)
            h.shim('mmap')
            addresses.append(h.arg(0))
        self.assertEqual(addresses, [0x20000000, 0x20001000])

    def test_stderr_is_only_a_diagnostic_event(self):
        h = self.make()
        ptr = h.cstr('error')
        for reg, value in zip(harness.REGS, (2, ptr, 5, 0)):
            h.uc.reg_write(reg, value)
        h.uc.reg_write(harness.UC_ARM_REG_LR, 0x70000001)
        h.shim('write')
        self.assertEqual(h.events[-1]['origin'], 'host_diagnostic_sink')
        self.assertEqual(h.events[-1]['text'], 'error')
        self.assertFalse(h.fd)

    def test_unknown_binary_rejected(self):
        h = self.make()
        with self.assertRaises(ValueError):
            harness.Harness(self.root / 'synthetic.elf', self.root / 'symbols.txt', self.root, self.package)

if __name__ == '__main__':
    unittest.main()
