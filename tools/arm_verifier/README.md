# ARM verifier diagnostic harness

CPU-only offline investigation of one SHA256-pinned, package-version `vold`.
The installed unit's verifier/key being identical is a **provisional assumption**.
This tool does not capture the car's status or demonstrate vehicle acceptance.

Requires Python 3.10+ and `pip install -r tools/arm_verifier/requirements.txt`.
Firmware, keys, disassembly, raw diagnostic logs and generated packages stay in
an existing private forensic workspace, outside this repository.

```powershell
python -m unittest discover -s tools/arm_verifier -p 'test_*.py' -v
python tools/arm_verifier/harness.py --workspace E:\x70 --package clean --out E:\x70\analysis\emulation\clean.json
python tools/arm_verifier/harness.py --workspace E:\x70 --package original --out E:\x70\analysis\emulation\original-native-xml.json
python tools/arm_verifier/harness.py --workspace E:\x70 --package original --xml-shim --out E:\x70\analysis\emulation\original-xml-shim.json
```

`--entry zip` tests native ZIP opening independently; it does not bypass a gate
in an installation run. `--scenario` accepts `baseline`, `package-denied`,
`key-denied`, `manifest-denied`, `status-denied`, `stale-status`,
`product-mismatch`, and `xml-fail`. The last scenario requires `--xml-shim` to
inject an XML result. These are controlled host faults, not observations of a car.

The workspace needs `analysis/evidence.json`, its extracted files,
`analysis/trace/vold-symbols.txt`, `input/update.zip`, and the existing
`output/clean-experiment/update.zip`. Outputs must be JSON under its `analysis`
directory. No package is built by this tool. Each run copies the chosen archive
and key into a temporary directory and compares archive hashes before/after.
Large archive copies and hashing take additional time beyond reported CPU-run time.

## Execution and containment boundary

Unicorn executes the verifier's ARM/Thumb control flow, native ZIP selection and
extraction, native key-loader control, and native RSA arithmetic/padding checks.
File operations, libc operations, imported integer division, properties, time,
hash compression, pipe and fork use explicitly implemented host shims. The hash
read loops and range calculations execute native instructions. `fork` selects
the child path without creating a process. `execv` logs its arguments and stops;
no updater instruction executes. There is no post-dispatch result.

Guest syscalls/interrupts stop execution: there is no syscall passthrough,
network connection, real sysfs access, device access, reboot, or partition write.
Only allowlisted paths in disposable storage are exposed. Package/key writes are
blocked. Guest data pages are non-executable; only the pinned verifier and explicitly loaded native ICU/ABI executable
segments can run. Unknown imports and memory accesses stop as **unsupported**,
not as a package rejection. This is an application-level emulation boundary,
not a whole Android VM or a host OS network-policy change.

Without either `--native-icu` or `--xml-shim`, the original-package run stops on unresolved
`ucnv_open_51` during native XML encoding setup. With it, host ElementTree supplies
the XML tree and native project/type checks continue. The option does not prove
that libxml2/ICU would accept the document on Android. Java, Binder, the daemon
command handler, actual system properties, kernel sysfs behavior and scheduling
are not emulated. The entry point is the install function inside `vold`.

## Structured logging

JSON `schema_version: 1` records ordered `sequence` events:

- `stage_enter` and `stage_return`: native address, registers, relevant paths,
  suffix/product/key count, result, and simulated visible status. Key loading
  returns a pointer; RSA returns 1 on success; other conventions are preserved.
- `read_input`, `hash_final`: footer/trailer bytes and offsets, hash input length
  and digest. Hash compression is explicitly labeled as host-provided.
- `io_open`, `extracted_file_closed`: access results and hashes of selected files.
- `failing_branch`: instrumented rejection block and associated branch address.
  `first_failing_gate` and `first_failing_branch` distinguish a native failure
  from an unsupported emulation stop. This is selected gate instrumentation,
  not a complete trace of every conditional instruction.
- `status_request`, `percent_write`, and status-writer stage return: requested
  value, exact four bytes, simulated parsed value, and host write return code.
  Bytes after NUL are preserved. Parsing the leading decimal text is a **mock
  sysfs policy**, not a reconstruction of the kernel driver.
- `updater_dispatch`: native exec arguments as raw bytes/text, intercepted before
  execution; `stage_interrupted` records null return codes for unfinished calls.
- `stop`: outcome, extracted artifact hashes, and remaining unsupported behavior.

Verification and I/O events carry origin labels; property_set_mock is explicitly named as a mock. `mock_visible_status` is not a measurement
from a vehicle, and `stale-status` does not execute Java's polling thread.

Synthetic tests cover native Thumb return, blocked SVC, non-executable data,
write/path restrictions, executable pinning, dispatch interception, ordered
stage logging and preservation of status bytes after NUL. They validate the
harness boundary, not all libc/Android semantics. See RESULTS.md for findings.

To reproduce the full matrix: `python tools/arm_verifier/run_matrix.py --workspace E:\x70`. Raw results stay under the private workspace analysis directory.

## Native ICU mode

Use `--native-icu` for native XML with the extracted package's ICU 51 data/code.
It cannot be combined with `--xml-shim`. The SHA256-pinned libicuuc and libgabi++
modules are relocated into guest memory; package libc is mapped non-executable
only to supply its preinitialized uppercase table. No libc initializers run.
Unresolved dependencies have unmapped guard addresses and fail on use. ICU data
is registered through an actual native call to udata_setCommonData_51; this is
explicit provisioning, not Android dynamic-linker/startup emulation. Native XML
functions and ICU converters execute; no XML tree or successful result is mocked.
Existing libc, hashing, I/O and runtime shims remain disclosed in the results.

```powershell
python tools/arm_verifier/harness.py --workspace E:\x70 --package original --native-icu --out E:\x70\analysis\emulation\icu\original-native-icu.json
python tools/arm_verifier/harness.py --workspace E:\x70 --package clean --native-icu --out E:\x70\analysis\emulation\icu\clean-native-icu.json
python tools/arm_verifier/harness.py --workspace E:\x70 --package original --native-icu --scenario product-mismatch --out E:\x70\analysis\emulation\icu\original-native-icu-product-mismatch.json
python tools/arm_verifier/probe_xml.py --workspace E:\x70
```

The fixture probe invokes native xmlReadFile and root access on disposable XML
fixtures, never creates an update package, and asserts that empty input has no
root. Options value 1 admits an unclosed fixture with a root; document-pointer
success is not a strict well-formedness test. A separate full native product
mismatch run demonstrates manifest rejection before dispatch.
