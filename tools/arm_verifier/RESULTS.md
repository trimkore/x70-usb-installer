# Offline ARM experiment results

The installed verifier and key being identical to the analyzed package's copies
is a provisional assumption. These results are not captured vehicle status.

| Experiment | Observed outcome |
|---|---|
| Original, `--native-icu`, no XML shim | Native XML/ICU and manifest checks pass; updater dispatch intercepted before execution |
| Original, native ICU with injected wrong product | Manifest returns -1; mock status 998; no dispatch |
| Original, without native ICU or XML shim | MD5, key loading, native RSA and native ZIP opening pass; native XML setup stops at unresolved ICU `ucnv_open_51` (PLT 0x8330) |
| Original, legacy explicit XML shim added | Native manifest caller checks pass; selected appended updater extracted; execv intercepted before payload execution |
| Clean, same verifier | MD5 helper returns 1 (absent marker, permitted continuation); key loads; signature footer fails; status 997 requested and written to mock sysfs; no dispatch |
| Independent native ZIP open, either archive | Returns 0; this is not authentication or firmware acceptance |
| Original, injected key-read denial | Native key-load failure, mock status 996 |
| Original, injected manifest-create denial | Authentication and ZIP pass; native manifest failure, mock status 998 |
| Original, injected initial package-open denial | Size helper and install return -1; no status write |
| Clean, injected status-node denial | Signature still fails; requests 997 but status writer returns -1; no successful status write |

The clean signature's first instrumented rejection is branch 0x158f4 to 0x158fe,
not a ZIP-integrity check. Native original ZIP extraction selects the appended
488-byte build-453 manifest and 9804-byte updater; their hashes match the prior
forensic evidence. The earlier firmware payload is not selected by this parser.
Native dispatch arguments are updater path, ASCII API `3`, a simulated pipe FD,
package path, raw byte `02`, NULL. Fork is mocked and execv is stopped; neither
updater behavior nor an installation result is observed.

Native install writes normal progress 0 only after validation. A controlled
stale-status run starts with simulated 997; it remains visible during validation
until the native zero write. The Settings polling thread was statically traced,
not executed. Kernel status persistence and concurrent scheduling are unknown,
so a stale-status race is a hypothesis only. The exact four-byte status request
is logged, including bytes following NUL; mock decimal parsing is not evidence
of the kernel driver's implementation.

Java admission depends on runtime numeric current-slot code (target 453 must be
greater), not the displayed version label. Full-update flag 1 skips the other-slot
dependency comparison. These Java rejection branches use a different broadcast
from the verification-failed status path. Installed slot properties, app identity,
I/O permissions and status history remain necessary evidence.

Twelve synthetic harness tests and the existing 23 forensic/clean-experiment
tests pass. Firmware, keys, extracted files, disassembly and raw diagnostic logs
remain outside Git. No new package, signing key, checksum patch, payload execution
or USB/car write was performed. ZIP validity and partial emulation success are
insufficient to establish firmware acceptance or the cause of a vehicle failure.

Native ICU mode uses SHA256-pinned package libicuuc/libgabi++ and icudt51l.dat.
Package libc is mapped non-executable only for its static uppercase table.
The native data-registration API is called explicitly; Android startup is not
emulated. Unused unresolved imports are guarded and stop on use. Native XML
fixtures show a root for valid/unclosed input and no root for empty input with
options value 1; a document pointer alone is not strict validation. These results
resolve the earlier reached ICU import blocker, not the installed-car discrepancy.
