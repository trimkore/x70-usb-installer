# Offline clean-package experiment

Creates a conventional, **unsigned experimental ZIP**, containing only the two
byte-identical payloads from the selected final archive view. It does not sign,
patch, execute or deploy anything. The resulting artifact fails authentication
under the reconstructed package-version verifier. ZIP integrity is not firmware
acceptance; no claim is made about an installed vehicle's verifier or trust keys.

Requires Python 3.10+ (standard library), host 7-Zip, and an existing local forensic
workspace. No firmware, keys, disassembly, device records or generated artifacts
are provided by this repository.

From the repository root:

```powershell
python -m unittest discover -s tools/clean_experiment -p 'test_*.py' -v
python tools/clean_experiment/build.py --workspace E:\x70 --seven-zip 'C:\Program Files\7-Zip\7z.exe'
```

The workspace must contain `input/update.zip`, `analysis/evidence.json`, extracted
files at their recorded paths, and `analysis/trace/verifier-model.json` from the
prior static trace (including `native_padding_hash_constant`). The builder checks
original size/SHA256, both payloads against recorded hashes **and original bytes**,
ELF32 ARM identity, build 453, and local key/vold/build.prop provenance. The output
is fixed to `output/clean-experiment/update.zip` inside that workspace. Existing
output is refused. To revalidate without rewriting the archive, add
`--check-existing`; only local result/log files are refreshed.

ZIP_STORED, fixed timestamps, canonical member order and fixed permissions make
the ZIP deterministic. CRCs, local/central offsets, unique entries, contiguity,
one directory, no comment/trailing bytes and extracted hashes are checked. Host
`7z t` must return success with no warnings. No original signature is copied to
the changed archive and no signing key is generated.

Local outputs include `results.json`, `original-integrity.json`, `7zip-test.txt`
and safely extracted copies. Keep all these outside Git. Only source, synthetic
fixtures and this concise result summary are intended for publication.

## Model provenance and limits

`forensic_zip.py` and its 15 tests reuse the existing `x70_analyze.py` parser and
safe extraction code, excluding its device-specific report generator.
`elf_data.py` reuses the data-only reader from `trace_native.py`. `verifier.py`
extends the arithmetic in `model_verifier.py` with ordered gates and short circuit
results, following the already completed `analysis/VERIFIER_TRACE.md` locally.

Relevant package Thumb addresses: vold install `0x15474`, MD5 `0x145e8`, key
loader `0x15bf0`, signature `0x15850`, ZIP `0x17e70`, manifest `0x14bc8`, dispatch
`0x150c8`. Signature range calculation is at `0x15a72` and `0x15b1e–0x15b48`;
native RSA padding comparison is at `0x17572–0x175d6`, SHA1 constant `0x5b708`.

The model supports this observed single v2 recovery key and regular update.zip
route. It checks its Montgomery parameters and both PKCS#1 SHA1 encoding and the
native padding hash. It models the observed ASCII manifest without a DTD, not all
libxml2 edge cases. It reports unterminated C trailers as unsupported instead of
inventing memory behavior. Runtime I/O/permissions, pathname-special branches,
Java preflight/slot codes, updater extraction/exec and installed-device trust are
not executed or emulated. Dispatch reachability means only that modeled native
gates pass with the package's product/key and successful I/O assumed.

Manifest extraction deliberately uses literal final-directory offsets. Python
`ZipFile` guesses a concatenation adjustment when bytes intervene before EOCD;
that would falsely report a manifest failure on the original. A synthetic gap
regression test protects this distinction.

See [RESULTS.md](RESULTS.md) for the experiment outcome.
