# Clean-package experiment result

The two-entry clean ZIP is structurally valid but **fails authentication**. It is
retained locally as an offline experimental artifact, not an accepted installer.

| Reconstructed native gate | Unchanged original | Clean ZIP |
|---|---|---|
| Trailer/MD5 | Pass; 196-byte suffix excluded | Markers absent; return 1, continue with suffix 0 |
| Package recovery-key loading | Pass | Pass |
| RSA signature gate | Pass, including native padding check | **Fail:** final six bytes lack `ff ff` footer marker; RSA operation not attempted |
| Native ZIP selection | Pass; final two-entry directory | Not reached after authentication failure |
| Native manifest/project | Pass; selected build 453 | Not reached after authentication failure |
| First failing modeled gate | None | Signature/footer authentication |
| Updater dispatch reachable under model | Yes, assuming successful runtime I/O | **No** |
| Updater actually executed | No | No |

Independent clean-ZIP checks pass: exactly two unique entries, byte-identical
selected manifest and ARM updater, one central directory, correct offsets, all
CRCs, no ZIP comment or trailing bytes. Its standalone manifest/project check
also passes; this does not imply the native chain reaches it.

The clean ZIP is 10,580 bytes. Local headers are at 0 and 534; central directory
is `[10409,10558)`, EOCD `[10558,10580)`. There are no earlier firmware entries.
SHA256: `4897dad48448374c1945725d6137518928783620e8406b828a6f024ec86de1e8`.
7-Zip 26.06 `t` returned 0, “Everything is Ok”, two files, no extra-data warnings.
All **23 synthetic tests** passed, covering parser fixtures, deterministic build,
overwrite refusal, corruption, offset/trailer checks and verifier short circuits.

The original size and SHA256 remain unchanged. No signature was reused on the
clean ZIP; no private/signing key was created, no target binary was executed,
and no USB/vehicle test occurred. The clean archive and all firmware/key/device
evidence remain outside Git. Package-version verification does not establish
acceptance by an installed head unit. Authentication cannot be resolved merely
by making the ZIP conventional.
