# X70 APK installer development

Development payload in a fork of prsyahmi/proton_firmware, upstream commit
111e5b27c6215e433af6327abb3ccd19e0e25b45. Original source remains unchanged.

This is NOT a flashable update.zip and does not solve package verification.
The public upstream supplies installer sources but not the complete package
construction exploit. Installed Pakistan firmware compatibility is unknown.

## Behavior

Scans /storage/udisk/apk, /storage/udisk1/apk and /storage/udisk2/apk.
Sorts APK paths, skips symlinks, bounds recursion and count, and calls
/system/bin/pm install -r using exec rather than a shell. Stops on a nonzero
package-manager exit status. Reports actual payload completion.
Does not format partitions, run custom scripts, change settings or reboot.
No rollback of APKs already installed if a later APK fails.

Dry-run mode performs discovery only and does not parse APK compatibility.
The normal payload must run in a live Android context with package-manager
access. Recovery-only execution is not established. Exit-code and progress
handling by the car's wrapper are NOT verified; upstream returned 1 on normal
completion, while this payload returns 0 on success. Do not insert this binary
into the existing archive until wrapper behavior is understood.

## Build Android ARMv7

Use Android NDK r21e (supports android-19). From this directory on Windows:

```powershell
& "$env:ANDROID_NDK_HOME\ndk-build.cmd" NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk NDK_APPLICATION_MK=jni/Application.mk
```

Expected output: libs/armeabi-v7a/x70-apk-installer. NDK build and on-device
execution have not been performed in this environment.

## Host checks (Linux)

```sh
gcc -std=c99 -Wall -Wextra -Werror -o /tmp/x70-installer-test jni/install.c
X70_TEST_BINARY=/tmp/x70-installer-test python3 -m unittest discover -s tests -v
```

Eight host tests passed: empty/missing directories, sorted recursive discovery,
shell metacharacter names, symlink skipping, maximum count, newline rejection,
recursion bounds and invalid invocation (some assertions share a test).
These tests do not establish Android package installation or OTA acceptance.

## Next milestone

Build ARMv7 with the NDK; test package-manager result handling in an isolated
Android environment; trace the verifier and execution wrapper from the locally
available firmware. Only then integrate a documented package format.

Keep original firmware, device identifiers and forensic dumps out of this public
repository. This directory contains only source and synthetic tests.
