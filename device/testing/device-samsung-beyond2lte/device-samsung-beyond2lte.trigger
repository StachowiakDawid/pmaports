#!/bin/sh
# apk trigger on /usr/lib/systemd/boot/efi: a systemd-boot install/upgrade
# brings back the byte-swapped menu separator (see beyond2lte-sdboot-wchar-fix).
# Patch the packaged app and the copy on the ESP that U-Boot starts.
/usr/libexec/beyond2lte-sdboot-wchar-fix /usr/lib/systemd/boot/efi/*.efi \
	/boot/EFI/BOOT/BOOTAA64.EFI || true
exit 0
