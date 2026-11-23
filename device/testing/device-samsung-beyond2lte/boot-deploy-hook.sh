#!/bin/sh
# boot-deploy hook (device-samsung-beyond2lte): make the systemd-boot menu
# reachable. Runs on every boot-deploy (kernel/initramfs install, mkinitfs),
# before boot-deploy copies its files. boot-deploy itself never writes
# loader.conf, and without one systemd-boot uses timeout 0 (no menu).
#
# In the menu (U-Boot stdin = button-kbd, CONFIG_BUTTON_REMAP_PHONE_KEYS):
#   Vol-Up = Up, Vol-Down = Down, Power = Enter.
# Remove the "managed" line below from loader.conf to keep local edits.
ESP=/boot
CONF=$ESP/loader/loader.conf
MARK="# managed by device-samsung-beyond2lte"
TIMEOUT=3
[ -r /etc/default/beyond2lte-boot ] && . /etc/default/beyond2lte-boot
TIMEOUT=${MENU_TIMEOUT:-$TIMEOUT}

# systemd-boot on musl: byte-swapped L'x' constants show the menu separator as
# a row of '%'. boot-deploy copies the app after the hooks ran, so fix it here.
[ -x /usr/libexec/beyond2lte-sdboot-wchar-fix ] &&
	/usr/libexec/beyond2lte-sdboot-wchar-fix /usr/lib/systemd/boot/efi/*.efi || true

[ -d "$ESP" ] || exit 0
if [ -e "$CONF" ] && ! grep -qF "$MARK" "$CONF"; then
	echo "==> beyond2lte: $CONF is locally modified, leaving it alone"
	exit 0
fi
mkdir -p "$ESP/loader"
# No "default": systemd-boot then boots the first entry in sort order, which
# is pmos.conf (sort-key postmarketOS) unless boot counting marked it bad;
# then it is the known-good fallback (sort-key postmarketOS-fallback-1).
cat > "$CONF.tmp" <<EOT
$MARK (boot-deploy hook)
timeout $TIMEOUT
editor no
auto-firmware no
console-mode keep
EOT
if ! cmp -s "$CONF.tmp" "$CONF"; then
	mv "$CONF.tmp" "$CONF"
	echo "==> beyond2lte: wrote $CONF (menu timeout ${TIMEOUT}s)"
else
	rm -f "$CONF.tmp"
fi
exit 0
