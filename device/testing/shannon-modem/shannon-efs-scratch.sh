#!/bin/sh
# Make a scratch copy of the EFS files the CP asks for over RFS, on tmpfs.
#
# The efs partition is NEVER mounted: debugfs opens the block device read-only (no -w) and
# dumps files into the tmpfs directory.  The copy disappears at reboot and must never be
# written back.  Only the NV files and efs/root (the CP's own RFS area) are copied; tee, DAK,
# prov, wifi and bluetooth are left alone.
#
#   shannon-efs-scratch.sh [DIR]     default DIR=/run/shannon-efs   (run as root)
set -eu
DIR=${1:-/run/shannon-efs}
EFS=/dev/disk/by-partlabel/efs

case $(stat -f -c %T "$(dirname "$DIR")") in
	tmpfs|ramfs) ;;
	*) echo "$(dirname "$DIR") is not tmpfs; refusing" >&2; exit 1 ;;
esac
if findmnt -S "$(readlink -f $EFS)" >/dev/null; then
	echo "efs is mounted somewhere; refusing (expected unmounted)" >&2
	exit 1
fi
[ -e "$DIR" ] && { echo "$DIR exists; remove it first if you want a fresh copy" >&2; exit 1; }

umask 077
mkdir -p "$DIR"
for f in nv_data.bin nv_data.bin.md5 .nv_data.bak .nv_data.bak.md5 .nv_state; do
	debugfs -R "dump -p /$f $DIR/$f" $EFS >/dev/null 2>&1 || echo "warning: no /$f" >&2
done
debugfs -R "rdump /root $DIR" $EFS >/dev/null 2>&1 || echo "warning: no /root" >&2
mkdir -p "$DIR/log" "$DIR/etc"
size=$(stat -c %s "$DIR/nv_data.bin")
[ "$size" = 1048576 ] || { echo "nv_data.bin has size $size, expected 1048576" >&2; exit 1; }
echo "scratch EFS in $DIR:"
find "$DIR" -type f | sed "s|^$DIR/||" | sort | tr '\n' ' '
echo
