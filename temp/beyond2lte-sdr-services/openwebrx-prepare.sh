#!/bin/sh
# ExecStartPre of openwebrx.service (runs as user openwebrx): make sure the
# data files exist with sane permissions. No admin user is created here -
# see "sdr-mode help" / NOTES: sudo -u openwebrx openwebrx admin adduser admin
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
d=/var/lib/openwebrx
umask 027
# first start: packaged receiver definition (LimeSDR + RTL-SDR)
if [ ! -s "$d/settings.json" ] || [ "$(tr -d ' \n\t' < "$d/settings.json")" = "{}" ]; then
	cp /usr/share/sdr-mode/openwebrx-settings.json "$d/settings.json"
fi
umask 077
[ -e "$d/users.json" ] || echo "[]" > "$d/users.json"
[ -e "$d/bookmarks.json" ] || echo "[]" > "$d/bookmarks.json"
exit 0
