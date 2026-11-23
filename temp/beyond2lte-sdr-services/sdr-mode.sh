#!/bin/sh
# sdr-mode - decide which service owns each physical SDR on the phone.
#
# Part of beyond2lte-sdr-services; see `sdr-mode help`.
#
# Model
#   devices:  lime (LimeSDR Mini 2.0, /dev/sdr/lime), rtl (RTL-SDR, /dev/sdr/rtl)
#   a mode names the one service that may open the device:
#     dedicated units  - serve exactly one device, bound to its .device unit
#                        (rtl-tcp, sdrpp-server-lime, sdrpp-server-rtl, decoder
#                        units); the selected one is `systemctl enable`d
#                        (WantedBy=dev-sdr-<dev>.device), all others are
#                        disabled + stopped. They also carry static Conflicts=.
#     shared services  - one process for both devices (SoapySDRServer,
#                        OpenWebRX). They run while they own at least one
#                        device and are told which one(s): SoapySDRServer via
#                        SOAPY_SDR_ROOT (a module directory with only that
#                        driver), OpenWebRX via the per-device "enabled" flag.
#   The choice is stored in /var/lib/sdr-mode/<device>.
set -u

PATH=/usr/sbin:/usr/bin:/sbin:/bin
STATE=${SDR_MODE_STATE:-/var/lib/sdr-mode}
RUN=${SDR_MODE_RUN:-/run/sdr-mode}
LIBEXEC=/usr/libexec/sdr-mode
REG_DIRS="/usr/lib/sdr-mode /etc/sdr-mode"
SOAPY_MODULE_DIR=/usr/lib/SoapySDR

SOAPY_UNIT=beyond2lte-sdr-server.service
SOAPY_DROPIN=/etc/systemd/system/$SOAPY_UNIT.d/50-sdr-mode.conf
OWRX_UNIT=openwebrx.service

DEVICES="lime rtl"
QUIET=0

say() { [ "$QUIET" = 1 ] || echo "$*"; }
warn() { echo "sdr-mode: $*" >&2; }
die() { warn "$*"; exit 1; }

usage() {
	cat <<'EOF'
Usage: sdr-mode [status]             who owns which SDR
       sdr-mode list                 modes that can be selected
       sdr-mode lime <mode>          soapy-remote (default) | sdrpp | openwebrx | off
                                     | <registered name> | <systemd unit>
       sdr-mode rtl <mode>           rtl_tcp (default) | sdrpp | openwebrx | soapy-remote | off
                                     | <registered name> | <systemd unit>
       sdr-mode get <lime|rtl>       print the selected mode
       sdr-mode owner <lime|rtl>     print the systemd unit that owns the device
       sdr-mode apply                re-assert the stored modes (idempotent)
       sdr-mode soapy-roots          rebuild /run/sdr-mode/soapy-* (used by the units)

Modes
  soapy-remote  SoapySDRServer (beyond2lte-sdr-server), TCP 55132 + UDP streams
  sdrpp         SDR++ server: LimeSDR on TCP 5259, RTL-SDR on TCP 5260
  rtl_tcp       rtl_tcp on TCP 1234 (rtl only)
  openwebrx     OpenWebRX+ web receiver, http://<phone>:8073/
  off           nothing opens the device
  <name|unit>   a decoder/other service: a name registered in
                /usr/lib/sdr-mode/<rtl|lime>.d/ (see `sdr-mode list`) or any
                systemd unit that follows the contract in the README there

Dedicated services only run while their device is plugged in; they start on
plug and stop on unplug. The selection is kept in /var/lib/sdr-mode.

OpenWebRX admin user (needed for the settings pages; none exists by default):
  sudo -u openwebrx openwebrx admin adduser admin
EOF
}

need_root() {
	[ "$(id -u)" = 0 ] || die "this needs root (sudo sdr-mode $*)"
}

# --- devices -------------------------------------------------------------

dev_ids() {
	case $1 in
	lime) echo "0403:601f 1d50:6108" ;;
	rtl) echo "0bda:2838 0bda:2832" ;;
	esac
}

dev_label() {
	case $1 in
	lime) echo "LimeSDR" ;;
	rtl) echo "RTL-SDR" ;;
	esac
}

default_mode() {
	case $1 in
	lime) echo soapy-remote ;;
	rtl) echo rtl_tcp ;;
	esac
}

# USB device with one of the IDs is on the bus (independent of udev)
dev_in_sysfs() {
	local id d
	for d in /sys/bus/usb/devices/*; do
		[ -r "$d/idVendor" ] || continue
		id="$(cat "$d/idVendor" 2>/dev/null):$(cat "$d/idProduct" 2>/dev/null)"
		case " $(dev_ids "$1") " in *" $id "*) return 0 ;; esac
	done
	return 1
}

# systemd knows the device (udev rule applied) - dedicated units can start
dev_plugged() {
	systemctl is-active --quiet "dev-sdr-$1.device" >/dev/null 2>&1
}

# --- modes and units -----------------------------------------------------

get_mode() {
	local m=
	[ -r "$STATE/$1" ] && m=$(head -n 1 "$STATE/$1" 2>/dev/null)
	[ -n "$m" ] || m=$(default_mode "$1")
	echo "$m"
}

# (LoadState, not `systemctl cat`: that fails while a drop-in was removed and
# the manager has not been reloaded yet)
unit_exists() {
	[ "$(systemctl show -P LoadState -- "$1" 2>/dev/null)" = loaded ]
}

# value of KEY= in a registry file (first match, quotes stripped)
reg_value() {
	sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

# registry file for <device> <name>, if any
reg_file() {
	local d
	for d in $REG_DIRS; do
		[ -f "$d/$1.d/$2.conf" ] && { echo "$d/$1.d/$2.conf"; return 0; }
	done
	return 1
}

# names registered for <device>
reg_names() {
	local d f
	for d in $REG_DIRS; do
		for f in "$d/$1.d"/*.conf; do
			[ -f "$f" ] && basename "$f" .conf
		done
	done | sort -u
}

valid_unit_name() {
	case $1 in
	"" | -* | *[!A-Za-z0-9:_.@-]*) return 1 ;;
	*.service | *.target | *.socket) return 0 ;;
	esac
	return 1
}

# The dedicated unit of <device> <mode>; empty for shared modes and "off".
# Otherwise: registered name -> its UNIT=, or the mode is itself a unit name.
unit_for() {
	local dev=$1 mode=$2 f u
	case $dev/$mode in
	*/off | */soapy-remote | */openwebrx) return 0 ;;
	lime/sdrpp) echo sdrpp-server-lime.service; return 0 ;;
	rtl/sdrpp) echo sdrpp-server-rtl.service; return 0 ;;
	rtl/rtl_tcp) echo rtl-tcp.service; return 0 ;;
	lime/rtl_tcp) return 1 ;;
	esac
	if f=$(reg_file "$dev" "$mode"); then
		u=$(reg_value "$f" UNIT)
		valid_unit_name "$u" || return 1
		echo "$u"
		return 0
	fi
	u=$mode
	case $u in *.service | *.target | *.socket) ;; *) u=$u.service ;; esac
	valid_unit_name "$u" || return 1
	echo "$u"
}

# every dedicated unit sdr-mode knows for <device>: built-in, registered and
# the one applied last time (covers unregistered decoder units)
dedicated_units() {
	local dev=$1 n f u
	{
		case $dev in
		lime) echo sdrpp-server-lime.service ;;
		rtl)
			echo rtl-tcp.service
			echo sdrpp-server-rtl.service
			;;
		esac
		for n in $(reg_names "$dev"); do
			f=$(reg_file "$dev" "$n") && u=$(reg_value "$f" UNIT) && valid_unit_name "$u" && echo "$u"
		done
		[ -r "$STATE/$dev.unit" ] && head -n 1 "$STATE/$dev.unit"
	} | grep . | sort -u
}

# can <device> <mode> be selected? prints the reason if not
check_mode() {
	local dev=$1 mode=$2 u
	case $mode in
	off) return 0 ;;
	soapy-remote)
		unit_exists $SOAPY_UNIT || { echo "$SOAPY_UNIT is not installed"; return 1; }
		return 0
		;;
	openwebrx)
		unit_exists $OWRX_UNIT || { echo "$OWRX_UNIT is not installed (apk add beyond2lte-sdr-services-openwebrx)"; return 1; }
		return 0
		;;
	esac
	u=$(unit_for "$dev" "$mode") || { echo "unknown mode '$mode' for $dev"; return 1; }
	case $u in
	$SOAPY_UNIT | $OWRX_UNIT) echo "use the mode name instead of $u"; return 1 ;;
	sdrpp-server-lime.service) [ "$dev" = lime ] || { echo "$u serves the LimeSDR"; return 1; } ;;
	sdrpp-server-rtl.service | rtl-tcp.service) [ "$dev" = rtl ] || { echo "$u serves the RTL-SDR"; return 1; } ;;
	esac
	if ! unit_exists "$u"; then
		case $mode in
		sdrpp) echo "$u is not installed (apk add beyond2lte-sdr-services-sdrpp)" ;;
		*) echo "$u does not exist" ;;
		esac
		return 1
	fi
	return 0
}

# --- actions on units ----------------------------------------------------

is_enabled() {
	case $(systemctl is-enabled -- "$1" 2>/dev/null) in
	enabled | enabled-runtime) return 0 ;;
	esac
	return 1
}

is_active() {
	case $(systemctl is-active -- "$1" 2>/dev/null) in
	active | activating | reloading) return 0 ;;
	esac
	return 1
}

# give a device up: disable + stop
release() {
	local u=$1 l
	if ! unit_exists "$u"; then
		# unit file gone (package removed): drop leftover enablement links
		for l in /etc/systemd/system/*.wants/"$u"; do
			[ -L "$l" ] && rm -f "$l" && RELOAD=1
		done
		return 0
	fi
	if is_enabled "$u" || [ -n "$(wants_link "$u")" ]; then
		say "  disable $u"
		systemctl disable --quiet -- "$u" 2>/dev/null
		rm -f $(wants_link "$u")
		RELOAD=1
	fi
	if is_active "$u"; then
		say "  stop    $u"
		systemctl stop -- "$u" || warn "could not stop $u"
	fi
}

# symlinks sdr-mode made by hand for units without an [Install] section
wants_link() {
	local dev
	for dev in $DEVICES; do
		[ -L "/etc/systemd/system/dev-sdr-$dev.device.wants/$1" ] &&
			echo "/etc/systemd/system/dev-sdr-$dev.device.wants/$1"
	done
}

# take a device with a dedicated unit: enable (start on plug) + start now
claim() {
	local dev=$1 u=$2 frag
	[ -n "$u" ] || return 0
	if ! is_enabled "$u" && [ -z "$(wants_link "$u")" ]; then
		say "  enable  $u"
		systemctl enable --quiet -- "$u" 2>/dev/null
		if ! is_enabled "$u"; then
			# no usable [Install] section: hook it to the device ourselves
			# (not `systemctl add-wants`: it refuses while the device is absent)
			frag=$(systemctl show -P FragmentPath -- "$u" 2>/dev/null)
			if [ -n "$frag" ]; then
				mkdir -p "/etc/systemd/system/dev-sdr-$dev.device.wants"
				ln -sf "$frag" "/etc/systemd/system/dev-sdr-$dev.device.wants/$u"
				systemctl daemon-reload
			else
				warn "could not enable $u (it will not start when the $(dev_label "$dev") is plugged in)"
			fi
		fi
	fi
	if is_active "$u"; then
		return 0
	fi
	if dev_plugged "$dev"; then
		say "  start   $u"
		systemctl start -- "$u" || warn "$u failed to start (journalctl -u $u)"
	elif dev_in_sysfs "$dev"; then
		warn "$(dev_label "$dev") is on the USB bus but dev-sdr-$dev.device is not active:"
		warn "  udev rule not applied yet? run: udevadm control --reload; udevadm trigger -s usb"
		warn "  then: sdr-mode apply"
	else
		say "  $(dev_label "$dev") not plugged in: $u starts when it appears"
	fi
}

# --- shared services -----------------------------------------------------

# Per-device SoapySDR roots: $RUN/soapy-<dev>/lib/SoapySDR/modulesX.Y/ holding
# only that device's driver module (symlinks). Incremental so that running
# services never see a half-built directory.
soapy_roots() {
	local dev md f base want dst
	[ "$(id -u)" = 0 ] || die "soapy-roots needs root"
	umask 022
	for dev in $DEVICES; do
		mkdir -p "$RUN/soapy-$dev/lib/SoapySDR"
		for md in "$SOAPY_MODULE_DIR"/modules*; do
			[ -d "$md" ] || continue
			dst="$RUN/soapy-$dev/lib/SoapySDR/$(basename "$md")"
			mkdir -p "$dst"
			for f in "$md"/*; do
				[ -e "$f" ] || continue
				base=$(basename "$f")
				case $base in
				*[Ll]ime*) want=lime ;;
				*[Rr][Tt][Ll]*) want=rtl ;;
				*) want= ;;
				esac
				[ "$want" = "$dev" ] && ln -sfn "$f" "$dst/$base"
			done
			# drop links whose module is gone
			for f in "$dst"/*; do
				[ -L "$f" ] && [ ! -e "$f" ] && rm -f "$f"
			done
		done
		# drop directories of a SoapySDR ABI that is no longer installed
		for dst in "$RUN/soapy-$dev/lib/SoapySDR"/modules*; do
			[ -d "$dst" ] && [ ! -d "$SOAPY_MODULE_DIR/$(basename "$dst")" ] && rm -rf "$dst"
		done
	done
	return 0
}

# which devices SoapySDRServer serves: all | lime | rtl | none
soapy_scope() {
	case $1/$2 in
	soapy-remote/soapy-remote) echo all ;;
	soapy-remote/*) echo lime ;;
	*/soapy-remote) echo rtl ;;
	*) echo none ;;
	esac
}

# write/remove the drop-in that restricts SoapySDRServer to one driver;
# sets SOAPY_CHANGED=1 if the unit's configuration changed
soapy_dropin() {
	local scope=$1 new cur=
	[ -f "$SOAPY_DROPIN" ] && cur=$(cat "$SOAPY_DROPIN")
	case $scope in
	lime | rtl)
		new="# written by sdr-mode: SoapySDRServer serves the $(dev_label "$scope") only
# (the other SDR belongs to another service). Do not edit; see sdr-mode(8).
[Service]
ExecStartPre=+/usr/bin/sdr-mode soapy-roots
Environment=SOAPY_SDR_ROOT=$RUN/soapy-$scope"
		;;
	*) new= ;;
	esac
	[ "$new" = "$cur" ] && return 0
	if [ -n "$new" ]; then
		mkdir -p "$(dirname "$SOAPY_DROPIN")"
		printf '%s\n' "$new" > "$SOAPY_DROPIN.tmp" && mv "$SOAPY_DROPIN.tmp" "$SOAPY_DROPIN"
	else
		rm -f "$SOAPY_DROPIN"
		rmdir "$(dirname "$SOAPY_DROPIN")" 2>/dev/null
	fi
	SOAPY_CHANGED=1
	systemctl daemon-reload
}

# --- apply ---------------------------------------------------------------

apply() {
	local L R ul ur u scope ol or rc
	need_root apply
	mkdir -p "$STATE"
	L=$(get_mode lime)
	R=$(get_mode rtl)
	RELOAD=0
	SOAPY_CHANGED=0

	# fall back to the default if a stored mode is no longer usable
	if ! check_mode lime "$L" >/dev/null; then
		warn "lime mode '$L' is not available ($(check_mode lime "$L")); using 'off'"
		L=off
	fi
	if ! check_mode rtl "$R" >/dev/null; then
		warn "rtl mode '$R' is not available ($(check_mode rtl "$R")); using 'off'"
		R=off
	fi
	ul=$(unit_for lime "$L")
	ur=$(unit_for rtl "$R")
	scope=$(soapy_scope "$L" "$R")
	ol=0; [ "$L" = openwebrx ] && ol=1
	or=0; [ "$R" = openwebrx ] && or=1

	say "lime -> $L, rtl -> $R"

	# 1. release: everything that must not own a device any more
	for u in $(dedicated_units lime); do
		[ "$u" = "$ul" ] || release "$u"
	done
	for u in $(dedicated_units rtl); do
		[ "$u" = "$ur" ] || release "$u"
	done

	if unit_exists $SOAPY_UNIT; then
		soapy_dropin "$scope"
		[ "$scope" = none ] && release $SOAPY_UNIT
	fi

	if [ "$ol$or" = 00 ]; then
		release $OWRX_UNIT
	elif unit_exists $OWRX_UNIT; then
		"$LIBEXEC/openwebrx-own" --check "$ol" "$or"
		rc=$?
		if [ $rc = 10 ]; then
			# settings.json is rewritten by the running server: stop first
			if is_active $OWRX_UNIT; then
				say "  stop    $OWRX_UNIT (device list changes)"
				systemctl stop $OWRX_UNIT
			fi
			"$LIBEXEC/openwebrx-own" "$ol" "$or" || warn "could not update OpenWebRX settings.json"
		elif [ $rc != 0 ]; then
			warn "could not read OpenWebRX settings.json"
		fi
	fi

	[ "$RELOAD" = 1 ] && systemctl daemon-reload

	# 2. claim
	if [ "$scope" != none ]; then
		soapy_roots
		if ! is_enabled $SOAPY_UNIT; then
			say "  enable  $SOAPY_UNIT"
			systemctl enable --quiet $SOAPY_UNIT
		fi
		if ! is_active $SOAPY_UNIT; then
			say "  start   $SOAPY_UNIT"
			systemctl start $SOAPY_UNIT || warn "$SOAPY_UNIT failed to start"
		elif [ "$SOAPY_CHANGED" = 1 ]; then
			say "  restart $SOAPY_UNIT (serves: $scope)"
			systemctl restart $SOAPY_UNIT || warn "$SOAPY_UNIT failed to restart"
		fi
	fi

	if [ "$ol$or" != 00 ]; then
		if ! is_enabled $OWRX_UNIT; then
			say "  enable  $OWRX_UNIT"
			systemctl enable --quiet $OWRX_UNIT
		fi
		if ! is_active $OWRX_UNIT; then
			say "  start   $OWRX_UNIT"
			systemctl start $OWRX_UNIT || warn "$OWRX_UNIT failed to start"
		fi
	fi

	claim lime "$ul"
	claim rtl "$ur"

	# remember what was applied (to release unregistered units later)
	echo "$ul" > "$STATE/lime.unit"
	echo "$ur" > "$STATE/rtl.unit"
	return 0
}

set_mode() {
	local dev=$1 mode=$2 why
	need_root "$dev $mode"
	case $mode in
	rtl-tcp | rtltcp) mode=rtl_tcp ;;
	soapy | soapyremote | soapy_remote | remote) mode=soapy-remote ;;
	sdr++ | sdrpp-server) mode=sdrpp ;;
	owrx) mode=openwebrx ;;
	none) mode=off ;;
	esac
	if ! why=$(check_mode "$dev" "$mode"); then
		die "$why (see: sdr-mode list)"
	fi
	mkdir -p "$STATE"
	printf '%s\n' "$mode" > "$STATE/$dev.tmp" && mv "$STATE/$dev.tmp" "$STATE/$dev"
	apply
	[ "$QUIET" = 1 ] || { echo; status; }
}

# --- reporting -----------------------------------------------------------

# owner unit of <device> for the stored mode (shared units included)
owner_unit() {
	local m
	m=$(get_mode "$1")
	case $m in
	off) ;;
	soapy-remote) echo $SOAPY_UNIT ;;
	openwebrx) echo $OWRX_UNIT ;;
	*) unit_for "$1" "$m" ;;
	esac
}

mode_endpoint() {
	local f p
	case $1/$2 in
	*/soapy-remote) echo "SoapyRemote tcp/55132" ;;
	lime/sdrpp) echo "SDR++ server tcp/5259" ;;
	rtl/sdrpp) echo "SDR++ server tcp/5260" ;;
	rtl/rtl_tcp) echo "rtl_tcp tcp/1234" ;;
	*/openwebrx) echo "http/8073" ;;
	*/off) echo "-" ;;
	*)
		if f=$(reg_file "$1" "$2"); then
			p=$(reg_value "$f" PORTS)
			echo "$(reg_value "$f" DESCRIPTION)${p:+ ($p)}"
		else
			echo "-"
		fi
		;;
	esac
}

status() {
	local dev m u st en present others o scope
	for dev in $DEVICES; do
		m=$(get_mode "$dev")
		u=$(owner_unit "$dev")
		if dev_plugged "$dev"; then
			present="plugged in ($(readlink -f "/dev/sdr/$dev" 2>/dev/null))"
		elif dev_in_sysfs "$dev"; then
			present="on the USB bus, but dev-sdr-$dev.device inactive (udev rule not applied?)"
		else
			present="not plugged in"
		fi
		echo "$(dev_label "$dev") ($dev)"
		echo "  device:   $present"
		echo "  mode:     $m$([ -r "$STATE/$dev" ] || echo " (default, never set)")"
		if [ -n "$u" ]; then
			st=$(systemctl is-active -- "$u" 2>/dev/null)
			en=$(systemctl is-enabled -- "$u" 2>/dev/null)
			echo "  owner:    $u [${st:-unknown}, ${en:-unknown}]"
		else
			echo "  owner:    -"
		fi
		echo "  endpoint: $(mode_endpoint "$dev" "$m")"
		# anything else that could hold the device?
		others=
		for o in $(dedicated_units "$dev"); do
			[ "$o" = "$u" ] && continue
			is_active "$o" && others="$others $o"
		done
		[ -n "$others" ] && echo "  WARNING:  also active:$others (run: sudo sdr-mode apply)"
	done
	if [ "$(get_mode lime)" != openwebrx ] && [ "$(get_mode rtl)" != openwebrx ] && is_active $OWRX_UNIT; then
		echo "WARNING: $OWRX_UNIT is active but owns no device (run: sudo sdr-mode apply)"
	fi
	scope=$(soapy_scope "$(get_mode lime)" "$(get_mode rtl)")
	if [ "$scope" = none ]; then
		is_active $SOAPY_UNIT && echo "WARNING: $SOAPY_UNIT is active but owns no device (run: sudo sdr-mode apply)"
	else
		echo "SoapySDRServer serves: $scope$([ -f "$SOAPY_DROPIN" ] && echo " (SOAPY_SDR_ROOT drop-in)")"
	fi
	return 0
}

list_modes() {
	local dev m n f why
	for dev in $DEVICES; do
		echo "$dev:"
		case $dev in
		lime) set -- soapy-remote sdrpp openwebrx off ;;
		rtl) set -- rtl_tcp sdrpp openwebrx soapy-remote off ;;
		esac
		for m in "$@"; do
			if why=$(check_mode "$dev" "$m"); then
				printf '  %-14s %s\n' "$m" "$(mode_endpoint "$dev" "$m")"
			else
				printf '  %-14s (unavailable: %s)\n' "$m" "$why"
			fi
		done
		for n in $(reg_names "$dev"); do
			f=$(reg_file "$dev" "$n")
			if why=$(check_mode "$dev" "$n"); then
				printf '  %-14s %s [%s]\n' "$n" "$(mode_endpoint "$dev" "$n")" "$(reg_value "$f" UNIT)"
			else
				printf '  %-14s (unavailable: %s)\n' "$n" "$why"
			fi
		done
		echo "  <unit>         any systemd unit that follows /usr/lib/sdr-mode/README"
	done
	return 0
}

# --- main ----------------------------------------------------------------

while [ $# -gt 0 ]; do
	case $1 in
	-q | --quiet) QUIET=1; shift ;;
	*) break ;;
	esac
done

cmd=${1:-status}
case $cmd in
status) status ;;
list) list_modes ;;
help | -h | --help) usage ;;
apply) apply ;;
soapy-roots) soapy_roots ;;
get)
	case ${2:-} in lime | rtl) get_mode "$2" ;; *) usage >&2; exit 64 ;; esac
	;;
owner)
	case ${2:-} in lime | rtl) owner_unit "$2" ;; *) usage >&2; exit 64 ;; esac
	;;
lime | rtl)
	if [ $# -lt 2 ]; then
		get_mode "$cmd"
	else
		set_mode "$cmd" "$2"
	fi
	;;
*)
	usage >&2
	exit 64
	;;
esac
