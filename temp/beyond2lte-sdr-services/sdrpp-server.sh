#!/bin/sh
# sdrpp-server <lime|rtl> - start one SDR++ server instance (run by
# sdrpp-server-<instance>.service as user sdr).
#
# Each instance has its own root directory and only sees "its" device:
#  lime: SoapySDR source, SoapySDR restricted to the LimeSuiteNG module
#  rtl:  native RTL-SDR source (+ SoapySDR restricted to the rtlsdr module)
# so a client of one instance can never grab the other SDR, and the SoapyRemote
# client module is not loaded (it would list the phone's own SoapySDRServer).
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
inst=${1:?usage: sdrpp-server <lime|rtl>}
case $inst in
lime)
	port=${SDRPP_LIME_PORT:-5259}
	modules='"SoapySDR Source": {"module": "soapy_source", "enabled": true}'
	source=SoapySDR
	;;
rtl)
	port=${SDRPP_RTL_PORT:-5260}
	modules='"RTL-SDR Source": {"module": "rtl_sdr_source", "enabled": true},
        "SoapySDR Source": {"module": "soapy_source", "enabled": true}'
	source=RTL-SDR
	;;
*)
	echo "sdrpp-server: unknown instance '$inst'" >&2
	exit 64
	;;
esac
root=${SDRPP_ROOT:-/var/lib/sdrpp-server/$inst}
mkdir -p "$root"
# SDR++ fills in every key that is missing, so a partial config is enough.
if [ ! -s "$root/config.json" ]; then
	cat > "$root/config.json" <<JSON
{
    "moduleInstances": {
        $modules
    },
    "modules": [],
    "source": "$source"
}
JSON
fi
export SOAPY_SDR_ROOT=/run/sdr-mode/soapy-$inst
exec /usr/bin/sdrpp --server --addr "${SDRPP_ADDRESS:-0.0.0.0}" --port "$port" --root "$root"
