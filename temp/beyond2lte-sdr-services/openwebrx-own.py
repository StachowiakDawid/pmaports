#!/usr/bin/python3 -I
"""openwebrx-own [--check] <lime:0|1> <rtl:0|1>

Switch the "enabled" flag of the SDR devices in OpenWebRX's settings.json
according to which physical SDRs OpenWebRX currently owns (called by
sdr-mode as root while openwebrx.service is stopped).

Devices are matched by type: lime_sdr -> LimeSDR; rtl_sdr, rtl_sdr_soapy ->
RTL-SDR. Other device types are left alone. If settings.json does not exist
yet it is created from the packaged template.

--check: change nothing; exit 10 if a change would be made, 0 if not.
"""
import json
import os
import shutil
import sys

SETTINGS = os.environ.get("OPENWEBRX_SETTINGS", "/var/lib/openwebrx/settings.json")
TEMPLATE = "/usr/share/sdr-mode/openwebrx-settings.json"
TYPES = {"lime_sdr": 0, "rtl_sdr": 1, "rtl_sdr_soapy": 1}


def main():
    args = sys.argv[1:]
    check = False
    if args and args[0] == "--check":
        check = True
        args = args[1:]
    if len(args) != 2 or any(a not in ("0", "1") for a in args):
        sys.stderr.write(__doc__)
        return 64
    want = [a == "1" for a in args]

    path = SETTINGS
    seeded = False
    try:
        with open(path) as f:
            settings = json.load(f)
    except (FileNotFoundError, ValueError):
        settings = {}
    if not settings:
        with open(TEMPLATE) as f:
            settings = json.load(f)
        seeded = True

    changed = seeded
    sdrs = settings.get("sdrs")
    if isinstance(sdrs, dict):
        for dev in sdrs.values():
            if not isinstance(dev, dict) or dev.get("type") not in TYPES:
                continue
            enabled = want[TYPES[dev["type"]]]
            if dev.get("enabled", True) != enabled:
                dev["enabled"] = enabled
                changed = True

    if not changed:
        return 0
    if check:
        return 10

    d = os.path.dirname(path)
    if not os.path.isdir(d):
        # before the first start (systemd creates the StateDirectory then)
        import pwd

        pw = pwd.getpwnam("openwebrx")
        os.makedirs(d, mode=0o750)
        os.chown(d, pw.pw_uid, pw.pw_gid)
    st = os.stat(d)
    if os.path.exists(path):
        shutil.copy2(path, path + ".sdr-mode.bak")
        os.chown(path + ".sdr-mode.bak", st.st_uid, st.st_gid)
    tmp = path + ".sdr-mode.tmp"
    with open(tmp, "w") as f:
        json.dump(settings, f, indent=4)
        f.write("\n")
    os.chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
