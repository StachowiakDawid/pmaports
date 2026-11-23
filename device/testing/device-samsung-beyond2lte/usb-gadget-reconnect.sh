#!/bin/sh
# After a warm reboot the DWC3 gadget often stays "not attached" until the cable
# is replugged (soft_connect toggling doesn't help). Re-initialise the USB PHY and
# DWC3 controller and rebind the configfs gadget, like a fresh probe.
# Usage: usb-gadget-reconnect.sh [--now]   (--now: reset once, unconditionally)
UDC=10c00000.usb
GLUE=soc@0:usb@10c00000
PHY=10b00000.phy
G=$(ls -d /sys/kernel/config/usb_gadget/*/ 2>/dev/null | head -1)

reset_usb() {
    echo "resetting USB (PHY + DWC3), state was $(cat /sys/class/udc/$UDC/state 2>/dev/null)"
    [ -n "$G" ] && echo "" > "$G/UDC" 2>/dev/null
    echo $GLUE > /sys/bus/platform/drivers/exynos-dwc3/unbind
    sleep 1
    echo $GLUE > /sys/bus/platform/drivers/exynos-dwc3/bind
    for i in 1 2 3 4 5 6 7 8 9 10; do [ -e /sys/class/udc/$UDC ] && break; sleep 0.5; done
    [ -n "$G" ] && echo $UDC > "$G/UDC"
}

# I2C bus of the MAX77705 (top-level PMIC at 0x66): the bus number changes when the DT adds
# I2C controllers (it moved from i2c-2 to i2c-4 with U-Boot r8), so look it up.
MXBUS=$(basename "$(dirname "$(readlink -f /sys/bus/i2c/devices/*-0066 2>/dev/null | head -1)")" 2>/dev/null | sed "s/^i2c-//")
case "$MXBUS" in ""|*[!0-9]*) MXBUS=2 ;; esac
# MAX77705 USB-C MCU opcode interface (I2C bus $MXBUS, 0x25): opcode at 0x21,
# data at 0x22.., commit by writing 0x41; read response at 0x51 (echo) 0x52..
mx_op_read() { i2crw $MXBUS 0x25 0x21 w $1; i2crw $MXBUS 0x25 0x41 w 0x00; sleep 0.1; i2crw $MXBUS 0x25 0x52 1; }
mx_ctrl1_usb() { i2crw $MXBUS 0x25 0x21 w 0x06 0x09; i2crw $MXBUS 0x25 0x41 w 0x00; sleep 0.1; }  # CTRL1_W = COM_USB

# After a warm reboot the MAX77705 may leave D+/D- switched away from the AP.
# The max77705-usbc kernel driver does this itself (and owns the opcode
# interface; concurrent opcodes from userspace would race with it), so only
# fall back to i2crw when that driver is not bound.
MXDRV=/sys/bus/i2c/drivers/max77705-usbc/$MXBUS-0025
# The driver loads at boot (r9): give udev time to bind it before falling back.
if modinfo max77705_usbc >/dev/null 2>&1; then
    for i in $(seq 1 30); do [ -e $MXDRV ] && break; sleep 0.5; done
fi
if [ -e $MXDRV ]; then
    echo "max77705-usbc driver bound, skipping userspace MUIC fix"
elif command -v i2crw >/dev/null; then
    c1=$(mx_op_read 0x05 2>&1)
    echo "max77705 CTRL1 = $c1 (COM_USB = 09)"
    if [ "$c1" != 09 ]; then
        mx_ctrl1_usb; echo "max77705 CTRL1 -> $(mx_op_read 0x05 2>&1) after CTRL1_W 0x09"
    fi
fi

# pd5: the max77705-usbc driver may have made DWC3 a USB host (OTG device, or
# PD hub after DR_Swap). Then there is no gadget to fix, and a DWC3 rebind
# would drop the host role (the LimeSDR/Ethernet behind the hub).
is_host() { grep -qx host /sys/class/usb_role/*/role 2>/dev/null ||
            grep -q '\[host\]' /sys/class/typec/port0/data_role 2>/dev/null; }

if [ "$1" = --now ]; then reset_usb; exit 0; fi
# MAX77705 USB-C/MUIC block (I2C bus $MXBUS, 0x25) state, for debugging the warm-boot issue
[ ! -e $MXDRV ] && command -v i2crw >/dev/null && echo "max77705 usbc 0x00-0x0f: $(i2crw $MXBUS 0x25 0x00 16 2>&1)"
for try in 1 2 3; do
    sleep 5
    st=$(cat /sys/class/udc/$UDC/state 2>/dev/null)
    [ "$st" = configured ] && { echo "USB configured"; exit 0; }
    is_host && { echo "USB is in host mode (typec data role host), not resetting DWC3"; exit 0; }
    [ -e $MXDRV ] && cat /sys/kernel/debug/$MXBUS-0025/state 2>/dev/null
    reset_usb
done
echo "USB still $(cat /sys/class/udc/$UDC/state 2>/dev/null) after 3 resets"
exit 0
