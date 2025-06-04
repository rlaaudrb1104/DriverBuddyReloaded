"""
ioctl_decoder.py – updated for IDA 9.1 & recent Windows device codes

* **Public names preserved** (functions, variables)
* Replaces deprecated `idc.ida_*` module access with direct `ida_*` imports
* Adds new FILE_DEVICE_* constants up to 0x5E (Win11 24H2)
* Robust operand extraction via `idc.get_operand_value()` if `get_operand_type()==5`
* File I/O wrapped in context manager and path auto‑created when needed
"""

import os
import idc
import ida_ida
import ida_search
import ida_idaapi

# ---------------------------------------------------------------------------
# Helpers for IOCTL decoding
# ---------------------------------------------------------------------------

def get_ioctl_code(ioctl_code):
    """Return (device_name, device_num) for *ioctl_code*.
    Extends coverage to recent Windows device codes."""

    device_name_unknown = "<UNKNOWN>"
    device_names = [
        device_name_unknown,  # 0x00000000
        "FILE_DEVICE_BEEP",  # 0x00000001
        "FILE_DEVICE_CD_ROM",  # 0x00000002
        "FILE_DEVICE_CD_ROM_FILE_SYSTEM",  # 0x00000003
        "FILE_DEVICE_CONTROLLER",  # 0x00000004
        "FILE_DEVICE_DATALINK",  # 0x00000005
        "FILE_DEVICE_DFS",  # 0x00000006
        "FILE_DEVICE_DISK",  # 0x00000007
        "FILE_DEVICE_DISK_FILE_SYSTEM",  # 0x00000008
        "FILE_DEVICE_FILE_SYSTEM",  # 0x00000009
        "FILE_DEVICE_INPORT_PORT",  # 0x0000000a
        "FILE_DEVICE_KEYBOARD",  # 0x0000000b
        "FILE_DEVICE_MAILSLOT",  # 0x0000000c
        "FILE_DEVICE_MIDI_IN",  # 0x0000000d
        "FILE_DEVICE_MIDI_OUT",  # 0x0000000e
        "FILE_DEVICE_MOUSE",  # 0x0000000f
        "FILE_DEVICE_MULTI_UNC_PROVIDER",  # 0x00000010
        "FILE_DEVICE_NAMED_PIPE",  # 0x00000011
        "FILE_DEVICE_NETWORK",  # 0x00000012
        "FILE_DEVICE_NETWORK_BROWSER",  # 0x00000013
        "FILE_DEVICE_NETWORK_FILE_SYSTEM",  # 0x00000014
        "FILE_DEVICE_NULL",  # 0x00000015
        "FILE_DEVICE_PARALLEL_PORT",  # 0x00000016
        "FILE_DEVICE_PHYSICAL_NETCARD",  # 0x00000017
        "FILE_DEVICE_PRINTER",  # 0x00000018
        "FILE_DEVICE_SCANNER",  # 0x00000019
        "FILE_DEVICE_SERIAL_MOUSE_PORT",  # 0x0000001a
        "FILE_DEVICE_SERIAL_PORT",  # 0x0000001b
        "FILE_DEVICE_SCREEN",  # 0x0000001c
        "FILE_DEVICE_SOUND",  # 0x0000001d
        "FILE_DEVICE_STREAMS",  # 0x0000001e
        "FILE_DEVICE_TAPE",  # 0x0000001f
        "FILE_DEVICE_TAPE_FILE_SYSTEM",  # 0x00000020
        "FILE_DEVICE_TRANSPORT",  # 0x00000021
        "FILE_DEVICE_UNKNOWN",  # 0x00000022
        "FILE_DEVICE_VIDEO",  # 0x00000023
        "FILE_DEVICE_VIRTUAL_DISK",  # 0x00000024
        "FILE_DEVICE_WAVE_IN",  # 0x00000025
        "FILE_DEVICE_WAVE_OUT",  # 0x00000026
        "FILE_DEVICE_8042_PORT",  # 0x00000027
        "FILE_DEVICE_NETWORK_REDIRECTOR",  # 0x00000028
        "FILE_DEVICE_BATTERY",  # 0x00000029
        "FILE_DEVICE_BUS_EXTENDER",  # 0x0000002a
        "FILE_DEVICE_MODEM",  # 0x0000002b
        "FILE_DEVICE_VDM",  # 0x0000002c
        "FILE_DEVICE_MASS_STORAGE",  # 0x0000002d
        "FILE_DEVICE_SMB",  # 0x0000002e
        "FILE_DEVICE_KS",  # 0x0000002f
        "FILE_DEVICE_CHANGER",  # 0x00000030
        "FILE_DEVICE_SMARTCARD",  # 0x00000031
        "FILE_DEVICE_ACPI",  # 0x00000032
        "FILE_DEVICE_DVD",  # 0x00000033
        "FILE_DEVICE_FULLSCREEN_VIDEO",  # 0x00000034
        "FILE_DEVICE_DFS_FILE_SYSTEM",  # 0x00000035
        "FILE_DEVICE_DFS_VOLUME",  # 0x00000036
        "FILE_DEVICE_SERENUM",  # 0x00000037
        "FILE_DEVICE_TERMSRV",  # 0x00000038
        "FILE_DEVICE_KSEC",  # 0x00000039
        "FILE_DEVICE_FIPS",  # 0x0000003A
        "FILE_DEVICE_INFINIBAND",  # 0x0000003B
        device_name_unknown,  # 0x0000003C
        device_name_unknown,  # 0x0000003D
        "FILE_DEVICE_VMBUS",  # 0x0000003E
        "FILE_DEVICE_CRYPT_PROVIDER",  # 0x0000003F
        "FILE_DEVICE_WPD",  # 0x00000040
        "FILE_DEVICE_BLUETOOTH",  # 0x00000041
        "FILE_DEVICE_MT_COMPOSITE",  # 0x00000042
        "FILE_DEVICE_MT_TRANSPORT",  # 0x00000043
        "FILE_DEVICE_BIOMETRIC",  # 0x00000044
        "FILE_DEVICE_PMI",  # 0x00000045
        "FILE_DEVICE_EHSTOR",  # 0x00000046
        "FILE_DEVICE_DEVAPI",  # 0x00000047
        "FILE_DEVICE_GPIO",  # 0x00000048
        "FILE_DEVICE_USBEX",  # 0x00000049
        device_name_unknown,  # 0x0000004A – 0x0000004F (reserved)
        *[device_name_unknown] * 7,
        "FILE_DEVICE_CONSOLE",  # 0x00000050
        "FILE_DEVICE_NFP",  # 0x00000051
        "FILE_DEVICE_SYSENV",  # 0x00000052
        "FILE_DEVICE_VIRTUAL_BLOCK",  # 0x00000053
        "FILE_DEVICE_POINT_OF_SERVICE",  # 0x00000054
        "FILE_DEVICE_STORAGE_REPLICATION",  # 0x00000055
        "FILE_DEVICE_TRUST_ENV",  # 0x00000056
        "FILE_DEVICE_UCM",  # 0x00000057
        "FILE_DEVICE_UCMTCPCI",  # 0x00000058
        "FILE_DEVICE_PERSISTENT_MEMORY",  # 0x00000059
    ]

    # Newer and vendor‑specific devices beyond table above
    custom_devices = [
        {"name": "FILE_DEVICE_NVDIMM", "code": 0x0000005A},
        {"name": "FILE_DEVICE_HOLOGRAPHIC", "code": 0x0000005B},
        {"name": "FILE_DEVICE_SDFXHCI", "code": 0x0000005C},
        {"name": "FILE_DEVICE_UCMUCSI", "code": 0x0000005D},
        {"name": "FILE_DEVICE_PRM", "code": 0x0000005E},
        {"name": "MOUNTMGRCONTROLTYPE", "code": 0x0000006D},
        {"name": "FILE_DEVICE_IRCLASS", "code": 0x00000F60},
    ]

    device = (ioctl_code >> 16) & 0xFFFF

    if device < len(device_names):
        return device_names[device], device

    for dev in custom_devices:
        if device == dev["code"]:
            return dev["name"], device

    return device_name_unknown, device


# ---------------------------------------------------------------------------
# Other decode helpers (unchanged public names)
# ---------------------------------------------------------------------------

def get_method(ioctl_code):
    method_names = [
        "METHOD_BUFFERED",
        "METHOD_IN_DIRECT",
        "METHOD_OUT_DIRECT",
        "METHOD_NEITHER",
    ]
    method = ioctl_code & 3
    return method_names[method], method


def get_access(ioctl_code):
    access_names = [
        "FILE_ANY_ACCESS",
        "FILE_READ_ACCESS",
        "FILE_WRITE_ACCESS",
        "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
    ]
    access = (ioctl_code >> 14) & 3
    return access_names[access], access


def get_function(ioctl_code):
    return (ioctl_code >> 2) & 0xFFF


def get_define(ioctl_code):
    function = get_function(ioctl_code)
    device_name, device_code = get_ioctl_code(ioctl_code)
    method_name, method_code = get_method(ioctl_code)
    access_name, access_code = get_access(ioctl_code)

    name = "%s_0x%08X" % (idc.get_root_filename().split(".")[0], ioctl_code)
    return "#define %s CTL_CODE(0x%X, 0x%X, %s, %s)" % (name, device_code, function, method_name, access_name)


# ---------------------------------------------------------------------------
# Dumb scanner (string‑based) – refactored for IDA 9.1 APIs
# ---------------------------------------------------------------------------

def _write_ioctl(ioctl_file_name, line):
    os.makedirs(os.path.dirname(ioctl_file_name), exist_ok=True)
    with open(ioctl_file_name, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def find_ioctls_dumb(log_file, ioctl_file_name):
    """Locate IOCTL constants by matching `"IoControlCode"` operand strings."""

    ioctl_file_name = f"{ioctl_file_name}_dumb.txt"
    result = False

    print("[>] Searching for IOCTLs found by IDA…")
    log_file.write("[>] Searching for IOCTLs found by IDA…\n")

    cur = ida_ida.inf_get_min_ea()
    maxea = ida_ida.inf_get_max_ea()

    while cur < maxea:
        cur = ida_search.find_text(cur, 0, 0, "IoControlCode", ida_search.SEARCH_DOWN)
        if cur == ida_idaapi.BADADDR:
            break

        for op_idx in (0, 1):
            if idc.get_operand_type(cur, op_idx) == 5:  # immediate
                ioctl_code = idc.get_operand_value(cur, op_idx)
                if ioctl_code is None:
                    continue

                function = get_function(ioctl_code)
                device_name, device_code = get_ioctl_code(ioctl_code)
                method_name, method_code = get_method(ioctl_code)
                access_name, access_code = get_access(ioctl_code)

                line = (
                    "0x{cur:016X} : 0x{ioctl_code:08X} | {device_name:<31} 0x{device_code:08X} | "
                    "0x{function:08X} | {method_name:<17} {method_code:<4d} | {access_name} ({access_code})".format(
                        cur=cur,
                        ioctl_code=ioctl_code,
                        device_name=device_name,
                        device_code=device_code,
                        function=function,
                        method_name=method_name,
                        method_code=method_code,
                        access_name=access_name,
                        access_code=access_code,
                    )
                )
                print(line)
                log_file.write(line + "\n")
                _write_ioctl(ioctl_file_name, line)
                result = True
        cur = idc.next_head(cur)
    return result
