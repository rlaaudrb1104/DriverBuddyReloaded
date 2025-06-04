"""
wdf.py – WDF export table locator and struct builder for DriverBuddyReloaded.

* **Public globals / function names unchanged** (populate_wdf, add_struct, …)
* Switched to `idc.get_qword` / `idc.get_wide_dword` for pointer reads; `idaapi.get_64bit` was removed in IDA 9.
* Safe pointer-size abstraction via `ptr_size` & `get_ptr` lambda.
* Uses `idc.apply_type()` (IDA ≥ 7.6) with fallback to legacy `SetType`.
* Improved `parse_binpat_str` call signature for IDA 9.1.
* Minor f‑string refactors and clearer error logs.
"""

from collections import namedtuple

import ida_bytes
import idaapi
import ida_idaapi
import idc
import ida_ida
from . import wdf_structs

VersionInfo = namedtuple("VersionInfo", ["library", "major", "minor"])

MAJOR_VERSION_OFFSET = 0x0
MINOR_VERSION_OFFSET = 0x4
WDF_FUNCTIONS_OFFSET = 0x10
STRUCT_NAME = "WDFFUNCTIONS"


def log(msg):
    print(f"[WDF]: {msg}")


# ---------------------------------------------------------------------------
# Struct definition helper
# ---------------------------------------------------------------------------

def add_struct(version):
    is64 = ida_ida.inf_is_64bit()
    FF_PTR = ida_bytes.FF_QWORD if is64 else ida_bytes.FF_DWORD
    ptr_size = 8 if is64 else 4

    # remove old definition if any
    struct_id = idc.get_struc_id(STRUCT_NAME)
    if struct_id != idc.BADADDR:
        idc.del_struc(struct_id)

    log(f"Creating struct for {version.library} Functions version {version.major}.{version.minor}")
    idc.add_struc(-1, STRUCT_NAME, 0)
    struct_id = idc.get_struc_id(STRUCT_NAME)
    if struct_id == idc.BADADDR:
        log("Failed to create struct")
        return -1

    def add_to_struct(func_name):
        idc.add_struc_member(struct_id, func_name, idc.BADADDR, ida_bytes.FF_DATA | FF_PTR, -1, ptr_size)

    wdf_library = wdf_structs.Wdfs.get(version.library)
    if not wdf_library:
        log(f"Unknown library {version.library}")
        return -1
    wdf_major = wdf_library.get(version.major)
    if not wdf_major:
        log(f"Unsupported major version {version.major}")
        return -1

    for minor in reversed(wdf_major.minors):
        if version.minor >= minor.revision:
            for fname in wdf_major.names_list[: minor.count]:
                add_to_struct(fname)
            break

    return struct_id


# ---------------------------------------------------------------------------
# Main routine – locate WDF table and apply struct
# ---------------------------------------------------------------------------

def populate_wdf():
    is64 = ida_ida.inf_is_64bit()
    ptr_size = 8 if is64 else 4
    get_ptr = (lambda ea: idc.get_qword(ea)) if is64 else (lambda ea: idc.get_wide_dword(ea))

    segments = [
        idaapi.get_segm_by_name(".data"),
        idaapi.get_segm_by_name(".rdata"),
        idaapi.get_segm_by_name("NONPAGE"),
    ]

    for seg in filter(None, segments):
        start, end = seg.start_ea, seg.end_ea
        if start == ida_idaapi.BADADDR:
            continue

        binpat = idaapi.compiled_binpat_vec_t()
        if not ida_bytes.parse_binpat_str(binpat, 0, 'L"mdfLibrary"', 16):
            continue
        idx = ida_bytes.bin_search(start, end, binpat, ida_bytes.BIN_SEARCH_NOCASE)
        if idx == ida_idaapi.BADADDR:
            continue

        actual_library = chr(ida_bytes.get_byte(idx - 2)) + "mdfLibrary"  # K/U + mdfLibrary
        log(f"Found {actual_library} string at 0x{idx - 2:X}")

        addr = idc.get_first_dref_to(idx - 2)
        if addr == idc.BADADDR:
            log("No xref to mdfLibrary string – skipping")
            continue

        version = VersionInfo(
            library=actual_library,
            major=idc.get_wide_dword(addr + ptr_size + MAJOR_VERSION_OFFSET),
            minor=idc.get_wide_dword(addr + ptr_size + MINOR_VERSION_OFFSET),
        )

        struct_id = add_struct(version)
        if struct_id == -1:
            continue

        wdf_func_ptr = get_ptr(addr + ptr_size + WDF_FUNCTIONS_OFFSET)
        size = idc.get_struc_size(struct_id)
        log(f"doStruct (size={size:#x}) at {wdf_func_ptr:#x}")
        ida_bytes.del_items(wdf_func_ptr, 0, ptr_size)

        if idc.set_name(wdf_func_ptr, f"WdfFunctions_{version.library}__{version.major}_{version.minor}", idc.SN_CHECK):
            # apply pointer-to-struct type
            if idc.apply_type(wdf_func_ptr, idaapi.tinfo_t(), idaapi.TINFO_DEMOD_PREFIX) == 0:
                # fallback for legacy IDA (<=7.5)
                idc.SetType(wdf_func_ptr, f"{STRUCT_NAME} *")
            log("Success")
        else:
            log("Failure renaming WDF function table pointer")
