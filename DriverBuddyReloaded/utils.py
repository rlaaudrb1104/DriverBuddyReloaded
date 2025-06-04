"""
utils.py – core helpers for DriverBuddyReloaded

* **Public/global variable names unchanged** (`functions_map`, `imports_map`, …)
* Optimised `get_driver_id()` – direct key look‑ups instead of linear scan
* `is_driver()` now first tries symbol lookup (`get_name_ea_simple`) before full segment walk and supports decorated exports (`DriverEntry@0`, etc.)
* Removed unused `math` import; modernised prints to f‑strings
* Minor safety tweaks (skip NULL import names in callback)
"""

import time
from datetime import date

import ida_funcs
import ida_nalt
import ida_segment
import idautils
import idc
from DriverBuddyReloaded.vulnerable_functions_lists.c import *
from DriverBuddyReloaded.vulnerable_functions_lists.custom import *
from DriverBuddyReloaded.vulnerable_functions_lists.opcode import *
from DriverBuddyReloaded.vulnerable_functions_lists.winapi import *
from .find_opcodes import find
from .wdf import populate_wdf
from .wdm import (
    check_for_fake_driver_entry,
    locate_ddc,
    define_ddc,
    find_dispatch_function,
)

# ----------------------------------------------------------------------------
# Maps collecting addresses of interesting routines
# ----------------------------------------------------------------------------
functions_map = {}
imports_map = {}
c_map = {}
winapi_map = {}
driver_map = {}


# ----------------------------------------------------------------------------
# Simple helpers
# ----------------------------------------------------------------------------

def timestamp():
    return str(int(time.time()))


def today():
    return str(date.today())


# ----------------------------------------------------------------------------
# Import enumeration callback
# ----------------------------------------------------------------------------

def cb(address, name, ord):
    if not name:
        return True  # skip unnamed import entries
    imports_map[name] = address
    functions_map[name] = address
    return True


# ----------------------------------------------------------------------------
# Population helpers
# ----------------------------------------------------------------------------

def populate_function_map():
    result = False
    # sub_ functions
    for address in idautils.Functions():
        func_name = idc.get_func_name(address)
        if func_name:
            functions_map[func_name] = address
            result = True
    # imports
    for index in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(index, cb)
        result = True
    return result


def populate_c_map():
    result = False
    for name, address in functions_map.items():
        if name in c_functions:
            c_map[name] = address
            result = True
    return result


def populate_winapi_map():
    result = False
    for name, address in functions_map.items():
        if name in winapi_functions:
            winapi_map[name] = address
            result = True
        else:
            for winapi in winapi_function_prefixes:
                if name.lower().startswith(winapi.lower()):
                    winapi_map[name] = address
                    result = True
                    break
    return result


def populate_driver_map():
    result = False
    for name, address in functions_map.items():
        if name in driver_functions:
            driver_map[name] = address
            result = True
    return result


# ----------------------------------------------------------------------------
# Bulk discovery routine
# ----------------------------------------------------------------------------

def populate_data_structures(log_file):
    if not populate_function_map():
        print("[!] ERR: Couldn't populate function_map")
        log_file.write("[!] ERR: Couldn't populate function_map\n")
        return False

    # --- opcode search ------------------------------------------------------
    print("[>] Searching for interesting opcodes…")
    log_file.write("[>] Searching for interesting opcodes…\n")
    for opcode in opcodes:
        find(log_file, opcode, x=True)

    # --- C runtime ----------------------------------------------------------
    print("[>] Searching for interesting C/C++ functions…")
    log_file.write("[>] Searching for interesting C/C++ functions…\n")
    if populate_c_map():
        get_xrefs(c_map, log_file)

    # --- WinAPI -------------------------------------------------------------
    print("[>] Searching for interesting Windows APIs…")
    log_file.write("[>] Searching for interesting Windows APIs…\n")
    if populate_winapi_map():
        get_xrefs(winapi_map, log_file)

    # --- Driver‑specific helpers -------------------------------------------
    if driver_functions:
        print("[>] Searching for interesting driver functions…")
        log_file.write("[>] Searching for interesting driver functions…\n")
        if populate_driver_map():
            get_xrefs(driver_map, log_file)

    return True


# ----------------------------------------------------------------------------
# X‑ref helper
# ----------------------------------------------------------------------------

def get_xrefs(func_map, log_file):
    for name, address in func_map.items():
        for ref in idautils.CodeRefsTo(int(address), 0):
            n = ida_funcs.get_func_name(ref) or ida_segment.get_segm_name(ida_segment.getseg(ref))
            print(f"\t- Found {name} in {n} at 0x{ref:08X}")
            log_file.write(f"\t- Found {name} in {n} at 0x{ref:08X}\n")


# ----------------------------------------------------------------------------
# Driver‑type detection / misc helpers
# ----------------------------------------------------------------------------

# def get_driver_id(driver_entry_addr, log_file):
#     driver_type = ""

#     if "FltRegisterFilter" in imports_map:
#         driver_type = "Mini-Filter"
#     elif "WdfVersionBind" in imports_map:
#         driver_type = "WDF"
#         populate_wdf()
#     elif "StreamClassRegisterMinidriver" in imports_map:
#         driver_type = "Stream Minidriver"
#     elif "KsCreateFilterFactory" in imports_map:
#         driver_type = "AVStream"
#     elif "PcRegisterSubdevice" in imports_map:
#         driver_type = "PortCls"

#     if not driver_type:
#         print("[!] Unable to determine driver type; assuming WDM")
#         log_file.write("[!] Unable to determine driver type; assuming WDM\n")
#         driver_type = "WDM"
#         real_driver_entry = check_for_fake_driver_entry(driver_entry_addr, log_file)
#         real_ddc_addr = locate_ddc(real_driver_entry, log_file)
#         if real_ddc_addr:
#             for ddc in real_ddc_addr.values():
#                 define_ddc(ddc)
#         find_dispatch_function(log_file)

#     return driver_type

DRIVER_SIGS = {
    # WDM/Generic ──────────────────────────────────────
    # (아무 시그니처에도 안 맞으면 최종적으로 'WDM' 으로 분류)
    "WDM": [],  # fallback

    # WDF - KMDF (커널 모드 프레임워크)
    "KMDF": [
        "WdfVersionBind",           # 필수 – kmdf.sys
        "WdfDriverCreate",
        "WdfObjectDelete"
    ],

    # 파일시스템 계열 ───────────────────────────────────
    "FS Mini-Filter": [            # FltMgr 기반
        "FltRegisterFilter",
        "FltStartFiltering"
    ],
    "Legacy FS Filter": [          # 옛날 IoAttachDevice 방식
        "IoRegisterFsRegistrationChange",
        "FsRtlRegisterFileSystemFilterCallbacks"
    ],
    "Filesystem Driver": [         # 자체 파일시스템 (NTFS, exFAT 등과 같은 FSD)
        "FsRtlInsertPerFileContext",
        "CcInitializeCacheMap"
    ],

    # 네트워크 스택 ─────────────────────────────────────
    "NDIS 6.x Miniport": [
        "NdisMRegisterMiniportDriver",
        "NdisMSetMiniportAttributes"
    ],
    "NDIS 6.x Filter": [
        "NdisFRegisterFilterDriver",
        "NdisFSetAttributes"
    ],
    "NDIS Legacy IM": [           # IM = Intermediate Driver (NDIS 5.x)
        "NdisIMInitializeDeviceInstanceEx"
    ],

    # 스토리지/버스 미니포트 ─────────────────────────────
    "StorPort Miniport": [
        "StorPortInitialize"
    ],
    "SCSIport Miniport": [
        "ScsiPortInitialize"
    ],
    "ATAport Miniport": [
        "AtaPortInitialize"
    ],
    "NVMe Miniport": [            # 최신 NVMe 스택
        "NvmeInitializeController"
    ],

    # 오디오/미디어 ────────────────────────────────────
    "PortCls (Audio)": [
        "PcRegisterSubdevice",
        "PcInitializeAdapterDescriptor"
    ],
    "AVStream (KS)": [
        "KsCreateFilterFactory",
        "KsAddItemToObjectTable"
    ],
    "BDA (TV/튜너)": [
        "BdaCreateFilterFactory"
    ],

    # 입력/센서 ─────────────────────────────────────────
    "HID Mini-driver": [
        "HidRegisterMinidriver"
    ],
    "GPIO CLX Client": [
        "GpioClxRegisterClient"
    ],
    "SPB (I²C/SPI) Controller": [
        "SpbDeviceInitialize"
    ],

    # USB 스택 ──────────────────────────────────────────
    "USB Function Driver (WDM)": [
        "USBD_CreateConfigurationRequestEx",
        "USBPORT_GetDevicePowerState"
    ],
    "USB Filter Driver": [
        "UsbRegisterTraceProvider"  # 예: xhci/ehci 필터
    ],

    # 네트워크 보안/필터링 ───────────────────────────────
    "WFP Callout": [
        "FwpmEngineOpen0",
        "FwpsCalloutRegister"
    ],

    # 리디렉터/미니 리다이렉터 ──────────────────────────
    "RDBSS Mini-Redirector": [
        "RxDriverEntry",
        "RxRegisterMiniRedirector"
    ],

    # 가상화/보안/전원 관리 등 기타 ───────────────────
    "ACPI Filter": [
        "AcpiAcquireGlobalLock"
    ],
    "PoFx Power-Managed": [
        "PoFxRegisterDevice"
    ],
    "Hyper-V VMBus": [
        "VmbChannelAllocate"
    ],
}
    
#     if not driver_type:
#         print("[!] Unable to determine driver type; assuming WDM")
#         log_file.write("[!] Unable to determine driver type; assuming WDM\n")
#         driver_type = "WDM"
#         real_driver_entry = check_for_fake_driver_entry(driver_entry_addr, log_file)
#         real_ddc_addr = locate_ddc(real_driver_entry, log_file)
#         if real_ddc_addr:
#             for ddc in real_ddc_addr.values():
#                 define_ddc(ddc)
#         find_dispatch_function(log_file)


def get_driver_id(driver_entry_addr, log_file):
    """
    imports_map: set 또는 list 형태의 Import 심볼 이름 모음
    driver_entry_addr: PE의 DriverEntry 주소
    log_file: open()-한 파일 객체
    """
    # 대소문자 무시용 lowercase 집합
    lower_imports = {s.lower() for s in imports_map}

    # ─ 1단계: 시그니처 사전 매칭 ────────────────────────
    driver_type = ""
    for dtype, sigs in DRIVER_SIGS.items():
        if any(sig.lower() in lower_imports for sig in sigs):
            driver_type = dtype
            break

    # ─ 2단계: 타입별 후처리(기존 로직 유지) ──────────────
    if driver_type == "WDF":            # WDF이면 추가 파싱
        populate_wdf()
    elif driver_type == "":             # 아무 시그니처에도 안 맞음 → WDM
        print("[!] Unable to determine driver type; assuming WDM")
        log_file.write("[!] Unable to determine driver type; assuming WDM\n")
        driver_type = "WDM"
        real_driver_entry = check_for_fake_driver_entry(driver_entry_addr, log_file)
        real_ddc_addr = locate_ddc(real_driver_entry, log_file)
        if real_ddc_addr:
            for ddc in real_ddc_addr.values():
                define_ddc(ddc)
        find_dispatch_function(log_file)

    return driver_type



def is_driver():
    """Return the address of `DriverEntry` if present, otherwise **False**."""

    for symbol in ("DriverEntry", "DriverEntry_0", "DriverEntry@0"):
        ea = idc.get_name_ea_simple(symbol)
        if ea != idc.BADADDR:
            return ea

    for ea in idautils.Functions():
        if idc.get_func_name(ea) in ("DriverEntry", "DriverEntry_0"):
            return ea
    return False
