"""
DeviceName finding functions.
Searches the raw binary for UTF‑16LE strings that look like Windows DeviceNames.

* Keeps the original public API (variable / function names unchanged).
* Fixes Python 3 `bytes`/`str` comparison bug in REPEATS test.
* Uses IDA 9.1‑safe `ida_nalt.get_input_file_path()` for reliable input path.
* Makes `buf_filled_with()` agnostic to byte / int input and avoids needless
  re‑allocations.
* Closes the `mmap` explicitly via context manager.
"""

import collections
import mmap
import re
from pathlib import Path

import ida_nalt

# ── constants ────────────────────────────────────────────────────────────────
ASCII_BYTE = (
    b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
    b"abcdefghijklmnopqrstuvwxyz{|}~\t"
)
# pre‑compiled regex for ≥4‑char UTF‑16LE strings
UNICODE_RE_4 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
# compare against ints – avoids bytes/str mismatch under Py3
REPEATS = [ord("A"), 0x00, 0xFE, 0xFF]
SLICE_SIZE = 4096

String = collections.namedtuple("String", ["s", "offset"])


# ── helpers ──────────────────────────────────────────────────────────────────

def buf_filled_with(buf, character):
    """Return **True** if *buf* is entirely filled with *character* (int/byte)."""

    if isinstance(character, (bytes, bytearray)):
        character = character[0]
    filler = bytes([character]) * SLICE_SIZE
    for offset in range(0, len(buf), SLICE_SIZE):
        chunk = buf[offset : offset + SLICE_SIZE]
        if filler[: len(chunk)] != chunk:
            return False
    return True


def extract_unicode_strings(buf, n=4):
    """Yield UTF‑16LE strings of length ≥ *n* from *buf*."""

    if not buf:
        return
    # fast‑path for homogenous padding blobs (\x00, 0xFF etc.)
    first_byte = buf[0]
    if (first_byte in REPEATS) and buf_filled_with(buf, first_byte):
        return

    regex = UNICODE_RE_4 if n == 4 else re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n))
    for match in regex.finditer(buf):
        try:
            yield String(match.group().decode("utf-16le"), match.start())
        except UnicodeDecodeError:
            pass  # ignore undecodable chunks


# ── public API ───────────────────────────────────────────────────────────────

def get_unicode_device_names():
    """Return a *set* of potential DeviceName strings found in the input binary."""

    # get full path to the analysed file (works in IDA >= 7.5, incl. 9.1)
    path = ida_nalt.get_input_file_path() or ida_nalt.get_root_filename()
    path = Path(path).expanduser().resolve()

    if not path.exists():
        raise FileNotFoundError(f"Cannot open input file: {path}")

    possible_names = set()
    with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        for s in extract_unicode_strings(mm, n=4):
            s_str = str(s.s)
            if s_str.startswith("\\Device\\") or s_str.startswith("\\DosDevices\\"):
                possible_names.add(s_str)
    return possible_names


def find_unicode_device_name(log_file):
    """Detect and print probable DeviceNames, writing results to *log_file*."""

    possible_names = get_unicode_device_names()

    # helper for consistent I/O
    def _out(msg):
        print(msg)
        log_file.write(msg + "\n")

    if not possible_names:
        _out("[!] No potential DeviceNames found; it may be obfuscated or created on the stack in some way.")
        return False

    if len(possible_names) <= 2 and ("\\Device\\" in possible_names or "\\DosDevices\\" in possible_names):
        _out("[!] The Device prefix was found but no full Device Paths; the DeviceName is likely obfuscated or created on the stack.")
        return False

    for name in sorted(possible_names):
        if name in ("\\Device\\", "\\DosDevices\\"):
            continue
        _out(f"\t- {name}")
    return True


def search(log_file):
    """Top‑level helper: attempt DeviceName discovery, then suggest FLOSS if needed."""
    if not find_unicode_device_name(log_file):
        print("[!] Unicode DeviceName not found; try using FLOSS in order to recover obfuscated and stack based strings.")
        log_file.write("[!] Unicode DeviceName not found; try using FLOSS in order to recover obfuscated and stack based strings.\n")
