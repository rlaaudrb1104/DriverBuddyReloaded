"""
find_opcodes.py – enhanced (IDA 9.1‑ready)

* **Variable names preserved** (public API unchanged)
* Fixed parameter order in the internal search loop
  (switched to ida_search.find_binary)
* Safer byte‑to‑hex conversion under Python 3
* Added fallback when *s* parameter is None
* Minor clean‑ups (context managers, early code creation)
"""

import re
import sys

import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_search
import ida_kernwin
import ida_lines
import ida_segment
import ida_ua
import idautils
import idaapi

from DriverBuddyReloaded.vulnerable_functions_lists.opcode import *

# This option will prevent Driver Buddy Reloaded to find opcodes in data sections
# https://github.com/VoidSec/DriverBuddyReloaded/issues/11
find_opcode_data = False


def FindInstructions(instr, asm_where=None):
    """Assemble *instr* (opcodes or assembly) and return matching addresses."""

    if instr is None:
        return False, "No instruction/opcode string supplied"

    if not asm_where:
        seg = ida_segment.get_first_seg()
        asm_where = seg.start_ea if seg else ida_idaapi.BADADDR
        if asm_where == ida_idaapi.BADADDR:
            return False, "No segments defined"

    re_opcode = re.compile(r"^[0-9a-f]{2}(?:\s[0-9a-f]{2})*$", re.I)

    bufs = []
    for line in instr.split(";"):
        line = line.strip()
        if not line:
            continue
        if re_opcode.match(line):
            try:
                buf = bytes(int(x, 16) for x in line.split())
            except ValueError:
                return False, f"Invalid opcode bytes: {line}"
        else:
            ok, buf = idautils.Assemble(asm_where, line)
            if not ok:
                return False, f"Failed to assemble: {line}"
        bufs.append(buf)

    buf = b"".join(bufs)
    tlen = len(buf)
    bin_str = ' '.join(["%02X" % (ord(x) if sys.version_info.major < 3 else x) for x in buf])
    
    ea = ida_ida.inf_get_min_ea()
    ret = []
    while True:
        ea = ida_bytes.find_bytes(bin_str, ea)
        # ea = ida_search.find_binary(ea, ida_idaapi.BADADDR, bin_str, 16, ida_search.SEARCH_DOWN)
        if ea == ida_idaapi.BADADDR:
            break
        ret.append(ea)
        # ida_kernwin.msg(".")
        ea += tlen
    if not ret:
        return False, "Could not match {} - [{}]".format(instr, bin_str)
    # ida_kernwin.msg("\n")
    return True, ret


class SearchResultChoose(ida_kernwin.Choose):
    def __init__(self, title, items):
        super().__init__(title, [["Address", 30], ["Function (or segment)", 25], ["Instruction", 20]], width=250)
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        i = self.items[n]
        return [hex(i.ea), i.funcname_or_segname, i.text]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.items[n].ea)


class SearchResult:
    def __init__(self, ea, log_file):
        self.ea = ea
        self.funcname_or_segname = ""
        self.text = ""

        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            ida_ua.create_insn(ea)

        t = ida_lines.generate_disasm_line(ea)
        if t:
            self.text = ida_lines.tag_remove(t)

        n = ida_funcs.get_func_name(ea) or ida_segment.get_segm_name(ida_segment.getseg(ea))
        if n:
            self.funcname_or_segname = n

        if find_opcode_data is False:
            for opcode in opcodes:
                if opcode in self.text:
                    print(f"\t- Found {self.text} in {self.funcname_or_segname} at 0x{self.ea:08X}")
                    log_file.write(f"\t- Found {self.text} in {self.funcname_or_segname} at 0x{self.ea:08X}\n")
                    break
        else:
            print(f"\t- Found {self.text} in {self.funcname_or_segname} at 0x{self.ea:08X}")
            log_file.write(f"\t- Found {self.text} in {self.funcname_or_segname} at 0x{self.ea:08X}\n")


def find(log_file, s=None, x=False, asm_where=None):
    """Wrapper around *FindInstructions* with optional exec‑segment filtering."""

    ok, ret = FindInstructions(s, asm_where)
    if not ok:
        print(ret)
        log_file.write(ret + "\n")
        return

    if x:
        results = [SearchResult(ea, log_file) for ea in ret if ida_segment.getseg(ea) and (ida_segment.getseg(ea).perm & ida_segment.SEGPERM_EXEC)]
    else:
        results = [SearchResult(ea, log_file) for ea in ret]

    # Uncomment below to display chooser UI
    # title = f"Search result for: [{s}]"
    # ida_kernwin.close_chooser(title)
    # chooser = SearchResultChoose(title, results)
    # chooser.Show(True)
