import idaapi
import ida_nalt          # 9.x: import 테이블 API
import ida_funcs
import ida_bytes
import idautils
import idc
import string

# ── 풀 태그 식별 대상 함수 그대로 ───────────────────────────
funcs = [
    "ExAllocatePoolWithTag",
    "ExFreePoolWithTag",
    "ExAllocatePool2",
    "ExFreePool2",
    "ExAllocatePool3",
    "ExAllocatePoolWithTagPriority",
    "ExAllocatePoolWithQuotaTag",
    "ExAllocatePoolZero",
    "ExAllocatePoolQuotaZero",
    "ExAllocatePoolQuotaUninitialized",
    "ExAllocatePoolPriorityZero",
    "ExAllocatePoolPriorityUninitialized",
    "ExAllocatePoolUninitialized",
]

# 4-byte가 모두 프린터블 ASCII 인지 검사
def _is_printable_tag(dword_val: int) -> bool:
    return all(chr((dword_val >> (8 * i)) & 0xFF) in string.printable[:-6] for i in range(4))

def find_pool_tags():
    """
    Walk import table → references to pool-allocation APIs → 직전 10개
    명령어 안에서 4-byte 태그 상수 또는 '# Tag' 주석을 찾아
    {tag: {caller_func, …}} 딕셔너리 반환
    """
    tags = {}

    def imp_cb(ea, name, ord_):
        if name not in funcs:
            return True                       # keep iterating

        for xref in idautils.XrefsTo(ea):
            call_ea = xref.frm
            func = ida_funcs.get_func(call_ea)
            if not func:
                continue
            caller_name = ida_funcs.get_func_name(func.start_ea)

            # 최대 10개 이전 명령어 탐색
            prev = call_ea
            for _ in range(10):
                prev = idc.prev_head(prev)
                if prev == idaapi.BADADDR or prev < func.start_ea:
                    break

                # 1) '# Tag' 코멘트
                if idc.get_cmt(prev, 0) == 'Tag' and idc.get_operand_type(prev, 1) == idc.o_imm:
                    dword_val = idc.get_operand_value(prev, 1)
                # 2) 문자 상수를 직접 이동 - 예: mov eax, 'gaTX'
                elif idc.print_insn_mnem(prev) == 'mov' and idc.get_operand_type(prev, 1) == idc.o_imm:
                    dword_val = idc.get_operand_value(prev, 1)
                    if not _is_printable_tag(dword_val):
                        continue
                else:
                    continue

                # DWORD → 문자열
                tag = ''.join(chr((dword_val >> (8 * i)) & 0xFF) for i in reversed(range(4)))

                tags.setdefault(tag, set()).add(caller_name)
                break
        return True

    # import 열거 (9.x API)
    for idx in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(idx, imp_cb)

    return tags


def get_all_pooltags():
    """
    Return pooltags.txt-style summary string.
    Format:  <TAG> - <driver.sys> - Called by: f1, f2, ...
    """
    tags = find_pool_tags()
    file_name = idaapi.get_root_filename()
    lines = []
    for tag, callers in tags.items():
        desc = 'Called by: ' + ', '.join(sorted(callers))
        lines.append(f"{tag} - {file_name} - {desc}")
    return '\n'.join(lines) + '\n'
