import idapro
import ida_auto
import idaapi
import traceback, sys, os, csv, time, re, builtins
from pathlib import Path

# ── 사용자 설정 ─────────────────────────────────────────────
START_DIR      = Path(r"C:\Users\KMG\Desktop\Drivers") # 드라이버 폴더
SUMMARY_CSV = START_DIR / "summary.csv"               # 로그 파일 파싱 후 저장할 CSV 파일


def make_summary_csv():
    """
    DriverBuddyReloaded가 만든 *-DriverBuddyReloaded_autoanalysis.txt 로그들을
    재귀적으로 찾아 한 줄씩 요약 CSV로 저장한다.
    """
    # ── 정규식 패턴 ─────────────────────────────────────────
    dev_re  = re.compile(r"No potential DeviceNames found", re.I)
    drv_re  = re.compile(r"Driver type detected:\s*([A-Za-z0-9_\- ?]+)")
    disp_ok = re.compile(r"Found\s+`DispatchDeviceControl`", re.I)
    disp_no = re.compile(r"Unable to locate `DispatchDeviceControl`", re.I)

    seen_files = set()  # 중복 체크용

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["file", "device_name", "driver_type", "dispatch"]
        )
        writer.writeheader()

        # *.txt 재귀 탐색
        for log in START_DIR.rglob("*-DriverBuddyReloaded_autoanalysis.txt"):
            print(f"[+] Parsing {log.name} ...")
            text = log.read_text(errors="ignore")
            sys_name = log.name.split("-")[0]
            
            if sys_name in seen_files:
                print(f"[!] Duplicate detected, skipping {log.name}")
                continue
            
            seen_files.add(sys_name)
            
            # DeviceName 유무
            device_name = "NO" if dev_re.search(text) else "YES"

            # Driver type
            m = drv_re.search(text)
            driver_type = m.group(1).strip() if m else "Unknown"

            # DispatchDeviceControl 존재 여부
            if disp_ok.search(text):
                dispatch = "FOUND"
            elif disp_no.search(text):
                dispatch = "NOT_FOUND"
            else:
                dispatch = "UNKNOWN"

            writer.writerow({
                "file": log.name.split("-")[0],
                "device_name": device_name,
                "driver_type": driver_type,
                "dispatch": dispatch
            })

    print(f"[+] summary.csv 생성 완료 → {SUMMARY_CSV}")

    
def analyze_sys(BIN_PATH):
    
    print(f"[+] Opening {BIN_PATH}")
    CURRENT_DIR = os.path.dirname(BIN_PATH)
    CURRENT_FILE = os.path.basename(BIN_PATH)
    os.chdir(CURRENT_DIR)
    idapro.open_database(CURRENT_FILE, True)
    ida_auto.auto_wait()
    
    print("[+] Running DriverBuddyReloaded ...")
    rc = idaapi.load_and_run_plugin("DriverBuddyReloaded", 0)
        
    if rc < 0:
        print(f"[!] Failed to run DriverBuddyReloaded plugin(code {rc})")
    else:
        print("[+] DriverBuddyReloaded plugin executed successfully")
    
    idapro.close_database()
    print("[+] Database closed - done.")
    
def analyze_sys_ALL():
    sys_files = list(START_DIR.rglob("*.sys"))
    print(f"[+] Found {len(sys_files)} .sys files under {START_DIR}")
    
    for idx, sys_file in enumerate(sys_files, 1):
        t0 = time.time()
        print(f"[{idx}/{len(sys_files)}] ▶ {sys_file}")
        analyze_sys(sys_file)
        print(f"    done in {time.time() - t0:.1f}s\n")
    print(f"[+] All done.")

def main():
    analyze_sys_ALL()
    make_summary_csv()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        os._exit(1)
        
        