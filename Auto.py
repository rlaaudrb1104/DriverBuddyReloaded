import idapro
import ida_auto
import idaapi
import traceback, sys, os, csv, time, re, builtins
from pathlib import Path

# ── 기본 경로 설정 ─────────────────────────────────────────────
DEFAULT_START_DIR = Path(r"C:\Users\KMG\Desktop\Drivers")

def make_summary_csv(START_DIR):
    SUMMARY_CSV = START_DIR / "summary.csv"

    dev_re  = re.compile(r"No potential DeviceNames found", re.I)
    drv_re  = re.compile(r"Driver type detected:\s*([A-Za-z0-9_\- ?]+)")
    disp_ok = re.compile(r"Found\s+`DispatchDeviceControl`", re.I)
    disp_no = re.compile(r"Unable to locate `DispatchDeviceControl`", re.I)

    seen_files = set()

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["file", "device_name", "driver_type", "dispatch"]
        )
        writer.writeheader()

        for log in START_DIR.rglob("*-DriverBuddyReloaded_autoanalysis.txt"):
            print(f"[+] Parsing {log.name} ...")
            text = log.read_text(errors="ignore")
            sys_name = log.name.split("-")[0]

            if sys_name in seen_files:
                print(f"[!] Duplicate detected, skipping {log.name}")
                continue

            seen_files.add(sys_name)

            device_name = "NO" if dev_re.search(text) else "YES"

            m = drv_re.search(text)
            driver_type = m.group(1).strip() if m else "Unknown"

            if disp_ok.search(text):
                dispatch = "FOUND"
            elif disp_no.search(text):
                dispatch = "NOT_FOUND"
            else:
                dispatch = "UNKNOWN"

            writer.writerow({
                "file": sys_name,
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
    print("[+] Running DriverBuddyReloaded ...")
    rc = idaapi.load_and_run_plugin("DriverBuddyReloaded", 0)

    if rc < 0:
        print(f"[!] Failed to run DriverBuddyReloaded plugin(code {rc})")
    else:
        print("[+] DriverBuddyReloaded plugin executed successfully")

    idapro.close_database()
    print("[+] Database closed - done.")

def analyze_sys_ALL(START_DIR):
    sys_files = list(START_DIR.rglob("*.sys"))
    print(f"[+] Found {len(sys_files)} .sys files under {START_DIR}")

    for idx, sys_file in enumerate(sys_files, 1):
        t0 = time.time()
        print(f"[{idx}/{len(sys_files)}] ▶ {sys_file}")
        analyze_sys(sys_file)
        print(f"    done in {time.time() - t0:.1f}s\n")

    print(f"[+] All done.")

def main():
    
    if len(sys.argv) > 1:
        START_DIR = Path(sys.argv[1]).resolve()
    else:
        START_DIR = DEFAULT_START_DIR

    print(f"[+] 분석 대상 경로: {START_DIR}")

    analyze_sys_ALL(START_DIR)
    make_summary_csv(START_DIR)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        os._exit(1)
