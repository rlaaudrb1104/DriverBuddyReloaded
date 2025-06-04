# DriverBuddyReloaded의 기능 개선판

## 주요 변경점

### IDA PRO 9.1 버전 최적화


### Driver Type 식별 강화 및 확장
#### 지원 드라이버 목록

- `WDM`
- `KMDF`

**파일 시스템**
- `FS Mini-Filter`
- `Legacy FS Filter`
- `Filesystem Driver`

**네트워크**
- `NDIS 6.x Miniport`
- `NDIS 6.x Filter`
- `NDIS Legacy IM`

**스토리지/버스 MiniPort**
- `StorPort Miniport`
- `SCSIport Miniport`
- `ATAport Miniport`
- `NVMe Miniport`

**오디오/미디어**
- `PortCls (Audio)`
- `AVStream (KS)`
- `BDA (TV/튜너)`

**입력/센서**
- `HID Mini-driver`
- `GPIO CLX Client`
- `SPB (I²C/SPI) Controller`

**USB**
- `USB Function Driver (WDM)`
- `USB Filter Driver`

**네트워크 보안/필터링**
- `WFP Callout`
- `RDBSS Mini-Redirector`

**가상화/보안/전원 관리**
- `ACPI Filter`
- `PoFx Power-Managed`
- `Hyper-V VMBus`

### Headless Mode 추가 (대량 드라이버 자동화) - Auto.py

**사용법**

```python
### 1. DEFAULT_START_DIR 경로 설정 시
python Auto.py
### 2. DEFAULT_START_DIR 경로 미설정 or 다른 경로 탐색
python Auto.py [Driver 파일 루트 경로]
```

분석 완료 시 Driver 파일 루트 경로에 summary.csv 파일 생성

**summary.csv 구성**
- `File` : `DriverName`
- `Device_Name` : `Yes` or `No`
- `Driver_Type` : `WDM`, `WDF`, ...
- `Dispatch routine` : `Yes` or `No`(기능 개선 x)
