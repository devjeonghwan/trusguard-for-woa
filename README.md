# TrusGuard for Windows on ARM

사용자가 제공한 TrusGuard 3.0.9.1 x64 설치 파일로 ARM64 호환 설치 EXE를 만듭니다.
AhnLab 파일은 저장소에 포함하지 않습니다. ARM64 TAP 드라이버는 포함되어 있습니다.

1. 원본 `tgsvpn_setup_x64.exe`를 이 폴더에 넣습니다.
2. PowerShell에서 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File .\Patch-TrusGuard.ps1
```

생성된 `tgsvpn_setup_x64_patched.exe`를 Windows 11 ARM64에서 실행하고 관리자 승인을 합니다.
설치 후 시작 메뉴의 **TrusGuard WOA**로 실행합니다.

x64 클라이언트는 원본을 유지하며 ARM64 TAP 드라이버를 사용합니다. 생성 EXE는 미서명입니다.
TAP 라이선스·소스는 `vendor/tap-windows6`, 보조 도구 빌드는 `tools/Build-Helpers.ps1`에 있습니다.
