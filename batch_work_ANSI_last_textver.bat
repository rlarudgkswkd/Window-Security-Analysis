@echo off


echo.
echo --------------------------------------------------------------------------------
echo Window Security Assessment Program by KyeongHan kim
echo Contact me : rlarudgkswkd@gmail.com
echo -----------------------------------------------------------------------------------
echo.

echo MIT License
echo.
echo Copyright (c) 2020 KyeongHan Kim
echo.
echo Permission is hereby granted, free of charge, to any person obtaining a copy
echo of this software and associated documentation files (the "Software"), to deal
echo in the Software without restriction, including without limitation the rights
echo to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
echo copies of the Software, and to permit persons to whom the Software is
echo furnished to do so, subject to the following conditions:

echo The above copyright notice and this permission notice shall be included in all
echo copies or substantial portions of the Software.

echo THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
echo IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
echo FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
echo AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
echo LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
echo OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
echo SOFTWARE.
echo ------------------------------------------------------------------------------------------------------
echo.

pause

cls

echo 점검자 성명 + 엔터입력
echo 수검자 성명 + 엔터입력
call :Search >result\result.txt
ren result\"result.txt" "%date%_%str1%_%str2%.txt"
goto :eof



:Search
echo.
set /p str1=점검자 성명을 기록하세요:
set /p str2=수검자 성명을 기록하세요:

echo.
echo =================================================
echo.
echo.
echo 윈도우 취약점 진단  : made by KyeongHan Kim
echo 점검자 이름 : %str1%
echo 수검자 이름 : %str2%
for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" ^| findstr /i "RegisteredOrganization"') do echo 회사 : %%a
for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" ^| findstr /i "RegisteredOwner"') do echo 사용자 : %%a
echo %date% %time%
echo.
echo.
echo =================================================
echo.
echo.
echo.
echo.
echo.
echo *****************************************************************
echo ★Accounts List

net user

::----------------------------

echo.
echo - Administrator
net user Administrator | findstr /I /C:"활성 계정"
echo - Guest 
net user Guest | findstr /I /C:"활성 계정"


::----------------------------


echo.
echo *****************************************************************
echo ★암호 정책
echo.
net accounts | findstr /I /C:"암호 기록 개수"
net accounts | findstr /I /C:"최대 암호 사용 기간"
net accounts | findstr /I /C:"최소 암호 길이"


::----------------------------

echo.
echo *****************************************************************
echo ★계정 잠금 정책
echo.
net accounts | findstr /I /C:"잠금 기간"
net accounts | findstr /I /C:"잠금 임계값"
net accounts | findstr /I /C:"잠금 관찰 창"


::----------------------------

echo.
echo *****************************************************************
echo ★OS감사
echo.
auditpol /get /category:* | findstr /I /C:"사용자 계정 관리"
auditpol /get /category:* | findstr /I /C:"계정 로그온 이벤트"
auditpol /get /category:* | findstr /I /C:"로그온/로그오프 이벤트"
auditpol /get /category:* | findstr /I /C:"시스템 이벤트"


::----------------------------
echo.
echo *****************************************************************
echo ★화면보호기
echo.
set /a Sel5 = 1
for /f "tokens=1* delims= " %%a in ('reg query "HKEY_CURRENT_USER\Control Panel\Desktop" ^| findstr /i "SCRNSAVE.EXE"') do (
	
	if "%%a" == "SCRNSAVE.EXE" (
		echo 	-화면보호기  설정    : Y
	)
	set /a Sel5 = 0
)

if %Sel5% == 1 (
	echo		-화면보호기 : 미설정
	echo.
)

if %Sel5%==0 (

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_CURRENT_USER\Control Panel\Desktop" ^| findstr /i "ScreenSaveTimeOut"') do (
			echo 	-화면보호기 설정시간 : %%f 초
)

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_CURRENT_USER\Control Panel\Desktop" ^| findstr /i "ScreenSaverIsSecure"') do (
	
	if "%%f"=="1" (
		echo		-화면잠금설정        : Y
	)ELSE (
		echo		-화면잠금설정        : N
	)
)

)


::----------------------------

echo.
echo *****************************************************************
echo ★UAC

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^| findstr /i "ConsentPromptBehaviorAdmin"') do (
	echo 	ConsentPromptBehaviorAdmin 값: %%f
	set a= %%f
)

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^| findstr /i "EnableLUA"') do (
	echo 	EnableLUA 값: %%f
	set b= %%f
)

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^| findstr /i "PromptOnSecureDesktop"') do (
	echo 	PromptOnSecureDesktop 값: %%f
	set c= %%f
)


if %a%==0x0 (
	
		if %c%==0x0 (
			echo.
			echo 	-UAC 설정 1단계
			echo.
		)
	
)


if %a%==0x5 (
	
		if %c%==0x0 (
			echo.
			echo 	-UAC 설정 2단계
			echo.
		)
	
)


if %a%==0x5 (
	
		if %c%==0x1 (
			echo.
			echo 	-UAC 설정 3단계
			echo.
		)
	
)

if %a%==0x2 (
	
		if %c%==0x1 (
			echo.
			echo 	-UAC 설정 4단계
			echo.
		)
	
)


::----------------------------

echo.
echo *****************************************************************
echo ★복구 콘솔 (오류 뜰경우 구성되지 않음)

for /f "tokens=3* delims= " %%f in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" ^| findstr /i "securityLevel"') do (
	if "%%f"=="0x0" (
		echo 값 %%f
		echo.
		echo 	-복구 콘솔 자동 로그인 허용 : 사용안함
	)  
	if not "%%f"=="0x0" (
		echo 값 %%f
		echo.
		echo 	-복구 콘솔 자동 로그인 허용 : 사용
	)
)

::----------------------------

echo.
echo *****************************************************************
echo ★정품 인증
echo.
::slmgr -xpr
for /f "tokens=3* delims= " %%a in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" ^| findstr /i "ProductName"') do echo 	-OS정보 : %%a %%b 


::----------------------------

echo.
echo *****************************************************************
echo ★Windows 업데이트 및 자동 업데이트 구성
set /a Sel2 = 1
echo.

set /a Sel2 = 1
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" ^| findstr /i "NoAutoUpdate"') do (
	echo.
	echo 	NoAutoUpdate 값: %%f
	echo.
	if "%%f"=="0x0" (
		echo		-자동 업데이트 구성 : 사용
		echo.
	)  
	if "%%f"=="0x1" (
		echo		-자동 업데이트 구성 : 사용 안함
		echo.
	)
	set /a Sel2 = 0
)

echo.
if %Sel2% == 1 (
	echo		-자동 업데이트 구성 : 구성되지 않음
	echo.
)



::----------------------------

echo.
echo *****************************************************************
echo ★방화벽 상태 windows defender 추가예정
echo.
echo.

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" ^| findstr /i "EnableFirewall"') do (
	if "%%f"=="0x1" (
		echo		-방화벽 설정 : 사용
		
	)  
	if not "%%f"=="0x1" (
		echo		-방화벽 설정 : 사용안함
		
	)
	echo.
)




::----------------------------

echo.
echo *****************************************************************
echo ★외부 저장매체
echo.
echo.
set /a Sel = 1

::=======================================모든이동식 저장소 클래스
echo.
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" ^| findstr /i "Deny_All"') do (
	if "%%f"=="0x1" (
		echo		-모든 이동식 저장소 클래스-모든권한거부 : 사용
		
	)  
	if not "%%f"=="0x1" (
		echo		-모든 이동식 저장소 클래스-모든권한거부 : 사용안함
		
	)
	set /a Sel = 0
)

if %Sel% == 1 (
	echo		-모든 이동식 저장소 클래스-모든권한거부 : 구성되지 않음

)


::======================================모든 이동식 저장소: 원격 세션에서 직접 액세스 허용
set /a Sel = 1
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" ^| findstr /i "AllowRemoteDASD"') do (
	if "%%f"=="0x1" (
		echo		-모든 이동식 저장소: 원격 세션에서 직접 액세스 허용 : 사용
		
	)  
	if not "%%f"=="0x1" (
		echo		-모든 이동식 저장소: 원격 세션에서 직접 액세스 허용 : 사용안함
		
	)
	set /a Sel = 0
)

if %Sel% == 1 (
	echo		-모든 이동식 저장소: 원격 세션에서 직접 액세스 허용 : 구성되지 않음
	
)

::====================================자동 실행 끄기

set /a Sel = 1
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" ^| findstr /i "NoDriveTypeAutoRun"') do (
	if "%%f"=="0xb5" (
		echo		-자동 실행 끄기 : 사용
		echo.
	)  
	if "%%f"=="0x0" (
		echo		-자동 실행 끄기 : 사용 안함
		echo.
	)
	set /a Sel = 0
)

if %Sel% == 1 (
	echo		-자동 실행 끄기 : 구성되지 않음
	echo.
)



::----------------------------

echo.
echo *****************************************************************
echo ★원격 설정
set /a Sel3 = 1
set /a Sel4 = 1
echo.

::== 여기는 원격지원
set /a Sel3 = 1
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" ^| findstr /i "fAllowToGetHelp"') do (
	echo.
	echo 	fAllowToGetHelp 값: %%f
	echo.
	if "%%f"=="0x1" (
		echo		- 원격 지원 연결 : 허용
		echo.
	)  
	if "%%f"=="0x0" (
		echo		- 원격 지원 연결 : 허용 안함
		echo.
	)
	set /a Sel3 = 0
)

echo.
if %Sel3% == 1 (
	echo		- 원격 지원 연결 : 예외 상황 발생
	echo.
)

::== 여기는 원격 데스크톱 연결
set /a Sel4 = 1
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" ^| findstr /i "fDenyTSConnections"') do (
	echo.
	echo 	fDenyTSConnections 값: %%f
	echo.
	if "%%f"=="0x0" (
		echo		-원격 데스크톱 연결 : 허용
		echo.
	)  
	if "%%f"=="0x1" (
		echo		-원격 데스크톱 연결 : 허용 안함
		echo.
	)
	set /a Sel4 = 0
)

echo.
if %Sel4% == 1 (
	echo		-원격 데스크톱 연결 : 예외 상황 발생
	echo.
)


::----------------------------

echo.
echo *****************************************************************
echo ★공유 폴더 확인
echo.
net share
echo.
echo *****************************************************************



exit /b
