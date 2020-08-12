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

echo ������ ���� + �����Է�
echo ������ ���� + �����Է�
call :Search >result\result.txt
ren result\"result.txt" "%date%_%str1%_%str2%.txt"
goto :eof



:Search
echo.
set /p str1=������ ������ ����ϼ���:
set /p str2=������ ������ ����ϼ���:

echo.
echo =================================================
echo.
echo.
echo ������ ����� ����  : made by KyeongHan Kim
echo ������ �̸� : %str1%
echo ������ �̸� : %str2%
for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" ^| findstr /i "RegisteredOrganization"') do echo ȸ�� : %%a
for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" ^| findstr /i "RegisteredOwner"') do echo ����� : %%a
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
echo ��Accounts List

net user

::----------------------------

echo.
echo - Administrator
net user Administrator | findstr /I /C:"Ȱ�� ����"
echo - Guest 
net user Guest | findstr /I /C:"Ȱ�� ����"


::----------------------------


echo.
echo *****************************************************************
echo �ھ�ȣ ��å
echo.
net accounts | findstr /I /C:"��ȣ ��� ����"
net accounts | findstr /I /C:"�ִ� ��ȣ ��� �Ⱓ"
net accounts | findstr /I /C:"�ּ� ��ȣ ����"


::----------------------------

echo.
echo *****************************************************************
echo �ڰ��� ��� ��å
echo.
net accounts | findstr /I /C:"��� �Ⱓ"
net accounts | findstr /I /C:"��� �Ӱ谪"
net accounts | findstr /I /C:"��� ���� â"


::----------------------------

echo.
echo *****************************************************************
echo ��OS����
echo.
auditpol /get /category:* | findstr /I /C:"����� ���� ����"
auditpol /get /category:* | findstr /I /C:"���� �α׿� �̺�Ʈ"
auditpol /get /category:* | findstr /I /C:"�α׿�/�α׿��� �̺�Ʈ"
auditpol /get /category:* | findstr /I /C:"�ý��� �̺�Ʈ"


::----------------------------
echo.
echo *****************************************************************
echo ��ȭ�麸ȣ��
echo.
set /a Sel5 = 1
for /f "tokens=1* delims= " %%a in ('reg query "HKEY_CURRENT_USER\Control Panel\Desktop" ^| findstr /i "SCRNSAVE.EXE"') do (
	
	if "%%a" == "SCRNSAVE.EXE" (
		echo 	-ȭ�麸ȣ��  ����    : Y
	)
	set /a Sel5 = 0
)

if %Sel5% == 1 (
	echo		-ȭ�麸ȣ�� : �̼���
	echo.
)

if %Sel5%==0 (

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_CURRENT_USER\Control Panel\Desktop" ^| findstr /i "ScreenSaveTimeOut"') do (
			echo 	-ȭ�麸ȣ�� �����ð� : %%f ��
)

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_CURRENT_USER\Control Panel\Desktop" ^| findstr /i "ScreenSaverIsSecure"') do (
	
	if "%%f"=="1" (
		echo		-ȭ����ݼ���        : Y
	)ELSE (
		echo		-ȭ����ݼ���        : N
	)
)

)


::----------------------------

echo.
echo *****************************************************************
echo ��UAC

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^| findstr /i "ConsentPromptBehaviorAdmin"') do (
	echo 	ConsentPromptBehaviorAdmin ��: %%f
	set a= %%f
)

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^| findstr /i "EnableLUA"') do (
	echo 	EnableLUA ��: %%f
	set b= %%f
)

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^| findstr /i "PromptOnSecureDesktop"') do (
	echo 	PromptOnSecureDesktop ��: %%f
	set c= %%f
)


if %a%==0x0 (
	
		if %c%==0x0 (
			echo.
			echo 	-UAC ���� 1�ܰ�
			echo.
		)
	
)


if %a%==0x5 (
	
		if %c%==0x0 (
			echo.
			echo 	-UAC ���� 2�ܰ�
			echo.
		)
	
)


if %a%==0x5 (
	
		if %c%==0x1 (
			echo.
			echo 	-UAC ���� 3�ܰ�
			echo.
		)
	
)

if %a%==0x2 (
	
		if %c%==0x1 (
			echo.
			echo 	-UAC ���� 4�ܰ�
			echo.
		)
	
)


::----------------------------

echo.
echo *****************************************************************
echo �ں��� �ܼ� (���� ���� �������� ����)

for /f "tokens=3* delims= " %%f in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" ^| findstr /i "securityLevel"') do (
	if "%%f"=="0x0" (
		echo �� %%f
		echo.
		echo 	-���� �ܼ� �ڵ� �α��� ��� : ������
	)  
	if not "%%f"=="0x0" (
		echo �� %%f
		echo.
		echo 	-���� �ܼ� �ڵ� �α��� ��� : ���
	)
)

::----------------------------

echo.
echo *****************************************************************
echo ����ǰ ����
echo.
::slmgr -xpr
for /f "tokens=3* delims= " %%a in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" ^| findstr /i "ProductName"') do echo 	-OS���� : %%a %%b 


::----------------------------

echo.
echo *****************************************************************
echo ��Windows ������Ʈ �� �ڵ� ������Ʈ ����
set /a Sel2 = 1
echo.

set /a Sel2 = 1
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" ^| findstr /i "NoAutoUpdate"') do (
	echo.
	echo 	NoAutoUpdate ��: %%f
	echo.
	if "%%f"=="0x0" (
		echo		-�ڵ� ������Ʈ ���� : ���
		echo.
	)  
	if "%%f"=="0x1" (
		echo		-�ڵ� ������Ʈ ���� : ��� ����
		echo.
	)
	set /a Sel2 = 0
)

echo.
if %Sel2% == 1 (
	echo		-�ڵ� ������Ʈ ���� : �������� ����
	echo.
)



::----------------------------

echo.
echo *****************************************************************
echo �ڹ�ȭ�� ���� windows defender �߰�����
echo.
echo.

for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" ^| findstr /i "EnableFirewall"') do (
	if "%%f"=="0x1" (
		echo		-��ȭ�� ���� : ���
		
	)  
	if not "%%f"=="0x1" (
		echo		-��ȭ�� ���� : ������
		
	)
	echo.
)




::----------------------------

echo.
echo *****************************************************************
echo �ڿܺ� �����ü
echo.
echo.
set /a Sel = 1

::=======================================����̵��� ����� Ŭ����
echo.
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" ^| findstr /i "Deny_All"') do (
	if "%%f"=="0x1" (
		echo		-��� �̵��� ����� Ŭ����-�����Ѱź� : ���
		
	)  
	if not "%%f"=="0x1" (
		echo		-��� �̵��� ����� Ŭ����-�����Ѱź� : ������
		
	)
	set /a Sel = 0
)

if %Sel% == 1 (
	echo		-��� �̵��� ����� Ŭ����-�����Ѱź� : �������� ����

)


::======================================��� �̵��� �����: ���� ���ǿ��� ���� �׼��� ���
set /a Sel = 1
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" ^| findstr /i "AllowRemoteDASD"') do (
	if "%%f"=="0x1" (
		echo		-��� �̵��� �����: ���� ���ǿ��� ���� �׼��� ��� : ���
		
	)  
	if not "%%f"=="0x1" (
		echo		-��� �̵��� �����: ���� ���ǿ��� ���� �׼��� ��� : ������
		
	)
	set /a Sel = 0
)

if %Sel% == 1 (
	echo		-��� �̵��� �����: ���� ���ǿ��� ���� �׼��� ��� : �������� ����
	
)

::====================================�ڵ� ���� ����

set /a Sel = 1
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" ^| findstr /i "NoDriveTypeAutoRun"') do (
	if "%%f"=="0xb5" (
		echo		-�ڵ� ���� ���� : ���
		echo.
	)  
	if "%%f"=="0x0" (
		echo		-�ڵ� ���� ���� : ��� ����
		echo.
	)
	set /a Sel = 0
)

if %Sel% == 1 (
	echo		-�ڵ� ���� ���� : �������� ����
	echo.
)



::----------------------------

echo.
echo *****************************************************************
echo �ڿ��� ����
set /a Sel3 = 1
set /a Sel4 = 1
echo.

::== ����� ��������
set /a Sel3 = 1
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" ^| findstr /i "fAllowToGetHelp"') do (
	echo.
	echo 	fAllowToGetHelp ��: %%f
	echo.
	if "%%f"=="0x1" (
		echo		- ���� ���� ���� : ���
		echo.
	)  
	if "%%f"=="0x0" (
		echo		- ���� ���� ���� : ��� ����
		echo.
	)
	set /a Sel3 = 0
)

echo.
if %Sel3% == 1 (
	echo		- ���� ���� ���� : ���� ��Ȳ �߻�
	echo.
)

::== ����� ���� ����ũ�� ����
set /a Sel4 = 1
for /f "tokens=3* delims= " %%f in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" ^| findstr /i "fDenyTSConnections"') do (
	echo.
	echo 	fDenyTSConnections ��: %%f
	echo.
	if "%%f"=="0x0" (
		echo		-���� ����ũ�� ���� : ���
		echo.
	)  
	if "%%f"=="0x1" (
		echo		-���� ����ũ�� ���� : ��� ����
		echo.
	)
	set /a Sel4 = 0
)

echo.
if %Sel4% == 1 (
	echo		-���� ����ũ�� ���� : ���� ��Ȳ �߻�
	echo.
)


::----------------------------

echo.
echo *****************************************************************
echo �ڰ��� ���� Ȯ��
echo.
net share
echo.
echo *****************************************************************



exit /b
