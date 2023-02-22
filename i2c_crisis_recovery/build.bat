:: This file generates exe and run tests on the generated exe
:: build.bat <flags>
::  flags :
::    test            -  runs executable with -test option
::    <exe_name>      -  Creates Executable exe_name.exe
::                       The exe_name should be the main source file in src folder.
::                       Default exe_name = i2c_host
::    release <label> -  Creates release.zip with label folder.
::                       Required files to  the utility are available in Label folder  

@echo off
setlocal EnableDelayedExpansion 

set flag=%1
set label=%2
set exe_name=i2c_host
set exe_src_file=src\%exe_name%.py
set src_folder=src
cls

:: Run exe with -test option
if [!flag!]==[test] (
goto TEST
)
if [!flag!]==[release] (
goto RELEASE
)
if NOT [!flag!]==[] (
:: if not empty check if source file exist
	set exe_name=!flag!
	set exe_src_file=%src_folder%\!exe_name!.py
	if not exist !exe_src_file! (
		goto ERROR !flag!
	)
)
) else (
:: if flag is empty goto Default option
goto EXE
)


:EXE
:: Create exe from py source file
echo *****************************   Compiling Source   *****************************
del !exe_name!.exe

:: Compile Source
python -m compileall -f %src_folder% 
if %errorlevel% neq 0 exit /b %errorlevel%

echo *****************************   Creating Executable !exe_name!.exe   *****************************
:: Create exe
pyinstaller --onefile !exe_src_file!
move dist\!exe_name!.exe .

:: CleanUp Workspace
rd /Q /S build 

rd /Q /S dist 

FOR /d /r . %%d IN (__pycache__) DO @IF EXIST "%%d" rd /s /q "%%d"

del !exe_name!.spec

:: Run Unit Test
goto :TEST 

:TEST
:: Run test for the exe generated
echo *****************************   Running Unit Tests   *****************************
:: Use powershell to redirect output to file and console
powershell -command ".\%exe_name%.exe -test 2>&1 | Tee-Object .\outputs\unit_test_report.txt"
copy outputs\logs\log.txt outputs\unit_test_logs.txt
exit /b 0

:RELEASE
:: zip required files
echo *****************************  Creating Release Package %label% *****************************
mkdir %label%
set files=!exe_name!.exe readme.txt script.txt script_user_mode.txt^
             script_fa_mode.txt script_enable_debug.txt script_qa_mode.txt script_with_auth.txt
for %%x in (%files%) do (
copy %%x %label%
) 
set folders=docs inputs outputs
for %%x in (%folders%) do (
xcopy %%x %label%\%%x /E /I
)
set releaseFolder=release.zip
tar.exe -a -c -f %releaseFolder% %label%
rd /Q /S %label%
exit /b 0

:ERROR %1
echo %1 invalid
exit /b 1