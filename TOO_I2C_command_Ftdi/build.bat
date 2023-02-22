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


set exe_name=TOO_i2c_command
set exe_src_file=src\%exe_name%.py
set src_folder=src
cls




:EXE
:: Create exe from py source file
echo *****************************   Compiling Source   *****************************
del !exe_name!.exe

:: Compile Source
python -m compileall -f %src_folder% 


echo *****************************   Creating Executable !exe_name!.exe   *****************************
:: Create exe
pyinstaller --onefile !exe_src_file!
move dist\!exe_name!.exe .

TOO_i2c_command.exe -i config\config.ini


