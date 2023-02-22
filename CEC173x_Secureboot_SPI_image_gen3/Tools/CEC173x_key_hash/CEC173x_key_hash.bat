@echo off
if "%1"== "" goto HELP

Glacier_key_hash.exe -i keycfg_B028.txt

goto end

:HELP
echo. =======================================================================
echo. Usage is:  
echo.Glacier_key_hash.bat  [.TXT config file] 
echo.
echo. Example:Glacier_key_hash.bat [keycfg.txt]  
echo   
echo. =======================================================================
goto END

:end
echo.********************************************************************************** 