REM Define all the required local variables 
SET SCAT=srec_cat.exe
set CNT_DIR=%cd%
set SPI_FLASH_OFFSET=0x50000000

SET FLASH_HEADER_SCRIPT=flash_header_script.exe

if not exist %FLASH_HEADER_SCRIPT% goto PATHERROR

::cd %FLASH_HEADER_PATH%
%FLASH_HEADER_SCRIPT%

if not exist flash_header_spi_image.bin goto ERROR

::cd %CNT_DIR%
%SCAT% flash_header_spi_image.bin -binary -offset %SPI_FLASH_OFFSET% -O flash_header_spi_image.hex -intel
move flash_header_spi_image.hex spiflash.X.production.hex

goto END

:CERROR
set BATCHERROR=1

:ERROR
echo //////********CHECK FLASH HEADER CFG FILE********\\\\\\

:PATHERROR
echo //////******** %FLASH_HEADER_SCRIPT% Not Found ********\\\\\\

:END
cd %CNT_DIR%

