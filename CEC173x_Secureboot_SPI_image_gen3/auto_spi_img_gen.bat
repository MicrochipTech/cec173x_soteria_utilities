@echo off
if "%1"== "" goto HELP
if "%2"== "" goto HELP
attrib -r /s
SET SCAT=.\Tools\srec_cat\srec_cat.exe
SET START_LOC=0xC8000




%SCAT% %1% -intel -offset -0xC8000 -O temp.hex -intel
%SCAT% temp.hex -intel -O CEC173x_GEN3_secureboot_app.bin -binary


REM %SCAT% %1% -intel -offset -0xE0000 -O temp.hex -intel
REM %SCAT% temp.hex -intel -O CEC173x_GEN3_secureboot_app.bin -binary

secureboot_spi_image_gen_3.exe -i %2%

copy /y Tools\flash_image_gen .

flash_image_gen.exe 

echo "Spi image has been generated succesfully " 

echo "EC_FW TAG1 - KHB1-TOO =0x102D"

type TAG0.bin KeyHashBlob.bin "SHA384(KeyHashBlob).bin" > "EC_FW_TAG0_KHB0_TOO.bin"

type TAG1.bin KeyHashBlob.bin "SHA384(KeyHashBlob).bin" > "EC_FW_TAG1_KHB1_TOO.bin"



if exist EC_FW_TAG0_KHB0_TOO.bin ( copy /y EC_FW_TAG0_KHB0_TOO.bin Output_binaries\spi_image\EC_FW_TAG0_KHB0_TOO.bin )
if exist EC_FW_TAG1_KHB1_TOO.bin ( copy /y EC_FW_TAG1_KHB1_TOO.bin Output_binaries\spi_image\EC_FW_TAG1_KHB1_TOO.bin )

if exist fw*.bin ( copy /y fw*.bin Output_binaries\spi_image\*.* )

if exist spi_image* ( copy /y spi_image* Output_binaries\spi_image\*.* )

if exist "SHA384(KeyHashBlob)*" ( copy /y "SHA384(KeyHashBlob)*" Output_binaries\spi_image\*.* )

if exist INT_spi_image* ( copy /y INT_spi_image* Output_binaries\spi_image\*.* )


if exist AP*.bin ( copy /y AP*.bin Output_binaries\spi_image\*.* )

if exist KeyHash*.bin ( copy /y KeyHash*.bin Output_binaries\spi_image\*.* )

if exist Owner01PubKey.bin ( copy /y Owner01PubKey.bin Output_binaries\spi_image\*.* )
if exist TAG*.bin ( copy /y TAG*.bin Output_binaries\spi_image\*.* )

if exist region*.bin ( copy /y region*.bin Output_binaries\spi_image\*.*   )
if exist ec_fw_entry_hash_blob.bin ( copy /y ec_fw_entry_hash_blob.bin Output_binaries\spi_image\*.*   )

if exist CEC173x_GEN3_secureboot_app.bin ( copy /y CEC173x_GEN3_secureboot_app.bin Output_binaries\spi_image\*.* )

if exist ec_fw_entry_hash_blob.bin ( copy /y ec_fw_entry_hash_blob.bin Tools\Glacier_key_hash\*.*   )


if exist CEC173x_GEN3_secureboot_app.bin ( del CEC173x_GEN3_secureboot_app.bin )

if exist header*.bin ( del header*.bin )

if exist fw*.bin ( del fw*.bin )

if exist spi_image* ( del spi_image* )

if exist AP*.bin ( del AP*.bin  )
if exist "SHA384(KeyHashBlob)*" ( del "SHA384(KeyHashBlob)*"  )

if exist INT_spi_image* ( del INT_spi_image*  )

if exist CEC173x_GEN3_secureboot_app.bin ( del CEC173x_GEN3_secureboot_app.bin )
if exist ec_fw_entry_hash_blob.bin ( del ec_fw_entry_hash_blob.bin )
if exist tem*.hex ( del tem*.hex )
if exist region*.bin ( del region*.bin )

if exist KeyHash*.bin ( del KeyHash*.bin )

if exist Owner01PubKey.bin ( del Owner01PubKey.bin )
if exist TAG*.bin ( del TAG*.bin )

if exist flash_header_cfg* ( del flash_header_cfg* )
if exist flash_header_script* ( del flash_header_script* )
if exist flash_header_spi_image* ( del flash_header_spi_image* )
if exist flash_image_gen* ( del flash_image_gen* )
if exist srec_cat* ( del srec_cat* )
if exist spi_flash_gen* ( del spi_flash_gen* )
if exist EC_FW_TAG0_KHB0_TOO.bin ( del EC_FW_TAG0_KHB0_TOO.bin )
if exist EC_FW_TAG1_KHB1_TOO.bin ( del EC_FW_TAG1_KHB1_TOO.bin )


REM cd ..\..

goto end

:HELP
echo. =======================================================================
echo. Usage is:  
echo.auto_spi_img_gen.bat [.HEX file from the IDE ]  [.INI config file] 
echo.
echo. Example:auto_spi_img_gen.bat [filename.hex] [spi_cfg.ini]  
echo   
echo. =======================================================================
goto END

:end3
echo SPI image is not generated 

:end
echo.********************************************************************************** 