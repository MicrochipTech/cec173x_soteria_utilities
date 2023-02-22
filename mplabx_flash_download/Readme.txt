mplabx_flash_download
=====================
flash_header_script                     -  Contains config files for flash selection and 
                                           generates output hex file required for MPLABX IDE.
FlashDownload                           -  Contains MPLABx Prebuilt Project files to exectute the program
                                           executive and download the flash image into flash.	
MPLABX_Flash_download_For_Glacier.docx  -  Detailed explaination of the steps required for flash download.
RIPE_26b_0003                           -  Program Executive in intel hex format. Internally loaded by IDE.
Readme                                  -  This File


Steps to Flash 
==============

Prerequsites
============
  1. spi_image.bin  - Output of SPI Image generator 
     which is intended to be programmed to flash.
  2. MPLABX IDE V5.50. 

Steps to Flash Using ICD4
=========================
  1. Open project FlashDownload.X- Check project properties if DFP 1.2.46 is installed.
     if not install 1.2.46 DFP
  2. Use RIPE_26b_0003.hex - This is the Program Executive needed by IDE to communicate to flash.
     This is explained in MPLABX_Flash_download_For_Glacier.docx
  3. Run the project FlashDownload.x in IDE using the debug option. Click stop once reset handler is hit.
  4. Place the spi_image.bin in the flash_header_script directory.
  5. In file : lash_header_script\flash_header_cfg.txt  
     Select the flash to be programmed using the folowing parameter
     Port = INT_SPI 
	     or
	 Port = SHD_SPI
     
  6. Run spi_flash_gen.bat. This will generate spiflash.X.production.hex with step 4 and 5 as inputs
  7. In IDE add the spiflash.X.production.hex as loadable.
  8 .Click make and download in IDE
     Wait until ""program/verify Complete"" for Flash download to complete.
