#!/bin/bash
chmod 777 *
srec_cat "$1" -intel -offset -0xC8000 -O temp.hex -intel
srec_cat temp.hex -intel -O Glacier_GEN3_secureboot_app.bin -binary
./secureboot_spi_image_gen_3 -i "$2"



echo "Spi image has been generated succesfully " 
echo "======================================================================="
echo "Usage is:  "
echo "auto_spi_img_gen.sh [.HEX file from the IDE] [.INI SPI CONFIG FILE] "
echo ""
echo "Example:auto_spi_img_gen.sh [filename.hex] [spi_cfg.ini] "
echo "======================================================================="
exit 0





