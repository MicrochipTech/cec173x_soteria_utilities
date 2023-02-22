@echo off
attrib -r /s
SET START_LOC=0xC8000





srec_cat.exe Glacier_GEN3_secureboot_app.hex -intel -offset -0xC8000 -O temp.hex -intel

srec_cat.exe temp.hex -intel -O Glacier_GEN3_secureboot_app.bin -binary
