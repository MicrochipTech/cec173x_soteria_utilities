# ********************************************************************************
# Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
# You may use this software and any derivatives exclusively with
# Microchip products.
# THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS".
# NO WARRANTIES, WHETHER EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE,
# INCLUDING ANY IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY,
# AND FITNESS FOR A PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP
# PRODUCTS, COMBINATION WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
# IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
# INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
# WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
# BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.
# TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL
# CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF
# FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
# MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE
# OF THESE TERMS.
# ********************************************************************************/


# ==========================================================================
# VERSION
# ==========================================================================
from datetime import datetime
import struct
from array import array, ArrayType
from ctypes import cdll
import binascii
import crc8
import sys
import os
import cryptography
import pytz
import pem
import os
import sys
import re
import struct
import binascii
import configparser
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join
import cryptography
import pytz
import pem
import sys, getopt
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.x509.oid import ExtensionOID
from datetime import datetime, date, time, timezone, timedelta , tzinfo
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec ,rsa
import ecdsa
from cryptography import x509
from functools import partial
import enum
import datetime
import time
from time import mktime
import pytz
import hashlib
from hashlib import blake2b

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec ,rsa
from cryptography import x509
from functools import partial
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

crypto_be = cryptography.hazmat.backends.default_backend()
AA_API_VERSION = 0x050a   # v5.10
AA_REQ_SW_VERSION = 0x050a   # v5.10
INTERVAL_TIMEOUT = 100
AA_ASYNC_NO_DATA = 0x00000000

BUS_TIMEOUT = 150  # ms

import random

def port_1_comp_1():
    print("EXT SPI image port_1_comp_1 \n")
    file_exists = os.path.exists('flash_header_cfg.txt')
    if 1:
        cmd ="del -f flash_header_cfg.txt "
        op = os.system(cmd)
        cmd ="del -f flash_header_spi_image.bin "
        op = os.system(cmd)
        cmd ="del -f spiflash.X.production.hex "
        op = os.system(cmd)
        cmd ="del -f spi_image_port_1_comp_1.hex "
        op = os.system(cmd) 
        cmd ="copy /y spi_image_port_1_comp_1.bin  Output_binaries\\spi_image"
        op = os.system(cmd)
        cmd ="rename  spi_image_port_1_comp_1.bin spi_image.bin "
        op = os.system(cmd)
    fd = open("flash_header_cfg.txt","wt+")
    fd.write("; Everglades Flash update process configurable file"  +"\n")
    fd.write("[FLASH HEADER]"+"\n")
    
    fd.write(" ;The port attribute is used to select which port(" + "SHD_SPI"+" or "+"PVT_SPI" +"or +""INT_SPI"+")"+" has to be programmed  "+ "\n")
    fd.write("Port = PVT_SPI" +"\n")
    fd.write(" ;The component attribute is used to select the component (0 or 1); for internal flash component is 0 >> flash_header_cfg.txt" +"\n")
    fd.write("Comp = 1 "+"\n")
    fd.write(";The erase sequence attribute can be used to select the type of erase("+"chip_erase" +"or "+"sector_erase"+")"+" to be performed on given port " +"\n")
    fd.write("Erase sequence = chip_erase" +"\n")
    fd.write(";The number of images attribute used to select the number of regions the user wants to program from the binary file"+"\n")
    fd.write(";The number of images count should be 1 or 2 or 3"+"\n")
    fd.write("Number of Images = 0"+"\n")
    fd.write("Image 0 Program address = 0x0"+"\n")
    fd.write("Image 0 Size = 0x1000"+"\n")
    fd.write("Image 1 Program address = 0x0"+"\n")
    fd.write("Image 1 Size = 0x0"+"\n")
    fd.write("Image 2 Program address = 0x000"+"\n")
    fd.write("Image 2 Size = 0x000"+"\n")
    fd.close()
    cmd ="spi_flash_gen.bat"
    op = os.system(cmd)
    cmd ="rename  flash_header_cfg.txt flash_header_cfg_port_1_comp_1.txt"
    op = os.system(cmd)
    cmd ="copy /y flash_header_cfg_port_1_comp_1.txt  Output_binaries\\spi_image"
    op = os.system(cmd)
    cmd ="rename  spiflash.X.production.hex spi_image_port_1_comp_1.hex "
    op = os.system(cmd)
    cmd ="del -f  spi_image.bin "
    op = os.system(cmd)
def port_1_comp_0():
    print("EXT SPI image port_1_comp_0 \n")
    file_exists = os.path.exists('flash_header_cfg.txt')
    if 1:
        cmd ="del -f flash_header_cfg.txt "
        op = os.system(cmd)
        cmd ="del -f flash_header_spi_image.bin "
        op = os.system(cmd)
        cmd ="del -f spiflash.X.production.hex "
        op = os.system(cmd)
        cmd ="del -f spi_image_port_1_comp_0.hex "
        op = os.system(cmd) 
        cmd ="copy /y spi_image_port_1_comp_0.bin  Output_binaries\\spi_image"
        op = os.system(cmd)
        cmd ="rename  spi_image_port_1_comp_0.bin spi_image.bin "
        op = os.system(cmd)
    fd = open("flash_header_cfg.txt","wt+")
    fd.write("; Everglades Flash update process configurable file"  +"\n")
    fd.write("[FLASH HEADER]"+"\n")
    
    fd.write(" ;The port attribute is used to select which port(" + "SHD_SPI"+" or "+"PVT_SPI" +"or +""INT_SPI"+")"+" has to be programmed  "+ "\n")
    fd.write("Port = PVT_SPI" +"\n")
    fd.write(" ;The component attribute is used to select the component (0 or 1); for internal flash component is 0 >> flash_header_cfg.txt" +"\n")
    fd.write("Comp = 0 "+"\n")
    fd.write(";The erase sequence attribute can be used to select the type of erase("+"chip_erase" +"or "+"sector_erase"+")"+" to be performed on given port " +"\n")
    fd.write("Erase sequence = chip_erase" +"\n")
    fd.write(";The number of images attribute used to select the number of regions the user wants to program from the binary file"+"\n")
    fd.write(";The number of images count should be 1 or 2 or 3"+"\n")
    fd.write("Number of Images = 0"+"\n")
    fd.write("Image 0 Program address = 0x0"+"\n")
    fd.write("Image 0 Size = 0x1000"+"\n")
    fd.write("Image 1 Program address = 0x0"+"\n")
    fd.write("Image 1 Size = 0x0"+"\n")
    fd.write("Image 2 Program address = 0x000"+"\n")
    fd.write("Image 2 Size = 0x000"+"\n")
    fd.close()
    cmd ="spi_flash_gen.bat"
    op = os.system(cmd)
    cmd ="rename  flash_header_cfg.txt flash_header_cfg_port_1_comp_0.txt"
    op = os.system(cmd)
    cmd ="copy /y flash_header_cfg_port_1_comp_0.txt  Output_binaries\\spi_image"
    op = os.system(cmd)
    cmd ="rename  spiflash.X.production.hex spi_image_port_1_comp_0.hex "
    op = os.system(cmd)
    cmd ="del -f  spi_image.bin "
    op = os.system(cmd)
def port_0_comp_1():
    print("EXT SPI image port_0_comp_1 \n")
    file_exists = os.path.exists('flash_header_cfg.txt')
    if 1:
        cmd ="del -f flash_header_cfg.txt "
        op = os.system(cmd)
        cmd ="del -f flash_header_spi_image.bin "
        op = os.system(cmd) 
        cmd ="del -f spiflash.X.production.hex "
        op = os.system(cmd)
        cmd ="del -f spi_image_port_0_comp_1.hex "
        op = os.system(cmd)       
        cmd ="copy /y spi_image_port_0_comp_1.bin  Output_binaries\\spi_image"
        op = os.system(cmd)
        cmd ="rename  spi_image_port_0_comp_1.bin spi_image.bin "
        op = os.system(cmd)
    fd = open("flash_header_cfg.txt","wt+")
    fd.write("; Everglades Flash update process configurable file"  +"\n")
    fd.write("[FLASH HEADER]"+"\n")
    
    fd.write(" ;The port attribute is used to select which port(" + "SHD_SPI"+" or "+"PVT_SPI" +"or +""INT_SPI"+")"+" has to be programmed  "+ "\n")
    fd.write("Port = SHD_SPI" +"\n")
    fd.write(" ;The component attribute is used to select the component (0 or 1); for internal flash component is 0 >> flash_header_cfg.txt" +"\n")
    fd.write("Comp = 0 "+"\n")
    fd.write(";The erase sequence attribute can be used to select the type of erase("+"chip_erase" +"or "+"sector_erase"+")"+" to be performed on given port " +"\n")
    fd.write("Erase sequence = chip_erase" +"\n")
    fd.write(";The number of images attribute used to select the number of regions the user wants to program from the binary file"+"\n")
    fd.write(";The number of images count should be 1 or 2 or 3"+"\n")
    fd.write("Number of Images = 0"+"\n")
    fd.write("Image 0 Program address = 0x0"+"\n")
    fd.write("Image 0 Size = 0x1000"+"\n")
    fd.write("Image 1 Program address = 0x0"+"\n")
    fd.write("Image 1 Size = 0x0"+"\n")
    fd.write("Image 2 Program address = 0x000"+"\n")
    fd.write("Image 2 Size = 0x000"+"\n")
    fd.close()
    cmd ="spi_flash_gen.bat"
    op = os.system(cmd)
    cmd ="rename  flash_header_cfg.txt flash_header_cfg_port_0_comp_1.txt"
    op = os.system(cmd)
    cmd ="copy /y flash_header_cfg_port_0_comp_1.txt  Output_binaries\\spi_image"
    op = os.system(cmd)
    cmd ="rename  spiflash.X.production.hex spi_image_port_0_comp_1.hex "
    op = os.system(cmd)
    cmd ="del -f  spi_image.bin "
    op = os.system(cmd)
def port_0_comp_0():
    print("EXT SPI image port_0_comp_0 \n")
    file_exists = os.path.exists('flash_header_cfg.txt')
    if 1:
        cmd ="del -f flash_header_cfg.txt "
        op = os.system(cmd)
        cmd ="del -f flash_header_spi_image.bin "
        op = os.system(cmd) 
        cmd ="del -f spiflash.X.production.hex "
        op = os.system(cmd)
        cmd ="del -f spi_image_port_0_comp_0.hex "
        op = os.system(cmd)       
        cmd ="copy /y spi_image_port_0_comp_0.bin  Output_binaries\\spi_image"
        op = os.system(cmd)
        cmd ="rename  spi_image_port_0_comp_0.bin spi_image.bin "
        op = os.system(cmd)
    fd = open("flash_header_cfg.txt","wt+")
    fd.write("; Everglades Flash update process configurable file"  +"\n")
    fd.write("[FLASH HEADER]"+"\n")
    
    fd.write(" ;The port attribute is used to select which port(" + "SHD_SPI"+" or "+"PVT_SPI" +"or +""INT_SPI"+")"+" has to be programmed  "+ "\n")
    fd.write("Port = SHD_SPI" +"\n")
    fd.write(" ;The component attribute is used to select the component (0 or 1); for internal flash component is 0 >> flash_header_cfg.txt" +"\n")
    fd.write("Comp = 0 "+"\n")
    fd.write(";The erase sequence attribute can be used to select the type of erase("+"chip_erase" +"or "+"sector_erase"+")"+" to be performed on given port " +"\n")
    fd.write("Erase sequence = chip_erase" +"\n")
    fd.write(";The number of images attribute used to select the number of regions the user wants to program from the binary file"+"\n")
    fd.write(";The number of images count should be 1 or 2 or 3"+"\n")
    fd.write("Number of Images = 0"+"\n")
    fd.write("Image 0 Program address = 0x0"+"\n")
    fd.write("Image 0 Size = 0x1000"+"\n")
    fd.write("Image 1 Program address = 0x0"+"\n")
    fd.write("Image 1 Size = 0x0"+"\n")
    fd.write("Image 2 Program address = 0x000"+"\n")
    fd.write("Image 2 Size = 0x000"+"\n")
    fd.close()
    cmd ="spi_flash_gen.bat"
    op = os.system(cmd)
    cmd ="rename  flash_header_cfg.txt flash_header_cfg_port_0_comp_0.txt"
    op = os.system(cmd)
    cmd ="copy /y flash_header_cfg_port_0_comp_0.txt  Output_binaries\\spi_image"
    op = os.system(cmd)
    cmd ="rename  spiflash.X.production.hex spi_image_port_0_comp_0.hex "
    op = os.system(cmd)
    cmd ="del -f  spi_image.bin "
    op = os.system(cmd)
def int_spi():
    print("Internal SPI image \n")
    file_exists = os.path.exists('flash_header_cfg.txt')
    if 1:
        cmd ="del -f flash_header_cfg.txt "
        op = os.system(cmd)        
        cmd ="del -f flash_header_spi_image.bin "
        op = os.system(cmd)
        cmd ="del -f spiflash.X.production.hex "
        op = os.system(cmd)
        cmd ="del -f INT_spi_image.hex "
        op = os.system(cmd)
        cmd ="copy /y spi_image.bin  Output_binaries\\spi_image"
        op = os.system(cmd)
        # cmd ="copy /y spi_image.bin  Output_binaries\\spi_image\\INT_spi_image.bin "
        # op = os.system(cmd)
    fd = open("flash_header_cfg.txt","wt+")
    fd.write("; Everglades Flash update process configurable file"  +"\n")
    fd.write("[FLASH HEADER]"+"\n")
    
    fd.write(" ;The port attribute is used to select which port(" + "SHD_SPI"+" or "+"PVT_SPI" +"or +""INT_SPI"+")"+" has to be programmed  "+ "\n")
    fd.write("Port = INT_SPI" +"\n")
    fd.write(" ;The component attribute is used to select the component (0 or 1); for internal flash component is 0 >> flash_header_cfg.txt" +"\n")
    fd.write("Comp = 0 "+"\n")
    fd.write(";The erase sequence attribute can be used to select the type of erase("+"chip_erase" +"or "+"sector_erase"+")"+" to be performed on given port " +"\n")
    fd.write("Erase sequence = sector_erase" +"\n")
    fd.write(";The number of images attribute used to select the number of regions the user wants to program from the binary file"+"\n")
    fd.write(";The number of images count should be 1 or 2 or 3"+"\n")
    fd.write("Number of Images = 3"+"\n")
    fd.write("Image 0 Program address = 0x0"+"\n")
    fd.write("Image 0 Size = 0x1000"+"\n")
    fd.write("Image 1 Program address = 0x6000"+"\n")
    fd.write("Image 1 Size = 0x2000"+"\n")
    fd.write("Image 2 Program address = 0x20000"+"\n")
    fd.write("Image 2 Size = 1E0000"+"\n")
    fd.close()
    cmd ="spi_flash_gen.bat"
    op = os.system(cmd)
    cmd ="rename  flash_header_cfg.txt flash_header_cfg_sector_erase_int_spi.txt"
    op = os.system(cmd)
    cmd ="copy /y flash_header_cfg_sector_erase_int_spi.txt  Output_binaries\\spi_image"
    op = os.system(cmd)
    cmd ="rename  spiflash.X.production.hex INT_spi_image.hex "
    op = os.system(cmd)
    cmd ="del -f  spi_image.bin "
    op = os.system(cmd)


    # REM echo Port = INT_SPI >> flash_header_cfg.txt
    
    # REM echo ;The component attribute is used to select the component (0 or 1); for internal flash component is 0 >> flash_header_cfg.txt
    # REM echo Comp = 0 >> flash_header_cfg.txt
    
    # REM echo ;The erase sequence attribute can be used to select the type of erase("chip_erase" or "sector_erase") to be performed on given port >> flash_header_cfg.txt
    # REM echo Erase sequence = sector_erase >> flash_header_cfg.txt
    
    # REM echo ;The number of images attribute used to select the number of regions the user wants to program from the binary file >> flash_header_cfg.txt
    # REM echo ;The number of images count should be 1 or 2 or 3 >> flash_header_cfg.txt
    # REM echo Number of Images = 2 >> flash_header_cfg.txt
    
    # REM echo ;Based on the number of images count the below programming region will be taken >> flash_header_cfg.txt
    # REM echo ;program addresss and program size should be 4kb boundary >> flash_header_cfg.txt
    # REM echo Image 0 Program address = 0x0 >> flash_header_cfg.txt
    # REM echo Image 0 Size = 0x1000 >> flash_header_cfg.txt
    # REM echo Image 1 Program address = 0x6000 >> flash_header_cfg.txt
    # REM echo Image 1 Size = 1FA000 >> flash_header_cfg.txt
    # REM echo Image 2 Program address = 0x000 >> flash_header_cfg.txt
    # REM echo Image 2 Size = 0x000  >> flash_header_cfg.txt


    # REM spi_flash_gen.bat
def main():
    print("========================================================================== ")
    print("Flash Image Generation   Utility Version 1.0 Dated 07/22/2022 ")
    print("========================================================================== ")
    # for i, arg in enumerate(argv):
    #     #print(f"Argument {i:>6}: {arg}")
    #     ini_file = argv[2]
    #     #print("ini_file  ",ini_file)
    #config = configparser.ConfigParser()
    #config.read(ini_file)
    cmd ="copy /y Tools\\flash_download_script ."
    op = os.system(cmd)
    #UseESPISizeMegabits = config['SPI']['UseESPISizeMegabits']
    #print("UseESPISizeMegabits ",UseESPISizeMegabits)
    #if UseESPISizeMegabits =='true':
    file_exists = os.path.exists('spi_image.bin')
    if file_exists:
        int_spi()
    file_exists = os.path.exists('spi_image_port_0_comp_0.bin')
    if file_exists:
       port_0_comp_0()
    file_exists = os.path.exists('spi_image_port_0_comp_1.bin')
    if file_exists:
        port_0_comp_1()
    file_exists = os.path.exists('spi_image_port_1_comp_0.bin')
    if file_exists:
        port_1_comp_0()
    file_exists = os.path.exists('spi_image_port_1_comp_1.bin')
    if file_exists:
        port_1_comp_1()
    print("========================================================================== ")
    print("*************EXIT**********************************************")
    print("========================================================================== ")

if __name__ == "__main__":
    main()
