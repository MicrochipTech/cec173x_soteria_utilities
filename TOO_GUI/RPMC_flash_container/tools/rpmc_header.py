import os
import platform
import argparse
import xlrd
import random
import sys
import os
import struct
import binascii
import configparser
import time
import datetime
import cryptography
import pytz
import pem
import xlrd
import xlwt
import sys
def generateheader():
    #fldloc = folder_create()
    #fldloc = "/".join(fldloc.split('\\'))
    fldloc ="rpmc"
    fldloc = "/".join(fldloc.split('\\'))
    dirpath = fldloc + "/contatenate_create_container_signature.bin"
    headpath = fldloc + "/rpmc_container_data.h"
    efuse_file = open(dirpath, "rb")
    efuse_file.seek(0)
    efuse_data = efuse_file.read()

    with open(headpath, "wt+") as in_file:
        in_file.write("")
        # in_file.write("* Copyright 2018 Microchip Technology Inc. and its subsidiaries.               \n")
        # in_file.write("* You may use this software and any derivatives exclusively with               \n")
        # in_file.write("* Microchip products.                                                          \n")
        # in_file.write("* THIS SOFTWARE IS SUPPLIED BY MICROCHIP 'AS IS'.                              \n")
        # in_file.write("* NO WARRANTIES, WHETHER EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE,\n")
        # in_file.write("* INCLUDING ANY IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY,       \n")
        # in_file.write("* AND FITNESS FOR A PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP      \n")
        # in_file.write("* PRODUCTS, COMBINATION WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.    \n")
        # in_file.write("* IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,    \n")
        # in_file.write("* INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND        \n")
        # in_file.write("* WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS    \n")
        # in_file.write("* BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.              \n")
        # in_file.write("* TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL     \n")
        # in_file.write("* CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF     \n")
        # in_file.write("* FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.    \n")
        # in_file.write("* MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE          \n")
        # in_file.write("* OF THESE TERMS.                                                              \n")
        # in_file.write("*****************************************************************************/ \n")
        # in_file.write("                                                                               \n")
        # in_file.write("/** @file efuse_data.h                                                         \n")
        # in_file.write(" *EVERGLADES efuse_data                                                        \n")
        # in_file.write(" */                                                                            \n")
        # in_file.write("/** @defgroup EVERGLADES efuse_data                                            \n")
        # in_file.write(" */                                                                            \n")
        # in_file.write("#ifndef _EFUSE_DATA_H                                                          \n")
        # in_file.write("#define _EFUSE_DATA_H                                                          \n")
        # in_file.write("typedef unsigned          char uint8_t;                                        \n")
        # in_file.write("typedef unsigned short    int uint16_t;                                       \n")
        # in_file.write("                                                                               \n")
        # in_file.write("typedef struct efuse_table_define {                                            \n")
        # in_file.write("    uint16_t index;                                                            \n")
        # in_file.write("    uint8_t value;                                                             \n")
        # in_file.write("} _EFUSE_TBLE_DFE_;                                                            \n")
        # in_file.write("                                                                               \n")
        # in_file.write("const _EFUSE_TBLE_DFE_ device_efuse_table_ [] = {\n")
        in_file.write("\n")
        in_file.write("typedef struct  \n")
        in_file.write("{  \n")
        in_file.write("	uint8_t container_enable; \n")
        in_file.write("	uint8_t container_num;\n")
        in_file.write("	uint8_t container_type;\n")
        in_file.write("	uint8_t secure_container_content_len[3];\n")
        in_file.write("	uint8_t cck0_pub[SHA_384_LEN];\n")
        in_file.write("	uint8_t cck1_pub[SHA_384_LEN];\n")
        in_file.write("	uint8_t cck2_pub[SHA_384_LEN];\n")
        in_file.write("	uint8_t cck3_pub[SHA_384_LEN];\n")
        in_file.write("	uint8_t owner_config;\n")
        in_file.write("	uint8_t owner_id[16];\n")
        in_file.write("	uint8_t key_revocation;\n")
        in_file.write("	uint8_t rollback_protection[16];\n")
        in_file.write("	uint32_t tag0_img_hdr_base_addr;\n")
        in_file.write("	uint32_t tag1_img_hdr_base_addr;\n")
        in_file.write("	uint8_t ecdh_priv_key[SHA_384_LEN];\n")
        in_file.write("	uint8_t ecdh_pub_key2[SHA_384_LEN];\n")
        in_file.write("	uint8_t khb_val[SHA_384_LEN];\n")
        in_file.write("	uint8_t owner_dbg_options;\n")
        in_file.write("	uint8_t owner_platform_id[2];\n")
        in_file.write("	uint8_t security_features;\n")
        in_file.write("	uint8_t platk[SHA_384_LEN];\n")
        in_file.write("	uint8_t ock_pub[SHA_384_LEN*2];\n")
        in_file.write("	uint8_t command_signature [SHA_384_LEN*2];\n")
        in_file.write("}__attribute__((packed)) rpmc_header_fmt;\n")
        in_file.write("\n\n")
        in_file.write("#pragma pack(1)\n")

        in_file.write("rpmc_header_fmt const rpmc_header __attribute__((section(" + "rpmc_header_data"+")"+")"+")"" = \n")
        in_file.write("{ \n")
        in_file.write("	.container_enable = 1,\n")
        in_file.write("	.container_num = 1,\n")
        in_file.write("	.container_type = 1,\n")
        in_file.write("	.secure_container_content_len = {0xF4,0x05,0x00},\n")
        message = "{" 
        for x in range(5, 48+5):
        	if x == 48+5-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        ##print("message ",message)
        in_file.write("	.cck0_pub = " +message +",\n")
        message = "{" 
        for x in range(0x35, 0x65):
        	if x == 0x65-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        ##print("message ",message)
        in_file.write("	.cck1_pub  = " +message +",\n")
        message = "{" 
        for x in range(0x65, 0x95):
        	if x == 0x95-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        ##print("message ",message)
        in_file.write("	.cck2_pub = " +message +",\n")
        message += "}"
        ###print("message ",message)
        in_file.write("	.cck1_pub  = " +message +",\n")
        message = "{" 
        for x in range(0x95, 0xC5):
        	if x == 0xC5-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.cck3_pub = " +message +",\n")
        in_file.write("	.owner_config = { "+hex(efuse_data[0xC5]) +"},\n")
        message = "{" 
        for x in range(0xC6, 0xD6):
        	if x == 0xD6-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.owner_id = " +message +",\n")
        in_file.write("	.key_revocation = { "+hex(efuse_data[0xD6]) +"},\n")
        message = "{" 
        for x in range(0xD7, 0xE7):
        	if x == 0xE7-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.rollback_protection = " +message +",\n")
        message = "{" 
        for x in range(0xE7, 0xEB):
        	if x == 0xEB-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.tag0_img_hdr_base_addr = " +message +",\n")
        message = "{" 
        for x in range(0xEB, 0xEF):
        	if x == 0xEF-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.tag1_img_hdr_base_addr = " +message +",\n")
        message = "{" 
        for x in range(0xEF, 0x11F):
        	if x == 0x11F-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.ecdh_priv_key = " +message +",\n")
        message = "{" 
        for x in range(0x11F, 0x14F):
        	if x == 0x14F-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.ecdh_pub_key2 = " +message +",\n")
        message = "{" 
        for x in range(0x14F, 0x17F):
        	if x == 0x17F-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.khb_val = " +message +",\n")
        in_file.write("	.owner_dbg_options = { "+hex(efuse_data[0x17F]) +"},\n")
        message = "{" 
        for x in range(0x180, 0x182):
        	if x == 0x182-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.owner_platform_id " +message +",\n")
        in_file.write("	.security_features ={ "+hex(efuse_data[0x182]) +"},\n")
        message = "{" 
        for x in range(0x183, 0x1B3):
        	if x == 0x1B3-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.platk = " +message +",\n")
        message = "{" 
        for x in range(0x1B3, 0x213):
        	if x == 0x213-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.ock_pub = " +message +",\n")
        message = "{" 
        for x in range(0x213, 0x273):
        	if x == 0x273-1:
        		message += hex(efuse_data[x]) 
        	else:
        		message += hex(efuse_data[x]) +","
        	#print("efuse_data %x ",hex(efuse_data[x]))
        message += "}"
        #print("message ",message)
        in_file.write("	.command_signature = " +message +",\n")
        in_file.write("};\n")
        # message = ""
        # in_file.write("    ")
        # for items in efuse_data:
        #     if 0 == cnt:
        #         idx = items
        #     if 1 == cnt:
        #         idx = idx + (items << 8)
        #     if 2 == cnt:
        #         dat = items
        #         # if 3 == cnt:
        #         if 57005 == idx:  # DEAD
        #             message = "{0xDEAD,0xFF}, "
        #         else:
        #             if idx == 9 or idx == 8:
        #                 message = "{" + str(idx) + ", " + hex(dat).zfill(2) + "}, "
        #             else:
        #                 message = "{" + str(idx).zfill(2) + ", " + hex(dat).zfill(2) + "}, "
        #         in_file.write(message)
        #         incnt = incnt + 1
        #         cnt = 0
        #         if (8 == incnt):
        #             in_file.write("\n    ")
        #             message = ""
        #             outcnt = outcnt + incnt
        #             incnt = 0
        #     else:
        #         cnt = cnt + 1
        # outcnt = outcnt + incnt

        # message = "{00, 0x00}, "
        # for idx in range(outcnt, 1024):
        #     if (8 == incnt):
        #         in_file.write("\n    ")
        #         incnt = 0
        #     in_file.write(message)
        #     incnt = incnt + 1
        # message = "{0xDEAD,0xFF}     //terminator\n"
        # in_file.write(message)
        # in_file.write("};                                                                             \n")
        # in_file.write("                                                                               \n")
        # in_file.write("#define TOTAL_SIZE sizeof(device_efuse_table_)/sizeof(device_efuse_table_[0]); \n")
        # in_file.write("#endif                                                                         \n")
        # in_file.write("/* end efuse_data.h */                                                         \n")
        # in_file.write("/**   @}                                                                       \n")
        # in_file.write(" */                                                                            \n")
    in_file.close()
    efuse_file.close()


def main():
    print("************* RPMC flash container header generation Ver: 1.00 ******\n")
    generateheader()
if __name__ == '__main__':
    main()