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

import sys
try:
    from pldm_struct_h import *
except:
    print("pldm_struct_h.py not found")
    sys.exit(0)

PHP_OFFSET = 0
php_pkg_hdr = fw_pkg_hdr()
php_fw_dev_id = Firmware_Device_Identification_Area()
php_component_image_count = Component_Image_Count()
down_stream = 0


def php_get_key_val(num_bytes, bin, offset):
    # print(num_bytes)

    if num_bytes < 5:
        temp = 0
        for i in range(0, num_bytes):
            temp |= bin[offset] << (i * 8)
            offset += 1
        return temp
    else:
        return bin[offset:offset+num_bytes]


def php_print_dict_in_hex(dict):  # This function added for debug will be useful in future
    for key, value in dict.items():
        print(key, end=" : ")
        if type(value) is int:
            print(hex(value))
        else:
            print('[{}]'.format(', '.join(hex(x) for x in value)))


def pkg_hdr_split():
    global php_pkg_hdr
    global PHP_OFFSET
    global hdr_file_content

    print("\n\nPackage Header Split ---------------------------------------\n")

    dict = vars(php_pkg_hdr)
    count = 0
    for key, value in dict.items():
        if (size_fw_pkg_hdr[count] != -1):
            dict[key] = php_get_key_val(size_fw_pkg_hdr[count], PHP_HDR_PKG_INT, PHP_OFFSET)
            PHP_OFFSET += size_fw_pkg_hdr[count]
            count += 1
    php_pkg_hdr.PackageVersionString = PHP_HDR_PKG_INT[PHP_OFFSET:PHP_OFFSET + php_pkg_hdr.PackageVersionStringLength]
    PHP_OFFSET += php_pkg_hdr.PackageVersionStringLength

    php_print_dict_in_hex(dict)


PHP_FW_DEV_ID_DESC_TABLE = []


def fw_dev_split():
    print("\n\nFW Dev Split ---------------------------------------\n")
    global php_fw_dev_id
    global PHP_OFFSET
    global hdr_file_content
    global PHP_FW_DEV_ID_DESC_TABLE

    dict = vars(php_fw_dev_id)
    count = 0
    for key, value in dict.items():
        if (size_fw_dev_id[count] != -1):
            dict[key] = php_get_key_val(size_fw_dev_id[count], PHP_HDR_PKG_INT, PHP_OFFSET)
            PHP_OFFSET += size_fw_dev_id[count]
            count += 1
        else:
            break

    applicable_comp_bytes = int(php_pkg_hdr.ComponentBitmapBitLength / 8)
    php_fw_dev_id.ApplicableComponents = PHP_HDR_PKG_INT[PHP_OFFSET:PHP_OFFSET +
                                                                   applicable_comp_bytes]
    
    PHP_OFFSET += applicable_comp_bytes

    php_fw_dev_id.ComponentImageSetVersionString = PHP_HDR_PKG_INT[PHP_OFFSET:PHP_OFFSET +
                                                                   php_fw_dev_id.ComponentImageSetVersionStringLength]
    PHP_OFFSET += php_fw_dev_id.ComponentImageSetVersionStringLength
    php_print_dict_in_hex(dict)

    for i in range(0, php_fw_dev_id.DescriptorCount):
        count = 0
        fw_dev_id_desc = Firmware_Device_Identification_Descriptor()
        dict = vars(fw_dev_id_desc)
        for key, value in dict.items():
            if (size_fw_dev_id_desc[count] != -1):
                dict[key] = php_get_key_val(
                    size_fw_dev_id_desc[count], PHP_HDR_PKG_INT, PHP_OFFSET)
                PHP_OFFSET += size_fw_dev_id_desc[count]
                count += 1
        fw_dev_id_desc.InitialDescriptorData = PHP_HDR_PKG_INT[PHP_OFFSET:PHP_OFFSET + fw_dev_id_desc.InitialDescriptorLength]
        PHP_OFFSET += fw_dev_id_desc.InitialDescriptorLength
        PHP_FW_DEV_ID_DESC_TABLE.append(dict)

    for obj in PHP_FW_DEV_ID_DESC_TABLE:
        print("\n\nFW DEV ComponentParameterTable{}:---")
        php_print_dict_in_hex(obj)
        count += 1


def downstream_dev_id_split():
    global PHP_OFFSET
    global down_stream

    print("Downstream dev id split ---------------------------------------\n\n")

    down_stream = PHP_HDR_PKG_INT[PHP_OFFSET]
    PHP_OFFSET += 1

    if(down_stream != 0):
        print("error Down stream must be 0 for SG3")
        sys.exit(1)


PHP_COMP_IMG_TABLE = []


def comp_img_split():
    print("Compo img Split ---------------------------------------\n\n")
    global php_component_image_count
    global PHP_OFFSET
    global hdr_file_content
    global PHP_COMP_IMG_TABLE

    dict = vars(php_component_image_count)
    count = 0
    for key, value in dict.items():
        if (size_ComponentImageCount[count] != -1):
            dict[key] = php_get_key_val(size_ComponentImageCount[count], PHP_HDR_PKG_INT, PHP_OFFSET)
            PHP_OFFSET += size_ComponentImageCount[count]
            count += 1
        else:
            break

    php_print_dict_in_hex(dict)

    for i in range(0, php_component_image_count.ComponentImageCount):
        count = 0
        comp_img_info = Component_Image_Information()
        dict = vars(comp_img_info)
        for key, value in dict.items():
            if (size_Component_Image_Information[count] != -1):
                dict[key] = php_get_key_val(
                    size_Component_Image_Information[count], PHP_HDR_PKG_INT, PHP_OFFSET)
                PHP_OFFSET += size_Component_Image_Information[count]
                count += 1
        comp_img_info.ComponentVersionString = PHP_HDR_PKG_INT[PHP_OFFSET:PHP_OFFSET + comp_img_info.ComponentVersionStringLength]
        PHP_OFFSET += comp_img_info.ComponentVersionStringLength
        PHP_COMP_IMG_TABLE.append(dict)

    for obj in PHP_COMP_IMG_TABLE:
        print("\n\nCOMP IMG ComponentParameterTable{}:---")
        php_print_dict_in_hex(obj)
        count += 1


PHP_HDR_PKG_INT = []
PHP_HDR_PKG_BIN = []


def PHP_main():
    global PHP_HDR_PKG_BIN
    global PHP_HDR_PKG_INT

    php_filename = "pldm_header_package.bin"
    try:
        file = open(php_filename, 'rb')
    except:
        print("Unable to open file pldm_header_package.bin")
        sys.exit(1)
    PHP_HDR_PKG_BIN = file.read()

    with open(php_filename, "rb") as f:
        byte = f.read(1)
        while byte:
            int_byte = int.from_bytes(byte, "big")
            PHP_HDR_PKG_INT.append(int_byte)
            byte = f.read(1)
    pkg_hdr_split()
    fw_dev_split()
    # downstream_dev_id_split()
    comp_img_split()


if __name__ == "__main__":
    PHP_main()
