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
import pldm_header_parser as php
from datetime import datetime
import struct
from array import array, ArrayType
from ctypes import cdll
import binascii
from aardvark_py import *
import crc8
import sys
import os
AA_API_VERSION = 0x050a   # v5.10
AA_REQ_SW_VERSION = 0x050a   # v5.10
INTERVAL_TIMEOUT = 100
AA_ASYNC_NO_DATA = 0x00000000
try:
    import configparser
except ImportError:
    # Python 2.x fallback
    import ConfigParser as configparser

try:
    from pldm_struct_h import *
except:
    print("pldm_struct_h.py not found")
    sys.exit(1)

try:
    from pldm_header_parser import *
except:
    print("pldm_header_parser.py not found")
    sys.exit(1)

query_packet = []
get_fw_query_packet = []

command_len = 0

command_name = ""

command_resp_len = 0

error_reported = 0

# READ THIS LINK TO PARSE THE ini FILE
# http://pymotw.com/2/ConfigParser/
# ==========================================================================
# CONSTANTS
# ==========================================================================
PAGE_SIZE = 8
BUS_TIMEOUT = 150  # ms
process = 0
transfer_comp_count = 0
verify_comp_flag = 0
apply_comp_flag = 0
status_var = 0
get_response_flag = 0
fw_get_response_flag = 0
req_update_flag = 0

################################################################
################################################################
# The below function will calculate CRC for given bytes.
# Return Type : integer
################################################################
################################################################


def get_crc(_bytes):
    crc = crc8.crc8(_bytes)
    #crc = crc.update(_bytes)
    crc = crc.hexdigest()
    return crc
    # return __crc8(_bytes)


def get_id():
    global command_resp_len
    global command_name
    global command_len
    command_resp_len = 15
    command_name = "Request Update "
    command_len = 12
    return "0F 09 C5 01 00 92 C8 01 81 05 10 C9"


def get_eid():
    global command_resp_len
    global command_name
    global command_len
    command_resp_len = 15
    command_name = "MCTP GET EID REQUEST"
    command_len = 11
    return "0F 08 C5 01 00 92 C8 00 81 02 22"


def set_eid():
    global command_resp_len
    global command_name
    global command_len
    command_resp_len = 15
    command_name = "MCTP SET EID REQUEST"
    command_len = 13
    return "0F 0A C5 01 00 92 C8 00 81 01 00 94 E2"


def mctp_type_support():
    global command_resp_len
    global command_name
    global command_len
    command_resp_len = 14
    command_name = "MCTP TYPE SUPPORT REQUEST"
    command_len = 11
    return "0F 08 C5 01 94 92 C9 00 81 05 F7"


def mctp_ver_support():
    global command_resp_len
    global command_name
    global command_len
    command_resp_len = 17
    command_name = "MCTP VER SUPPORT REQUEST"
    command_len = 12
    return "0F 09 C5 01 94 92 CA 00 81 04 00 10"


def Get_Vnd_defined_Msg_Support():
    global command_resp_len
    global command_name
    global command_len
    command_resp_len = 18
    command_name = "MCTP VNDR DEFINED REQUEST"
    command_len = 12
    return "0F 09 C5 01 94 92 CD 00 81 06 00 13"


switcher = {
    1: get_id,
    2: set_eid,
    3: mctp_type_support,
    4: mctp_ver_support,
    5: Get_Vnd_defined_Msg_Support
}


def get_the_mctp_request(argument):
    # Get the function from switcher dictionary
    func = switcher.get(argument, "nothing")
    # Execute the function
    return func()


def ActivateFirmware():
    print("ActivateFirmware Command ")
    global handle
    read_data1 = "C8"
    read_data1 = bytes.fromhex(read_data1)
    resp = bytearray()
    resp.append(read_data1[0])
    # 0F 45 C5 01 92 92 C8 01 81 05 15
    # 0F 45 C5 01 92 92 C8 01 81 05 15 00
    # 0F 1E C5 01 92 92 C8 01 81 05 15 00
    #read_data ="0F 1E C5 01 92 92 C8 01 81 05 15 00"
    # 0A C5 01 92 92 C8 01 81 05 16 00
    read_data = "0F 0A C5 01 00 92 C8 01 81 05 1A 01"  # 22"
    read_data_1 = bytes.fromhex(read_data)
    resp.extend(read_data_1)
    #read_data_2 = bytes.fromhex(copy_cnt)
    # resp.extend(copy_cnt)
    read_data_3 = get_crc(resp)
    #print("read_data_3 ",read_data_3)
    # resp.extend(read_date_3)
    data = bytearray()
    data.extend(read_data_1)
    # data.extend(copy_cnt)
    read_data_3 = bytes.fromhex(read_data_3)
    data.extend(read_data_3)
    print("Send Data ", data.hex())
    # api.py_aa_sleep_ms(1)
    send(data, len(data))
    read_fun(handle, 64, timeout_ms)


def GetStatus():
    print("GetStatus Command ")
    global handle
    read_data1 = "C8"
    read_data1 = bytes.fromhex(read_data1)
    resp = bytearray()
    resp.append(read_data1[0])
    # 0F 45 C5 01 92 92 C8 01 81 05 15
    # 0F 45 C5 01 92 92 C8 01 81 05 15 00
    # 0F 1E C5 01 92 92 C8 01 81 05 15 00
    #read_data ="0F 1E C5 01 92 92 C8 01 81 05 15 00"
    # 0A C5 01 92 92 C8 01 81 05 16 00
    read_data = "0F 09 C5 01 00 92 C8 01 81 05 1B"  # 22"
    read_data_1 = bytes.fromhex(read_data)
    resp.extend(read_data_1)
    #read_data_2 = bytes.fromhex(copy_cnt)
    # resp.extend(copy_cnt)
    read_data_3 = get_crc(resp)
    #print("read_data_3 ",read_data_3)
    # resp.extend(read_date_3)
    data = bytearray()
    data.extend(read_data_1)
    # data.extend(copy_cnt)
    read_data_3 = bytes.fromhex(read_data_3)
    data.extend(read_data_3)
    print("Send Data ", data.hex())
    # api.py_aa_sleep_ms(1)
    send(data, len(data))
    read_fun(handle, 64, timeout_ms)


def CancelUpdateComponent():
    print("CancelUpdateComponent Command ")
    global handle
    read_data1 = "C8"
    read_data1 = bytes.fromhex(read_data1)
    resp = bytearray()
    resp.append(read_data1[0])
    # 0F 45 C5 01 92 92 C8 01 81 05 15
    # 0F 45 C5 01 92 92 C8 01 81 05 15 00
    # 0F 1E C5 01 92 92 C8 01 81 05 15 00
    #read_data ="0F 1E C5 01 92 92 C8 01 81 05 15 00"
    # 0A C5 01 92 92 C8 01 81 05 16 00
    read_data = "0F 09 C5 01 00 92 C8 01 81 05 1C"  # 22"
    read_data_1 = bytes.fromhex(read_data)
    resp.extend(read_data_1)
    #read_data_2 = bytes.fromhex(copy_cnt)
    # resp.extend(copy_cnt)
    read_data_3 = get_crc(resp)
    #print("read_data_3 ",read_data_3)
    # resp.extend(read_date_3)
    data = bytearray()
    data.extend(read_data_1)
    # data.extend(copy_cnt)
    read_data_3 = bytes.fromhex(read_data_3)
    data.extend(read_data_3)
    print("Send Data ", data.hex())
    # api.py_aa_sleep_ms(1)
    send(data, len(data))
    read_fun(handle, 64, timeout_ms)


def CancelUpdate():
    print("CancelUpdate Command ")
    global handle
    read_data1 = "C8"
    read_data1 = bytes.fromhex(read_data1)
    resp = bytearray()
    resp.append(read_data1[0])
    # 0F 45 C5 01 92 92 C8 01 81 05 15
    # 0F 45 C5 01 92 92 C8 01 81 05 15 00
    # 0F 1E C5 01 92 92 C8 01 81 05 15 00
    #read_data ="0F 1E C5 01 92 92 C8 01 81 05 15 00"
    # 0A C5 01 92 92 C8 01 81 05 16 00
    read_data = "0F 09 C5 01 00 92 C8 01 81 05 1D"  # 22"
    read_data_1 = bytes.fromhex(read_data)
    resp.extend(read_data_1)
    #read_data_2 = bytes.fromhex(copy_cnt)
    # resp.extend(copy_cnt)
    read_data_3 = get_crc(resp)
    #print("read_data_3 ",read_data_3)
    # resp.extend(read_date_3)
    data = bytearray()
    data.extend(read_data_1)
    # data.extend(copy_cnt)
    read_data_3 = bytes.fromhex(read_data_3)
    data.extend(read_data_3)
    print("Send Data ", data.hex())
    # api.py_aa_sleep_ms(1)
    send(data, len(data))
    read_fun(handle, 64, timeout_ms)


def GETID():
    print("GETID Command ")
    global handle
    read_data1 = "C8"
    read_data1 = bytes.fromhex(read_data1)
    resp = bytearray()
    resp.append(read_data1[0])
    # 0F 45 C5 01 92 92 C8 01 81 05 15
    # 0F 45 C5 01 92 92 C8 01 81 05 15 00
    # 0F 1E C5 01 92 92 C8 01 81 05 15 00
    #read_data ="0F 1E C5 01 92 92 C8 01 81 05 15 00"
    # 0A C5 01 92 92 C8 01 81 05 16 00
    # 0F 15 C5 01 00 92 C8 01 81 05 10
    read_data = "0F 09 C5 01 00 92 C8 01 81 00 02"  # 22"
    read_data_1 = bytes.fromhex(read_data)
    resp.extend(read_data_1)
    #read_data_2 = bytes.fromhex(copy_cnt)
    # resp.extend(copy_cnt)
    read_data_3 = get_crc(resp)
    #print("read_data_3 ",read_data_3)
    # resp.extend(read_date_3)
    data = bytearray()
    data.extend(read_data_1)
    # data.extend(copy_cnt)
    read_data_3 = bytes.fromhex(read_data_3)
    data.extend(read_data_3)
    print("Send Data ", data.hex())
    # api.py_aa_sleep_ms(1)
    send(data, len(data))
    read_fun(handle, 64, timeout_ms)


def GetPLDMVersion():
    print("GetPLDMVersion Command ")
    global handle
    read_data1 = "C8"
    read_data1 = bytes.fromhex(read_data1)
    resp = bytearray()
    resp.append(read_data1[0])
    # 0F 45 C5 01 92 92 C8 01 81 05 15
    # 0F 45 C5 01 92 92 C8 01 81 05 15 00
    # 0F 1E C5 01 92 92 C8 01 81 05 15 00
    #read_data ="0F 1E C5 01 92 92 C8 01 81 05 15 00"
    # 0A C5 01 92 92 C8 01 81 05 16 00
    read_data = "0F 09 C5 01 00 92 C8 01 81 00 03"  # 22"
    read_data_1 = bytes.fromhex(read_data)
    resp.extend(read_data_1)
    #read_data_2 = bytes.fromhex(copy_cnt)
    # resp.extend(copy_cnt)
    read_data_3 = get_crc(resp)
    #print("read_data_3 ",read_data_3)
    # resp.extend(read_date_3)
    data = bytearray()
    data.extend(read_data_1)
    # data.extend(copy_cnt)
    read_data_3 = bytes.fromhex(read_data_3)
    data.extend(read_data_3)
    print("Send Data ", data.hex())
    # api.py_aa_sleep_ms(1)
    send(data, len(data))
    read_fun(handle, 64, timeout_ms)


def GetPLDMTypes():
    print("GetPLDMTypes Command ")
    global handle
    read_data1 = "C8"
    read_data1 = bytes.fromhex(read_data1)
    resp = bytearray()
    resp.append(read_data1[0])
    # 0F 45 C5 01 92 92 C8 01 81 05 15
    # 0F 45 C5 01 92 92 C8 01 81 05 15 00
    # 0F 1E C5 01 92 92 C8 01 81 05 15 00
    #read_data ="0F 1E C5 01 92 92 C8 01 81 05 15 00"
    # 0A C5 01 92 92 C8 01 81 05 16 00
    read_data = "0F 09 C5 01 00 92 C8 01 81 00 04"  # 22"
    read_data_1 = bytes.fromhex(read_data)
    resp.extend(read_data_1)
    #read_data_2 = bytes.fromhex(copy_cnt)
    # resp.extend(copy_cnt)
    read_data_3 = get_crc(resp)
    #print("read_data_3 ",read_data_3)
    # resp.extend(read_date_3)
    data = bytearray()
    data.extend(read_data_1)
    # data.extend(copy_cnt)
    read_data_3 = bytes.fromhex(read_data_3)
    data.extend(read_data_3)
    print("Send Data ", data.hex())
    # api.py_aa_sleep_ms(1)
    send(data, len(data))
    read_fun(handle, 64, timeout_ms)


def GetPLDMCommands():
    print("GetPLDMCommands Command ")
    global handle
    read_data1 = "C8"
    read_data1 = bytes.fromhex(read_data1)
    resp = bytearray()
    resp.append(read_data1[0])
    # 0F 45 C5 01 92 92 C8 01 81 05 15
    # 0F 45 C5 01 92 92 C8 01 81 05 15 00
    # 0F 1E C5 01 92 92 C8 01 81 05 15 00
    #read_data ="0F 1E C5 01 92 92 C8 01 81 05 15 00"
    # 0A C5 01 92 92 C8 01 81 05 16 00
    read_data = "0F 09 C5 01 00 92 C8 01 81 00 05"  # 22"
    read_data_1 = bytes.fromhex(read_data)
    resp.extend(read_data_1)
    #read_data_2 = bytes.fromhex(copy_cnt)
    # resp.extend(copy_cnt)
    read_data_3 = get_crc(resp)
    #print("read_data_3 ",read_data_3)
    # resp.extend(read_date_3)
    data = bytearray()
    data.extend(read_data_1)
    # data.extend(copy_cnt)
    read_data_3 = bytes.fromhex(read_data_3)
    data.extend(read_data_3)
    print("Send Data ", data.hex())
    # api.py_aa_sleep_ms(1)
    send(data, len(data))
    read_fun(handle, 64, timeout_ms)


transfer_complete_flag = 0


def file_transfer(handle, filename, timeout, USE_PLDM_HEADER=False):
    global log
    #global handle
    global addr
    global timeout_ms
    global process
    global transfer_offset
    global transfer_length
    global transfer_complete_flag
    global binary_image
    # debug_counter = 0 # Uncomment this line to test prm - packet retry mechanism
    # Open the file
    if USE_PLDM_HEADER == False:
        try:
            file = open(filename, 'rb')
        except:
            print("Unable to open file '" + filename + "'")
            return
        file_size = os.path.getsize(filename)
        print("file_size ", file_size)
        file_content = file.read()
    else:
        file_content = binary_image
        file_size = len(binary_image)
    offset = 0

    print("file_size ", file_size)
    print("Start ")
    # creating object
    global obj_now_start
    obj_now_start = datetime.now()

    # log.write("\n file_transfer Started "+filename)
    print("Current date & time: ", obj_now_start)

    if process == 1:
        print("\nRequest Firmware is ready for File transfer to FD")
    else:
        print("\nRequest Firmware is not ready for File transfer to FD", process)
        sys.exit(0)
    while(transfer_complete_flag != 1):
        loop_offset = 0
        byte_cnt = 0
        num_bytes_to_be_transferred = transfer_length
        max_data_bytes = 0
        iter = 0

        while(num_bytes_to_be_transferred):
            # frame
            read_data1 = "C8"
            read_data1 = bytes.fromhex(read_data1)
            resp = bytearray()
            resp.append(read_data1[0])

            if num_bytes_to_be_transferred <= 64:  # last packet
                copy_cnt = file_content[transfer_offset +
                                        loop_offset:transfer_offset + loop_offset + num_bytes_to_be_transferred]
                
                read_data = "0F 1F C5 01 00 00 40"
                read_data_1 = bytes.fromhex(read_data)

                # convert to list to modify count parameter, SOM, PKT_SEQ_NUM bits
                list1 = list(read_data_1)
                
                # modify count
                list1[1] =  len(read_data_1) - 2 + len(copy_cnt) # subtract 2 to account for mctp pkt cmd code (0F) and Length field

                # modify pkt_seq_num
                pkt_seq_num = iter % 4
                list1[6] = list1[6] | (pkt_seq_num << 4)

                # Re-Convert list to byte array
                read_data_1 = bytearray(list1)

                resp.extend(read_data_1)
                resp.extend(copy_cnt)
                read_data_3 = get_crc(resp)

                data = bytearray()
                data.extend(read_data_1)
                data.extend(copy_cnt)
                read_data_3 = bytes.fromhex(read_data_3)
                data.extend(read_data_3)

                if process == 1:
                    send(data, len(data))
                    api.py_aa_sleep_ms(50) #TODO
                break

            else:
                if(iter  == 0): # First Packet
                    read_data = "0F 45 C5 01 00 00 00 01 00 05 15 00"
                else:
                    read_data = "0F 45 C5 01 00 00 00" # Second packet to (last_packet - 1)
                read_data_1 = bytes.fromhex(read_data)
                
                max_data_bytes = 71 - len(read_data_1)
                copy_cnt = file_content[transfer_offset +
                                    loop_offset:transfer_offset + loop_offset + max_data_bytes]
                loop_offset+= max_data_bytes 

                # convert to list to modify SOM, PKT_SEQ_NUM bits, COUNT
                list1 = list(read_data_1)

                # modify count
                list1[1] =  len(read_data_1) - 2 + len(copy_cnt) # subtract 2 to account for mctp pkt cmd code (0F) and Length field

                # modify pkt_seq_num
                pkt_seq_num = iter % 4

                # Uncomment following commented lines of code to test pkt retry mechanism prm
                # if(debug_counter == 0 and (transfer_offset == 0x38000)):
                #     print("Intentionally modify pkt seq num for testing ")
                #     debug_counter += 1
                #     if(pkt_seq_num == 3):
                #         pkt_seq_num = 2

                list1[6] = list1[6] | (pkt_seq_num << 4)

                # modify SOM
                if(iter == 0):
                    list1[6] = list1[6] | (1 << 7)

                # Re-Convert list to byte array
                read_data_1 = bytearray(list1)
                resp.extend(read_data_1)
                resp.extend(copy_cnt)
                read_data_3 = get_crc(resp)

                data = bytearray()
                data.extend(read_data_1)
                data.extend(copy_cnt)
                read_data_3 = bytes.fromhex(read_data_3)
                data.extend(read_data_3)

                if process == 1:
                    send(data, len(data))
                    api.py_aa_sleep_ms(50) #TODO
            num_bytes_to_be_transferred -= max_data_bytes
            iter+=1 #Iter for packet sequence number

        print('\r FW Image Write BytesWriten start_offset:end_offset/TotalSize : ', hex(transfer_offset), ':', hex(transfer_offset + transfer_length - 1),
              '/', hex(file_size - 1), end="\r")
        req_dump(handle, timeout)  # wait until pr
        retry_count = 3
        while((process == 0) and (retry_count != 0)):
            req_dump(handle, timeout)
            retry_count = retry_count - 1
        if(process == 0):
            print("\nERROR request not received ")
            sys.exit(1)

    print("\n file_transfer Ended ")
    transfer_complete_flag = 0
    # creating object
    obj_now = datetime.now()
    print("After transfer of image, current time: ", obj_now)


transfer_offset = 0
transfer_length = 0


def packet_parser_update(packet, length):
    global transfer_comp_count
    global transfer_complete_flag
    global process
    global verify_comp_flag
    global apply_comp_flag
    global status_var

    global verify_sucess
    global transfer_offset
    global transfer_length
    global ic
    #print("packet_parser Function")
    variable = 0
    status_var = 0
    try:
        val = packet[10]
        status_var = packet[11]
    except:
        val = 0
        status_var = 0
    if val == 0x15:
        # print('[{}]'.format(', '.join(hex(x) for x in packet)))
        transfer_offset = 0
        transfer_length = 0
        for i in range(0, 4):
            transfer_offset += packet[11 + i] << 8 * i
            transfer_length += packet[15 + i] << 8 * i
        variable = 1
    if val == 0x16:
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        print("\n Transfercomplete Commadn received from  FD to Host \n")
        transfercomplete_resp()
        transfer_comp_count += 1
        transfer_complete_flag = 1
        variable = 2
    if val == 0x17:
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        print("\n VerifyComplete Commadn received from  FD to Host \n")
        verifycomplete_resp()
        verify_comp_flag += 1
        if status_var == 0x0:
            verify_sucess = 1
        else:
            verify_sucess = 0
        print("\n VerifyComplete Commadn received from  FD to Host status: 1 --> success; 0 ---> fail : ", verify_sucess)
        variable = 2
    if val == 0x18:
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        print("\n Apply Command  Commadn received from  FD to Host \n")
        applycomplete_resp()
        if verify_sucess == 1:
            apply_comp_flag += 1
        else:
            apply_comp_flag = 0
        variable = 0x5  # Status code to indicate Received apply cmd
    return variable


def req_dump_(handle, timeout_ms):
    global log
    global error_reported
    global command_resp_len
    global process
    global transfer_comp_count
    global verify_comp_flag
    status_var = ''
    process = 0
    #print ("Request Firmware Watching slave I2C data...")

    command = []
    command.append(13)
    command.append(20)
    command.append(72)
    command.append(20)
    i = 0
    # for x in command:
    # print(command[i])
    #    i = i+1
    #command[4] ={13,20,72}
    j = 3
    retry_flag = 3
    # Loop until aa_async_poll times out
    while retry_flag:
        # print("Loop")
        if(process != 5):
            result = api.py_aa_async_poll(handle, timeout_ms)
            if (result == AA_ASYNC_NO_DATA):
                #print ("No data available.")
                return
        else:
            return
        status = ""
        # Read the I2C message.
        # This function has an internal timeout (see datasheet), though
        # since we have already checked for data using aa_async_poll,
        # the timeout should never be exercised.
        if (result == AA_ASYNC_I2C_READ):
            # Get data written by master
            (num_bytes, addr, data_in) = aa_i2c_slave_read(
                handle, command[j])  # command_resp_len)

            if (num_bytes < 0):
                log.write("error: %s" % api.py_aa_status_string(status))
                error_reported = 1
                retry_flag = retry_flag-1
                return

            process = packet_parser_update(data_in, num_bytes)
            # retry_flag =retry_flag - 1

        command_resp_len = 20


def req_dump(handle, timeout_ms):
    global log
    global error_reported
    global command_resp_len
    global process
    global transfer_comp_count
    global verify_comp_flag
    status_var = ''
    process = 0
    #print ("Request Firmware Watching slave I2C data...")

    command = []
    command.append(13)
    command.append(20)
    command.append(72)
    command.append(20)
    i = 0
    j = 3
    retry_flag = 3
    # Loop until aa_async_poll times out
    while retry_flag:
        # print("Loop")
        result = api.py_aa_async_poll(handle, timeout_ms)
        if (result == AA_ASYNC_NO_DATA):
            #print ("No data available.")
            retry_flag = retry_flag-1
            return
            # continue

        #print ("")

        trans_num = 0
        status = ""
        # Read the I2C message.
        # This function has an internal timeout (see datasheet), though
        # since we have already checked for data using aa_async_poll,
        # the timeout should never be exercised.
        if (result == AA_ASYNC_I2C_READ):
            # Get data written by master
            (num_bytes, addr, data_in) = aa_i2c_slave_read(
                handle, command[j])  # command_resp_len)

            if (num_bytes < 0):
                log.write("error: %s" % api.py_aa_status_string(status))
                error_reported = 1
                retry_flag = retry_flag-1
                # continue
                return
            process = packet_parser_update(data_in, num_bytes)

        elif (result == AA_ASYNC_I2C_WRITE):
            # Get number of bytes written to master
            num_bytes = aa_i2c_slave_write_stats(handle)

            if (num_bytes < 0):
                log.write("error: %s" % api.py_aa_status_string(status))
                error_reported = 1
                retry_flag = retry_flag-1
                # continue
                return

        trans_num = trans_num + 1
        command_resp_len = 20


def packet_parser(packet, length):
    #print("packet_parser Function")
    global get_response_flag
    global fw_get_response_flag
    global process
    global query_packet
    global get_fw_query_packet
    global req_update_flag
    global req_update_status
    global transfer_offset
    global transfer_length
    variable = 0
    eom_bit_val = False
    try:
        var = packet[10]
    except:
        var = 0

    if var == 0x1:
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        query_packet += packet[11:len(packet)-1]
        get_response_flag = 1
        # return (process,variable)
    if var == 0x1B:
        print("Get status response ", packet)
    if var == 0x10:
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        req_update_flag = 1
        req_update_status = hex(packet[11])
    if var == 0x15:
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        print("\nRequestFirmwareData Commadn received from  FD to Host \n")
        transfer_offset = 0
        transfer_length = 0
        for i in range(0, 4):
            transfer_offset += packet[11 + i] << 8 * i
            transfer_length += packet[15 + i] << 8 * i
        variable = 1
        process = 1
    if var == 0x02:
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        get_fw_query_packet += packet[11:len(packet)-1]
        fw_get_response_flag = 1
    if var == 0x16:
        print("\n Transfercomplete Commadn received from  FD to Host \n")
    if var == 0x17:
        print("\n VerifyComplete Commadn received from  FD to Host \n")
    if var == 0x18:
        print("\n Apply Command  Commadn received from  FD to Host \n")
    if var == 0x13:
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        print("\n Pass comp resp  Commadn received from  FD to Host \n")
    if var == 0x14:
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        print("\n update comp resp cmmnd received from FD to host \n")
    if(packet[6] & (1<<6) != 0):
        eom_bit_val = True
    else:
        eom_bit_val = False
    return eom_bit_val


def read_fun(handle, length, timeout_ms):
    global log
    global error_reported
    global command_resp_len
    global process

    one_time_data = []
    data_in_parse = []
    process = 0
    variable = 0
    #print ("Response From FW")
    log.write("Response From FW")
    iter = 0
    i = 0
    j = 3
    retry_flag = 3
    # Loop until aa_async_poll times out
    while retry_flag:
        result = api.py_aa_async_poll(handle, timeout_ms)
        if (result == AA_ASYNC_NO_DATA):
            #print ("No data available.")
            retry_flag = retry_flag-1
            continue

        #print ("")

        trans_num = 0
        status = ""
        # Read the I2C message.
        # This function has an internal timeout (see datasheet), though
        # since we have already checked for data using aa_async_poll,
        # the timeout should never be exercised.
        if (result == AA_ASYNC_I2C_READ):
            # Get data written by master
            (num_bytes, addr, data_in) = aa_i2c_slave_read(
                handle, length)  # command_resp_len)

            if (num_bytes < 0):
                #print ("error: %s" % api.py_aa_status_string(status))
                error_reported = 1
                retry_flag = retry_flag-1
                continue
            if(iter == 0):
                one_time_data = data_in[7:11]
                data_in_parse = data_in
                # print('[{}]'.format(', '.join(hex(x) for x in one_time_data)))
                iter+=1
                # answer = input('Would you like to update component id <Y/N>').lower()
                # if answer.startswith('n'):
                #     sys.exit(1)                # print(one_time_data)
                # appended_data = one_time_data + data_in
                # print(appended_data)
            else:
                data_in_parse = data_in[0:7] + one_time_data + data_in[7:len(data_in)]
                # print('[{}]'.format(', '.join(hex(x) for x in data_in)))
                # print('[{}]'.format(', '.join(hex(x) for x in data_in_parse)))
                # answer = input('Would you like to update component id <Y/N>').lower()
                # if answer.startswith('n'):
                #     sys.exit(1)
                

                # return
            #print("num_bytes ",num_bytes,"length ",length)
            is_eom_bit_set = packet_parser(data_in_parse, num_bytes)
            if(is_eom_bit_set==True):
                return

        elif (result == AA_ASYNC_I2C_WRITE):
            # Get number of bytes written to master
            num_bytes = aa_i2c_slave_write_stats(handle)

            if (num_bytes < 0):
                log.write("error: %s" % api.py_aa_status_string(status))
                error_reported = 1
                retry_flag = retry_flag-1
                continue
                # return

            # Print status information to the screen
            log.write("*** Transaction #%02d" % trans_num)
            log.write("Number of bytes written to master: %04d" % num_bytes)
            log.write("")

        # else:
        #    print ("error: non-I2C asynchronous message is pending")
            # return

        trans_num = trans_num + 1
        command_resp_len = 20
# ==========================================================================
# FUNCTIONS
# ==========================================================================


def send(z, command_len, k=0):
    global handle
    global addr
    global Master_Slave_Addr
    api.py_aa_i2c_write(handle, addr, AA_I2C_NO_FLAGS, command_len, z)
    # if(k==1):
    #     print('[{}]'.format(', '.join(hex(x) for x in z)))
    #     print(command_len)
    #     print("\n")


def read():
    print("")


port = 0
handle = 0
addr = 0
timeout_ms = 0


def dword_bytes(value):
    value = value & 0xffffffff  # << 4
    v1 = (value & (0xFF))
    v2 = ((value >> 8) & (0xFF))
    v3 = ((value >> 16) & (0xFF))
    v4 = ((value >> 24) & (0xFF))
    data_table = bytearray()
    temp = struct.pack('B', v1)
    data_table.extend(temp)
    temp = struct.pack('B', v2)
    data_table.extend(temp)
    temp = struct.pack('B', v3)
    data_table.extend(temp)
    temp = struct.pack('B', v4)
    data_table.extend(temp)
    return data_table


def qword_bytes(value):
    value = value & 0xffff  # << 4
    v1 = (value & (0xFF))
    v2 = ((value >> 8) & (0xFF))
    data_table = bytearray()
    temp = struct.pack('B', v1)
    data_table.extend(temp)
    temp = struct.pack('B', v2)
    data_table.extend(temp)
    return data_table


def int1_to_bytes(value):
    value = value & 0xff  # << 4
    v1 = (value & (0xFF))
    data_table = bytearray()
    temp = struct.pack('B', v1)
    data_table.extend(temp)
    return data_table

def transfercomplete_resp():
    global log
    global Master_Slave_Addr
    global timeout_ms
    #Master_Slave_Addr  =Master_Slave_Addr *2
    print("Found the verifyresponse")
    cmd_bytes = bytearray()
    d = bytearray()
    cmd_bytes.append(Master_Slave_Addr)
    read_data = "0F 0A C5 01 00 92 C8 01 81 05 16 00"
    read_data1 = bytes.fromhex((read_data))
    cmd_bytes.extend(read_data1)
    #print("CommandCode ",CommandCode)
    read_data_3 = get_crc(cmd_bytes)
    value = bytes.fromhex(read_data_3)
    #print("Get crc ",read_data_3)
    #print("cmd bytes",cmd_bytes.hex())
    data = bytearray()
    data.extend(read_data1)
    data.extend(d)
    data.extend(value)
    log.write("UA Send transfer COMPL RESPONSE "+data.hex())
    print("UA Send transfer COMPL RESPONSE ", data.hex())
    send(data, len(data))

def verifycomplete_resp():
    global log
    global Master_Slave_Addr
    global timeout_ms
    #Master_Slave_Addr  =Master_Slave_Addr *2
    print("Found the verifyresponse")
    cmd_bytes = bytearray()
    d = bytearray()
    cmd_bytes.append(Master_Slave_Addr)
    read_data = "0F 0A C5 01 00 92 C8 01 81 05 17 00"
    read_data1 = bytes.fromhex((read_data))
    cmd_bytes.extend(read_data1)
    #print("CommandCode ",CommandCode)
    read_data_3 = get_crc(cmd_bytes)
    value = bytes.fromhex(read_data_3)
    #print("Get crc ",read_data_3)
    #print("cmd bytes",cmd_bytes.hex())
    data = bytearray()
    data.extend(read_data1)
    data.extend(d)
    data.extend(value)
    log.write("UA Send VERIFY COMPL RESPONSE "+data.hex())
    print("UA Send VERIFY COMPL RESPONSE ", data.hex())
    send(data, len(data))

def applycomplete_resp():
    global log
    global Master_Slave_Addr
    global timeout_ms
    #Master_Slave_Addr  =Master_Slave_Addr *2
    print("Found the verifyresponse")
    cmd_bytes = bytearray()
    d = bytearray()
    cmd_bytes.append(Master_Slave_Addr)
    read_data = "0F 0A C5 01 00 92 C8 01 81 05 18 00"
    read_data1 = bytes.fromhex((read_data))
    cmd_bytes.extend(read_data1)
    #print("CommandCode ",CommandCode)
    read_data_3 = get_crc(cmd_bytes)
    value = bytes.fromhex(read_data_3)
    #print("Get crc ",read_data_3)
    #print("cmd bytes",cmd_bytes.hex())
    data = bytearray()
    data.extend(read_data1)
    data.extend(d)
    data.extend(value)
    log.write("UA Send apply COMPL RESPONSE "+data.hex())
    print("UA Send apply COMPL RESPONSE ", data.hex())
    send(data, len(data))


def Get_Firmwareparameters_command(parser, var, USE_PLDM_HEADER=False):
    global log
    global Master_Slave_Addr
    global timeout_ms
    #Master_Slave_Addr  =Master_Slave_Addr *2
    if var.find("GetFirmwareparameters") == 0 or USE_PLDM_HEADER == True:
        print("Found the GetFirmwareparameters")
        cmd_bytes = bytearray()
        d = bytearray()

        cmd_bytes.append(Master_Slave_Addr)
        read_data = "0F 09 C5 01 00 92 C8 01 81 05 02"
        # 0F 15 C5 01 00 92 C8 01 81 05 10
        read_data1 = bytes.fromhex((read_data))
        cmd_bytes.extend(read_data1)
        # for name, value in parser.items(var):
        #     if name.lower() == "commandcode":
        #         CommandCode = value
        #         CommandCode = int(CommandCode, 16)
        #print("CommandCode ",CommandCode)
        read_data_3 = get_crc(cmd_bytes)
        value = bytes.fromhex(read_data_3)
        #print("Get crc ",read_data_3)
        #print("cmd bytes",cmd_bytes.hex())
        data = bytearray()
        data.extend(read_data1)
        data.extend(d)
        data.extend(value)
        log.write("UA Send GetFirmwareparameters "+data.hex())
        print("UA Send GetFirmwareparameters ", data.hex())
        send(data, len(data))
        #print("UA Receives QuerydeviceIdentifiers from FD")
        read_fun(handle, 1024, timeout_ms)


def query_command(parser, var, USE_PLDM_HEADER=False):
    global log
    global Master_Slave_Addr
    global timeout_ms
    #Master_Slave_Addr  =Master_Slave_Addr *2
    if var.find("QuerydeviceIdentifiers") == 0 or USE_PLDM_HEADER == True:
        print("===============================================================")
        print("Found the QuerydeviceIdentifiers")
        cmd_bytes = bytearray()
        d = bytearray()

        cmd_bytes.append(Master_Slave_Addr)
        read_data = "0F 09 C5 01 00 92 C8 01 81 05 01"
        # 0F 15 C5 01 00 92 C8 01 81 05 10
        read_data1 = bytes.fromhex((read_data))
        cmd_bytes.extend(read_data1)
        # for name, value in parser.items(var):
        #     if name.lower() == "commandcode":
        #         CommandCode = value
        #         CommandCode = int(CommandCode, 16)
        #         #print("CommandCode ",CommandCode)
        read_data_3 = get_crc(cmd_bytes)
        value = bytes.fromhex(read_data_3)
        #print("Get crc ",read_data_3)
        #print("cmd bytes",cmd_bytes.hex())
        data = bytearray()
        data.extend(read_data1)
        data.extend(d)
        data.extend(value)
        log.write("UA Send QuerydeviceIdentifiers "+data.hex())
        print("UA Send QuerydeviceIdentifiers ", data.hex())
        print("===============================================================")
        send(data, len(data))
        #print("UA Receives QuerydeviceIdentifiers from FD")
        read_fun(handle, 1024, timeout_ms)
        # GetStatus()


def Request_Update_command_bin(num_of_components):
    global Master_Slave_Addr
    global timeout_ms
    global process
    flag = "false"

    payload = bytearray()
    pldm_header = "0F 15 C5 01 00 92 C8 01 81 05 10"
    pldm_header_in_bytes = bytes.fromhex((pldm_header))

    if(1):
        MaximumTransferSize = 0x400  # Configurable
        value = dword_bytes(MaximumTransferSize)
        payload.extend(value)
        #------#------#------#

        value = qword_bytes(num_of_components)
        payload.extend(value)
        #------#------#------#

        MaxOutstandingtransferrequests = 0x0
        value = int1_to_bytes(MaxOutstandingtransferrequests)
        payload.extend(value)
        #------#------#------#

        PackagedataLength = php_fw_dev_id.FirmwareDevicePackageDataLength
        value = qword_bytes(PackagedataLength)
        #print("ater packagedatalength ",value.hex())
        payload.extend(value)
        #------#------#------#

        Componentversionstringtype = php_fw_dev_id.ComponentImageSetVersionStringType
        value = int1_to_bytes(Componentversionstringtype)
        #print("ater componentversionstringtype ",value.hex())
        payload.extend(value)
        #------#------#------#

        Componentversionstringlength = php_fw_dev_id.ComponentImageSetVersionStringLength
        value = int1_to_bytes(Componentversionstringlength)
        #print("ater Componentversionstringlength ",value.hex())
        payload.extend(value)
        #------#------#------#

        # print(php_fw_dev_id.ComponentImageSetVersionString)
        ComponentVersioString = php_fw_dev_id.ComponentImageSetVersionString
        # arr = [0xa]
        value = bytes(ComponentVersioString)
        # value =  bytes(arr)
        payload.extend(value)

    total_length = len(pldm_header_in_bytes) + len(payload)

    # convert to list to modify pkt length
    list1 = list(pldm_header_in_bytes)
    list1[1] = total_length - 2
    pldm_header_in_bytes = bytearray(list1)

    temp = bytearray()
    temp.append(Master_Slave_Addr)
    temp = temp + pldm_header_in_bytes + payload
    crc = get_crc(temp)
    crc_in_bytes = bytes.fromhex(crc)

    data = bytearray()
    data.extend(pldm_header_in_bytes)
    data.extend(payload)
    data.extend(crc_in_bytes)
    print("data ", data.hex())

    send(data, len(data), 1)
    read_fun(handle, 64, timeout_ms)


def Requestcommand(parser, var):
    global log
    global Master_Slave_Addr
    global timeout_ms
    global req_update_flag
    global req_update_status
    global process
    flag = "false"

    #Master_Slave_Addr  =Master_Slave_Addr *2
    if var.find("RequestUpdate") == 0:
        print("Found the RequestUpdate")
        flag = "false"
        cmd_bytes = bytearray()
        d = bytearray()
        cmd_bytes.append(Master_Slave_Addr)
        read_data = "0F 15 C5 01 00 92 C8 01 81 05 10"
        # 0F 15 C5 01 00 92 C8 01 81 05 10
        read_data1 = bytes.fromhex((read_data))
        cmd_bytes.extend(read_data1)
        for name, value in parser.items(var):
            if name.lower() == "commandcode":
                CommandCode = value
                CommandCode = int(CommandCode, 16)
                #print("CommandCode ",CommandCode)
            if name.lower() == "maximumtransfersize":
                MaximumTransferSize = int(value, 16)
                #print("Before MaximumTransferSize ",MaximumTransferSize)
                value = dword_bytes(MaximumTransferSize)
                #print("ater MaximumTransferSize ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "numberofcomponents":
                NumberofComponents = int(value, 16)
                #print("NumberofComponents ",NumberofComponents)
                value = qword_bytes(NumberofComponents)
                #print("ater numberofcomponents ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "maxoutstandingtransferrequests":
                MaxOutstandingtransferrequests = int(value, 16)
                value = int1_to_bytes(MaxOutstandingtransferrequests)
                #print("ater maxoutstandingtransferrequests ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "packagedatalength":
                PackagedataLength = int(value, 16)
                value = qword_bytes(PackagedataLength)
                #print("ater packagedatalength ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentversionstringtype":
                Componentversionstringtype = int(value, 16)
                value = int1_to_bytes(Componentversionstringtype)
                #print("ater componentversionstringtype ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentversionstringlength":
                Componentversionstringlength = int(value, 16)
                value = int1_to_bytes(Componentversionstringlength)
                #print("ater Componentversionstringlength ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentversiostring":
                ComponentVersioString = int(value, 16)
                value = int1_to_bytes(ComponentVersioString)
                #print("ater componentversiostring ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "userequestupdate":
                flag = value
        read_data_3 = get_crc(cmd_bytes)
        value = bytes.fromhex(read_data_3)
        #print("Get crc ",read_data_3)
        #print("cmd bytes",cmd_bytes.hex())
        data = bytearray()
        data.extend(read_data1)
        data.extend(d)
        data.extend(value)
        print("data ", data.hex())
        if flag == "true":
            send(data, len(data))
            read_fun(handle, 64, timeout_ms)
        else:
            print("UseRequestUpdate request is False")
            sys.exit(0)


def PassComponentTablecommand_bin(comp_classification, comp_id, ComponentComparisonStamp, ComponentVersionStringType, ComponentVersionStringLength, ComponentVersionString):
    global log
    global Master_Slave_Addr
    global timeout_ms
    global req_update_flag
    global req_update_status
    global process

    payload = bytearray()
    pldm_header = "0F 15 C5 01 00 92 C8 01 81 05 13"
    pldm_header_in_bytes = bytes.fromhex((pldm_header))

    if(1):
        #----------------#
        transfer_flag = 0x05
        value = int1_to_bytes(transfer_flag)
        payload.extend(value)

        #----------------#
        value = qword_bytes(comp_classification)
        payload.extend(value)

        #----------------#
        value = qword_bytes(comp_id)
        payload.extend(value)

        #----------------#
        componentclassificationindex = 0x0  # No downstream device for SG3, so value is 0
        value = int1_to_bytes(componentclassificationindex)
        #print("ater packagedatalength ",value.hex())
        payload.extend(value)

        #----------------#
        value = dword_bytes(ComponentComparisonStamp)
        #print("ater packagedatalength ",value.hex())
        payload.extend(value)

        #----------------#
        value = int1_to_bytes(ComponentVersionStringType)
        #print("ater componentversionstringtype ",value.hex())
        payload.extend(value)

        #----------------#
        value = int1_to_bytes(ComponentVersionStringLength)
        #print("ater Componentversionstringlength ",value.hex())
        payload.extend(value)

        #----------------#
        value = bytes(ComponentVersionString)
        #print("ater componentversiostring ",value.hex())
        payload.extend(value)

        #----------------#

        total_length = len(pldm_header_in_bytes) + len(payload)

        # convert to list to modify pkt length
        list1 = list(pldm_header_in_bytes)
        list1[1] = total_length - 2
        pldm_header_in_bytes = bytearray(list1)

        temp = bytearray()
        temp.append(Master_Slave_Addr)
        temp = temp + pldm_header_in_bytes + payload
        crc = get_crc(temp)
        crc_in_bytes = bytes.fromhex(crc)

        data = bytearray()
        data.extend(pldm_header_in_bytes)
        data.extend(payload)
        data.extend(crc_in_bytes)
        print("data ", data.hex())

        print("UsePassComponentTable request is True")
        send(data, len(data), 1)
        read_fun(handle, 64, timeout_ms)


def PassComponentTablecommand(parser, var):
    global log
    global Master_Slave_Addr
    global timeout_ms
    global req_update_flag
    global req_update_status
    global process
    flag = "false"

    #Master_Slave_Addr  =Master_Slave_Addr *2
    if var.find("PassComponentTable") == 0:
        flag = "false"
        #print("Found the PassComponentTable")
        cmd_bytes = bytearray()
        d = bytearray()
        cmd_bytes.append(Master_Slave_Addr)
        read_data = "0F 16 C5 01 00 92 C8 01 81 05 13"
        # 0F 15 C5 01 00 92 C8 01 81 05 10
        read_data1 = bytes.fromhex((read_data))
        cmd_bytes.extend(read_data1)
        for name, value in parser.items(var):
            if name.lower() == "commandcode":
                CommandCode = value
                CommandCode = int(CommandCode, 16)
                #print("CommandCode ",CommandCode)
            if name.lower() == "transferflag":
                MaximumTransferSize = int(value, 16)
                #print("Before MaximumTransferSize ",MaximumTransferSize)
                value = int1_to_bytes(MaximumTransferSize)
                #print("ater MaximumTransferSize ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentclassification":
                NumberofComponents = int(value, 16)
                #print("NumberofComponents ",NumberofComponents)
                value = qword_bytes(NumberofComponents)
                #print("ater numberofcomponents ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentidentifier":
                MaxOutstandingtransferrequests = int(value, 16)
                value = qword_bytes(MaxOutstandingtransferrequests)
                #print("ater maxoutstandingtransferrequests ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentclassificationindex":
                PackagedataLength = int(value, 16)
                value = int1_to_bytes(PackagedataLength)
                #print("ater packagedatalength ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentcomparisonstamp":
                PackagedataLength = int(value, 16)
                value = dword_bytes(PackagedataLength)
                #print("ater packagedatalength ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentversionstringtype":
                Componentversionstringtype = int(value, 16)
                value = int1_to_bytes(Componentversionstringtype)
                #print("ater componentversionstringtype ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentversionstringlength":
                Componentversionstringlength = int(value, 16)
                value = int1_to_bytes(Componentversionstringlength)
                #print("ater Componentversionstringlength ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentversiostring":
                ComponentVersioString = int(value, 16)
                value = int1_to_bytes(ComponentVersioString)
                #print("ater componentversiostring ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "usepasscomponenttable":
                flag = value
        read_data_3 = get_crc(cmd_bytes)
        value = bytes.fromhex(read_data_3)
        #print("Get crc ",read_data_3)
        #print("cmd bytes",cmd_bytes.hex())
        data = bytearray()
        data.extend(read_data1)
        data.extend(d)
        data.extend(value)
        print("data ", data.hex())
        # GetStatus()
        if flag == "true":
            print("UsePassComponentTable request is True")
            send(data, len(data))
            read_fun(handle, 64, timeout_ms)
        else:
            print("UsePassComponentTable request is False")
            sys.exit(0)


total_update_comp = 0  # Total Components to be updated


def UpdateComponentTableCommand_bin(comp_classification, comp_id, ComponentComparisonStamp, img_size, ComponentVersionStringType, ComponentVersionStringLength, ComponentVersionString):
    global log
    global Master_Slave_Addr
    global timeout_ms
    global req_update_flag
    global req_update_status
    global process
    global total_update_comp

    if 1:
        total_update_comp += 1
        #print("Found the UpdateComponent")
        payload = bytearray()
        pldm_header = "0F 1C C5 01 00 92 C8 01 81 05 14"
        pldm_header_in_bytes = bytes.fromhex(pldm_header)

        #----------------##----------------#

        value = qword_bytes(comp_classification)
        payload.extend(value)
        #----------------##----------------#

        value = qword_bytes(comp_id)
        #print("ater componentidentifier ",value.hex())
        payload.extend(value)
        #----------------##----------------#

        value = int1_to_bytes(0x0)
        #print("ater componentclassificationindex ",value.hex())
        payload.extend(value)
        #----------------##----------------#

        value = dword_bytes(ComponentComparisonStamp)
        #print("ater componentcomparisonstamp ",value.hex())
        payload.extend(value)
        #----------------##----------------#

        value = dword_bytes(img_size)
        #print("ater componentimagesize ",value.hex())
        payload.extend(value)
        #----------------##----------------#

        value = dword_bytes(0x0)
        #print("ater updateoptionflags ",value.hex())
        payload.extend(value)
        #----------------##----------------#

        value = int1_to_bytes(ComponentVersionStringType)
        #print("ater componentversionstringtype ",value.hex())
        payload.extend(value)
        #----------------##----------------#

        value = int1_to_bytes(ComponentVersionStringLength)
        #print("ater Componentversionstringlength ",value.hex())
        payload.extend(value)
        #----------------##----------------#

        value = bytes(ComponentVersionString)
        payload.extend(value)
        #----------------##----------------#

        total_length = len(pldm_header_in_bytes) + len(payload)

        # convert to list to modify pkt length
        list1 = list(pldm_header_in_bytes)
        list1[1] = total_length - 2
        pldm_header_in_bytes = bytearray(list1)

        temp = bytearray()
        temp.append(Master_Slave_Addr)
        temp = temp + pldm_header_in_bytes + payload
        crc = get_crc(temp)
        crc_in_bytes = bytes.fromhex(crc)

        data = bytearray()
        data.extend(pldm_header_in_bytes)
        data.extend(payload)
        data.extend(crc_in_bytes)
        print("data ", data.hex())

        print("UpdateComponent request is True")
        send(data, len(data), 1)
        read_fun(handle, 64, timeout_ms) # Get UpdateComponent response
        read_fun(handle, 64, timeout_ms) # Get requestFWdata response sent by FD


def command(parser, var):
    global log
    global Master_Slave_Addr
    global timeout_ms
    global req_update_flag
    global req_update_status
    global process
    global total_update_comp
    flag = "false"

    #Master_Slave_Addr  =Master_Slave_Addr *2
    if var.find("UpdateComponent") == 0:
        total_update_comp += 1
        #print("Found the UpdateComponent")
        flag = "false"
        cmd_bytes = bytearray()
        d = bytearray()
        cmd_bytes.append(Master_Slave_Addr)
        read_data = "0F 1D C5 01 00 92 C8 01 81 05 14"
        # 0F 15 C5 01 00 92 C8 01 81 05 10
        read_data1 = bytes.fromhex((read_data))
        cmd_bytes.extend(read_data1)
        for name, value in parser.items(var):
            if name.lower() == "commandcode":
                CommandCode = value
                CommandCode = int(CommandCode, 16)
                #print("CommandCode ",CommandCode)
            if name.lower() == "componentclassification":
                MaximumTransferSize = int(value, 16)
                #print("Before MaximumTransferSize ",MaximumTransferSize)
                value = qword_bytes(MaximumTransferSize)
                #print("ater componentclassification ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentidentifier":
                MaxOutstandingtransferrequests = int(value, 16)
                value = qword_bytes(MaxOutstandingtransferrequests)
                #print("ater componentidentifier ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentclassificationindex":
                PackagedataLength = int(value, 16)
                value = int1_to_bytes(PackagedataLength)
                #print("ater componentclassificationindex ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentcomparisionstamp":
                PackagedataLength = int(value, 16)
                value = dword_bytes(PackagedataLength)
                #print("ater componentcomparisonstamp ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentimagesize":
                PackagedataLength = int(value, 16)
                value = dword_bytes(PackagedataLength)
                #print("ater componentimagesize ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "updateoptionflags":
                PackagedataLength = int(value, 16)
                value = dword_bytes(PackagedataLength)
                #print("ater updateoptionflags ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentversionstringtype":
                Componentversionstringtype = int(value, 16)
                value = int1_to_bytes(Componentversionstringtype)
                #print("ater componentversionstringtype ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentversionstringlength":
                Componentversionstringlength = int(value, 16)
                value = int1_to_bytes(Componentversionstringlength)
                #print("ater Componentversionstringlength ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "componentversiostring":
                ComponentVersioString = int(value, 16)
                value = int1_to_bytes(ComponentVersioString)
                #print("ater componentversiostring ",value.hex())
                cmd_bytes.extend(value)
                d.extend(value)
            if name.lower() == "useupdatecomponent":
                flag = value
        read_data_3 = get_crc(cmd_bytes)
        value = bytes.fromhex(read_data_3)
        #print("Get crc ",read_data_3)
        #print("cmd bytes",cmd_bytes.hex())
        data = bytearray()
        data.extend(read_data1)
        data.extend(d)
        data.extend(value)
        print("data ", data.hex())
        # GetStatus()
        if flag == "true":
            print("UpdateComponent request is True")
            send(data, len(data))
            read_fun(handle, 64, timeout_ms)
        else:
            print("UseUpdateComponent request is False")
            sys.exit(0)
    if var.find("RequestFirmwaredata") == 0:
        print("Found the RequestFirmwaredata")
        flag = "false"
        for name, value in parser.items(var):
            if name.lower() == "commandcode":
                CommandCode = value
                CommandCode = int(CommandCode, 16)
            if name.lower() == "componentidentifierimage":
                ComponentIdentifierImage = value
            if name.lower() == "timeout_ms":
                timeout = value
                timeout = int(timeout, 10)
            if name.lower() == "userequestfirmwaredata":
                flag = value
        if flag == "true":
            print("RequestFirmwaredata request is True")
            file_transfer(handle, ComponentIdentifierImage, timeout)
            num_of_cmds = 2
            while(num_of_cmds and (process != 5)):
                req_dump_(handle, 30000)
                num_of_cmds = num_of_cmds - 1

        else:
            print("UseRequestFirmwaredata request is False")
            sys.exit(0)
        # GetStatus()
            #print("CommandCode ",CommandCode)


def configure_aadvark():
    global log
    global handle
    global port
    global timeout_ms
    global BitRate
    global Slave_Slave_Addr
    handle = api.py_aa_open(port)
    if (handle <= 0):
        #    print "Unable to open Aardvark device on port %d" % port
        #    print "Error code = %d" % handle
        print("error code")
        sys.exit()

    # Ensure that the I2C subsystem is enabled
    api.py_aa_configure(handle, AA_CONFIG_SPI_I2C)

    # Enable the I2C bus pullup resistors (2.2k resistors).
    # This command is only effective on v2.0 hardware or greater.
    # The pullup resistors on the v1.02 hardware are enabled by default.
    api.py_aa_i2c_pullup(handle, AA_I2C_PULLUP_BOTH)

    # Power the EEPROM using the Aardvark adapter's power supply.
    # This command is only effective on v2.0 hardware or greater.
    # The power pins on the v1.02 hardware are not enabled by default.
    api.py_aa_target_power(handle, AA_TARGET_POWER_BOTH)

    # Set the bitrate
    bitrate = api.py_aa_i2c_bitrate(handle, BitRate)
    print("Bitrate set to %d kHz" % bitrate)
    log.write("Bitrate set to %d kHz" % bitrate)

    # Set the bus lock timeout
    bus_timeout = api.py_aa_i2c_bus_timeout(handle, BUS_TIMEOUT)

    api.py_aa_i2c_slave_enable(handle, Slave_Slave_Addr, 0, 0)
    print("Slave enabled with address 0x62")


def query_parser_fun(packet):
    if packet != "":
        print("-------------------------------------------------------------------------------------------\n")
        print("Query Device Identifier Packet :")
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        print("\n")
        print("-------------------------------------------------------------------------------------------\n")


def get_firmare_parser_fun(packet):
    if packet != "":
        print("-------------------------------------------------------------------------------------------\n")
        print("Get Firmware parameters Packet :")
        print('[{}]'.format(', '.join(hex(x) for x in packet)))
        print("\n")
        print("-------------------------------------------------------------------------------------------\n")


def get_key_val(num_bytes, bin, offset):
    # print(num_bytes)

    if num_bytes < 5:
        temp = 0
        for i in range(0, num_bytes):
            temp |= bin[offset] << (i * 8)
            offset += 1
        return temp
    else:
        return bin[offset:offset+num_bytes]


def print_dict_in_hex(dict):  # This function added for debug will be useful in future
    for key, value in dict.items():
        print(key, end=" : ")
        if type(value) is int:
            print(hex(value))
        else:
            print('[{}]'.format(', '.join(hex(x) for x in value)))


def print_class_objects():  # This function added for debug will be useful in future
    global ComponentParameterTable
    global q_id
    global fw_pm

    print("\n\n!--!--!--!--!--!--!--!--!--!--!--!--Debug Print--!--!--!--!--!--!--!--!--!--!--!--!--!--!--!--!")
    print("ComponentParameterTable:")
    count = 0
    for obj in ComponentParameterTable:
        print("\nComponentParameterTable{}:---".format(count))
        print_dict_in_hex(obj)
        count += 1

    print("\n\nFirmware Parameter")
    dict = vars(fw_pm)
    print_dict_in_hex(dict)

    # print("\n\nQueryDevice Identifier:")
    # dict = vars(q_id)
    # print_dict_in_hex(dict)
    print("\n\n!--!--!--!--!--!--!--!--!--!--!--!--Debug Print--!--!--!--!--!--!--!--!--!--!--!--!--!--!--!--!")


ComponentParameterTable = []
user_update = []
binary_image = bytearray()
total_number_of_updates = 0


def main():
    print("========================================================================== ")
    print("PLDM HOST Utility Version 12.0 Dated 01/07/2022 ")
    print("========================================================================== ")
    global addr
    global port
    global Master_Slave_Addr
    global Slave_Slave_Addr
    global BitRate
    global Timeout_ms
    global timeout_ms
    global process
    global log
    global status_var
    global get_response_flag
    global fw_get_response_flag
    global process
    global query_packet
    global get_fw_query_packet
    global q_id
    global fw_pm
    global ComponentParameterTable
    global total_number_of_updates
    global user_update
    global handle
    global binary_image
    global PHP_HDR_PKG_BIN
    global transfer_comp_count
    global verify_comp_flag
    global apply_comp_flag
    global total_update_comp

    log = open("pldm_commands.log", "w+")

    q_id = QueryId()
    fw_pm = GetFwPm()

    #h= get_crc(b"C8")
    ini_file = "pldm_cfg.ini"
    if(not(os.path.isfile(ini_file))):
        print("ini file not found, exit")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(ini_file)
    port = config['I2C_Configure']['Port']
    port = int(port, 16)
    addr = config['I2C_Configure']['Master_Slave_Addr']
    addr = int(addr, 16)
    addr = addr
    Master_Slave_Addr = addr * 2
    Slave_Slave_Addr = config['I2C_Configure']['Slave_Slave_Addr']
    Slave_Slave_Addr = int(Slave_Slave_Addr, 16)
    BitRate = config['I2C_Configure']['BitRate']
    BitRate = int(BitRate, 10)
    timeout_ms = config['I2C_Configure']['Timeout_ms']
    timeout_ms = int(timeout_ms, 10)

    if(config['PLDMHEADER']['UsePLDMPacket'].lower() == "true"):
        USE_PLDM_HEADER = True
    else:
        USE_PLDM_HEADER = False
    print(config['PLDMHEADER']['UsePLDMPacket'].lower(), USE_PLDM_HEADER)
    print("Port ", port)
    print("Master_Slave_Addr ", addr)
    print("Slave_Slave_Addr ", Slave_Slave_Addr)
    print("BitRate ", BitRate)
    print("Timeout_ms ", timeout_ms)

    if(USE_PLDM_HEADER == True):
        print(" Parsing from Input binary")
        PHP_main()
        print(len(php.PHP_HDR_PKG_BIN))
    else:
        print(" Using ini file")

    configure_aadvark()

    parser = configparser.ConfigParser()
    parser.read(ini_file)
    section_variable = []

    if(USE_PLDM_HEADER == True):
        print("using bin file")

        query_command(0, "temp", USE_PLDM_HEADER)
        if get_response_flag == 1:
            print("\nQuery device Identifiers Commadn received from  FD to Host \n")
            # query_parser_fun(query_packet)
            dict = vars(q_id)
            count = 0
            offset = 0
            for key, value in dict.items():
                dict[key] = get_key_val(size_mem_Q_id[count], query_packet, offset)
                offset += size_mem_Q_id[count]
                count += 1
            print("===============================================================")
        else:
            print("\nQuery device Identifiers Commadn is not received from  FD to Host \n")
            print("\nDevice is not ready , check the connection and FD is running or not\n")
            print("Sending the Cancel command and just try again for the FD update from UA \n")
            CancelUpdate()

        Get_Firmwareparameters_command(0, "temp", USE_PLDM_HEADER)

        if fw_get_response_flag == 1:
            print("===============================================================")
            print("\nGet Firmware parameters Commadn received from  FD to Host \n")
            # get_firmare_parser_fun(get_fw_query_packet)
            dict = vars(fw_pm)
            count = 0
            offset = 0
            for key, value in dict.items():
                if(size_mem_GetFwPm[count]!=-1):
                    dict[key] = get_key_val(
                        size_mem_GetFwPm[count], get_fw_query_packet, offset)
                    offset += size_mem_GetFwPm[count]
                    count += 1
                else:
                    break
            fw_pm.active_comp_image_set_version_string = get_fw_query_packet[offset:offset + fw_pm.active_comp_image_set_version_string_length]
            offset+=fw_pm.active_comp_image_set_version_string_length
            
            fw_pm.pending_comp_image_set_version_string = get_fw_query_packet[offset:offset + fw_pm.pending_comp_image_set_version_string_length]
            offset+=fw_pm.pending_comp_image_set_version_string_length
            
            
            for i in range(0, fw_pm.component_count):
                count = 0
                fw_pm_comp_table = GetFwPm_comp_pm_table()
                dict = vars(fw_pm_comp_table)
                for key, value in dict.items():
                    if(size_mem_GetFwPm_cpt[count]!=-1):
                        dict[key] = get_key_val(size_mem_GetFwPm_cpt[count], get_fw_query_packet, offset)
                        offset += size_mem_GetFwPm_cpt[count]
                        count += 1
                    else:
                        break
                fw_pm_comp_table.active_comp_version_string = get_fw_query_packet[offset:offset + fw_pm_comp_table.active_comp_version_string_length]
                offset+=fw_pm_comp_table.active_comp_version_string_length
                
                fw_pm_comp_table.pending_comp_version_string = get_fw_query_packet[offset:offset + fw_pm_comp_table.pending_comp_version_string_length]
                offset+=fw_pm_comp_table.pending_comp_version_string_length
                
                ComponentParameterTable.append(dict)

            print_class_objects()
            print("===============================================================")

        else:
            print("\nGet Firmware parameters Commadn is not received from  FD to Host \n")
            print("\nDevice is not ready , check the connection and FD is running or not\n")
            print("Sending the Cancel command and just try again for the FD update from UA \n")
            CancelUpdate()
            sys.exit(0)

        # os.system('cls')

        # Check if the component is available in the header bin file
        iter_count = 0
        for obj in ComponentParameterTable:
            user_update.append(0)
            obj["is_supported"] = 0
            for iter in PHP_COMP_IMG_TABLE:
                if(obj["comp_identifier"] == iter["ComponentIdentifier"]):
                    obj["is_supported"] = 1
                    break
            iter_count += 1

        print(user_update)
        # if the component is available in the header bin file, Ask if the user wats to update it
        i = 0
        for obj in ComponentParameterTable:
            if(obj["is_supported"] == 1):
                answer = input('Would you like to update component id {}...<Y/N>'.format(hex(obj["comp_identifier"]))).lower()
                if answer.startswith('y'):
                    user_update[i] = 1
                    total_number_of_updates += 1

            i += 1
        print(user_update)
        # At this point of execution user_update conatains whether the component needs to be updated
        # If it is 1, it needs to be updated
        # If not, either the component is not supported in the header binary file or the user doesn'tr want to update it
        if total_number_of_updates > 0:
            Request_Update_command_bin(total_number_of_updates)
        i = 0
        for obj in ComponentParameterTable:
            if user_update[i] == 1:
                for iter in PHP_COMP_IMG_TABLE:
                    if(obj["comp_identifier"] == iter["ComponentIdentifier"]):
                        PassComponentTablecommand_bin(iter["ComponentClassification"], iter["ComponentIdentifier"], iter["ComponentComparisonStamp"],
                                                      iter["ComponentVersionStringType"], iter["ComponentVersionStringLength"], iter["ComponentVersionString"])
            i += 1

        i = 0
        for obj in ComponentParameterTable:
            if user_update[i] == 1:
                for iter in PHP_COMP_IMG_TABLE:
                    if(obj["comp_identifier"] == iter["ComponentIdentifier"]):
                        UpdateComponentTableCommand_bin(iter["ComponentClassification"], iter["ComponentIdentifier"], iter["ComponentComparisonStamp"],
                                                        iter["ComponentSize"], iter["ComponentVersionStringType"], iter["ComponentVersionStringLength"], iter["ComponentVersionString"])
                        start_offset = iter["ComponentLocationOffset"]
                        end_offset = iter["ComponentLocationOffset"] + iter["ComponentSize"]
                        # print(hex(start_offset), hex(end_offset))

                        binary_image = php.PHP_HDR_PKG_BIN[start_offset:end_offset]
                        # print(len(binary_image))

                        file_transfer(handle, "temp", timeout_ms, USE_PLDM_HEADER)
                        num_of_cmds = 2
                        while(num_of_cmds and (process != 5)):
                            req_dump_(handle, 30000)
                            num_of_cmds = num_of_cmds - 1
            i += 1
        if(transfer_comp_count == total_update_comp and verify_comp_flag == total_update_comp and apply_comp_flag == total_update_comp and total_update_comp != 0):
            print("RESULT: PLDM Update Success")
            ActivateFirmware()
        else:
            print("RESULT: PLDM Update Failure")
        sys.exit(1)
    else:  # Use ini file
        for section_name in parser.sections():
            section_variable.append(section_name)
        i = 0
        for section_name in parser.sections():
            query_command(parser, section_variable[i], USE_PLDM_HEADER)
            i = i+1
        if get_response_flag == 1:
            print("\nQuery device Identifiers Commadn received from  FD to Host \n")
            # query_parser_fun(query_packet)
            print("===============================================================")

        else:
            print("\nQuery device Identifiers Commadn is not received from  FD to Host \n")
            print("\nDevice is not ready , check the connection and FD is running or not\n")
            print("Sending the Cancel command and just try again for the FD update from UA \n")
            CancelUpdate()
        i = 0
        for section_name in parser.sections():
            # print(section_variable[i])
            Get_Firmwareparameters_command(parser, section_variable[i])
            # if section_name==section_variable[i]:
            #    print("same")
            # for name, value in parser.items(section_variable[i]):
            #    print('Name  %s Value = %s' % (name, value))
            i = i+1
        if fw_get_response_flag == 1:
            print("===============================================================")
            print("\nGet Firmware parameters Commadn received from  FD to Host \n")
            # get_firmare_parser_fun(get_fw_query_packet)
            print("===============================================================")

        else:
            print("\nGet Firmware parameters Commadn is not received from  FD to Host \n")
            print("\nDevice is not ready , check the connection and FD is running or not\n")
            print("Sending the Cancel command and just try again for the FD update from UA \n")
            CancelUpdate()
            sys.exit(0)
        i = 0
        for section_name in parser.sections():
            # print(section_variable[i])
            Requestcommand(parser, section_variable[i])
            # if section_name==section_variable[i]:
            #    print("same")
            # for name, value in parser.items(section_variable[i]):
            #    print('Name  %s Value = %s' % (name, value))
            i = i+1
        i = 0
        for section_name in parser.sections():
            # print(section_variable[i])
            PassComponentTablecommand(parser, section_variable[i])
            # if section_name==section_variable[i]:
            #    print("same")
            # for name, value in parser.items(section_variable[i]):
            #    print('Name  %s Value = %s' % (name, value))
            i = i+1
        i = 0
        for section_name in parser.sections():
            # print(section_variable[i])
            command(parser, section_variable[i])
            # if section_name==section_variable[i]:
            #    print("same")
            # for name, value in parser.items(section_variable[i]):
            #    print('Name  %s Value = %s' % (name, value))
            i = i+1
        if(transfer_comp_count == total_update_comp and verify_comp_flag == total_update_comp and apply_comp_flag == total_update_comp):
            ActivateFirmware()
        else:
            print(transfer_comp_count, verify_comp_flag, apply_comp_flag)
            print("Activate Firmware Not sent")
        obj_now = datetime.now()
        print("After Complete transfer, current time: ", obj_now)

    # # Disable the slave and close the device
    api.py_aa_i2c_slave_disable(handle)

    api.py_aa_close(handle)
    log.close()
    print("========================================================================== ")
    print("===============PLDM Host utility Exit=========================================== ")


if __name__ == "__main__":
    main()
