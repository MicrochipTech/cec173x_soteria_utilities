
Steps:
1. Download the python 3 version 
  Python 3.8.9 (tags/v3.8.9:a743f81, Apr  6 2021, 14:02:34) [MSC v.1928 64 bit (AMD64)] on win32
    Ensure that the aardvark_py package and python 3 library in your OS
2. pip install aardvark_py
   pip install crc8
3. Use the latest PLDM package gen exe tool in //depot_pcs/FWEng/solutions/Glacier_GEN3/tools/PLDM_DIR/PLDM_package_creation_Utility/ , generate pldm_header_package.bin
4. Place pldm_header_package.bin in current directory
5. pldm_cfg.ini contains two sections
	1) I2C_Configure:
			It is used to configure Aardvark
			Default values are configured
			If needed, update respective fields say, Master/Slave Address
	2) PLDMHEADER
			This is added for internal-debug purposes
			UsePLDMPacket value should be true
6. Connection Diagram:
     Refer connection_pldm.png
7. Run SG3 code with Trace Level set to 0 or 1 (No or Minimal Trace)
8. Run the script using command
   Command usage :
    python pldm_host.py

Expected Output:
    Pass case: RESULT: PLDM Update Success 
	Fail case: RESULT: PLDM Update Failure

Note:
UA handles request firmware data of multiples of 256bytes with Maximum limit of 1024bytes and, 
UA responds in multiple MCTP packets (max 59bytes) with EOM bit set for last packet

The above transferSize can be specified in pldm_host.py script (MaximumTransferSize)
By default it is set to 0x400 (1024)

Time taken for transferring 224K of EC_FW image is 2minutes and 30secs (MaximumTransferSize at 1024 bytes)