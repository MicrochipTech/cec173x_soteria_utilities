 MCHP - SPI Image generator for GLACIER 
===========================
THIS FOLDER CONTAINS FOLLOWING FILES:
Tools\Glacier_key_hash: 
Glacier_key_hash.exe :Tool used to generate the KHB0/1 binaries

keycfg.txt : Configuration of the Glacier_key_hash.exe tools
			KeyHashBlob.bin of Test KHB0/1 of the generated from the Glacier_key_hash.exe

Tools\Merge_utilty

This tool is to extract and copy the content form one file to another for the
given offset and length

merge.exe : merge.exe to extract the image content from input file for the length
            given and copy to the offset address provided for the output file
		
Usage :Merge.exe read the merge.txt file


 
srec.bat  :   This batch script is used to convert the mplabx IDE generated hex 
				into intel binary format

SREC_CAT tool:

Tool is to convert the MPLABX IDE generated HEX file into Binary file using the below command 

srec_cat.exe <MPLABX IDE HEX> -intel -offset -0xD0000 -O temp.hex -intel
srec_cat.exe temp.hex -intel -O Glacier_GEN3_secureboot_app.bin -binary

Dir Generate_ECDSA_key : Generate the ECDSA key pair using the generate_key.bat and which is used by the 
			EC FW for calculating the signature

Dir FW_Test_keys : Generate the ECDSA key pair using the fw_key_gen.bat and which is used by the 
			AP FW for calculating the signature and calculating the AP public key hash blob 0/1

generate
readme.txt              : This File
 ~~~~~~~~~End of Document~~~~~~~~~