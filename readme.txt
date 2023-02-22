 utilities Folder - CEC173x Secureboot app  Projects
===============================================================================

readme.txt                  	: This File
cec173x_KHB_generation		: cec173x_KHB_generation source code and exe
CEC173x_otp_generator	  	: CEC173x_otp_generator source and exe 
Merge_Utility			: Merge Utility to merge the binaries from the source to Destination with offset/Length
Extractor			: Extractor tool to extract the RAW image from source to Destination file
i2c_crisi_utlity 		: I2c crisis Utility using FT4222 device to connect to CEC173x parts for i2c commands 
CEC173x_Secureboot_SPI_image_gen3: Soteria Gen3 SPI image generator source.
SB_Custom_file_gen3             : Custom File gen source and exe to generate the 
                                   custom_file.txt to map the efuse region 576-863
TestScripts  			: Test script ini for MPLABX Debugging
mplabd Flash downloader		: Flash the SPI image into internal/External Flash (AP0/AP1)
mplabx_OTP_programming 		: MPLABX project based OTP programmer to program the otp files 
                                  into CEC173xBlank parts for provisioning
OTP_reader 			: Using MDB script to read back the otp values
PLDM				: Host utility to transfer the Image to EC_FW
PLDM_package 			: PLDM package creatiom  tool 
ROME_ecdnII_key_enc		: Tool to generate the otp offest 0-47 Encryption keys 
				 sha384 of the ECDH2 pub key for the otp offest 128-175
				 ECDH2 Public key in binaries for the SPI header
container_merge			: To merge the RPMC create container request binary in hex/bin using the RPMC tool
				and merge to the Sotergia GEN3 hex file
				once merged and give to SG3 SPI image gen 
Create Container GUI 		:GUI to merge the RPMC create container request binary in hex/bin using the RPMC tool
				and merge to the Sotergia GEN3 hex file
				once merged and give to SG3 SPI image gen 
TOO GUI 			:GUI  to do the EC_FW communication via i2c which do the transfer of ownership image
TOO_I2C_command_Ftdi		: Commnd line tool to 	EC_FW communication via i2c which do the transfer of ownership image			  
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                              E.N.D  O.F  D.O.C.U.M.E.N.T
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤