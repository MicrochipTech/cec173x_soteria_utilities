Python 3.9

Install Python 3.8.5 or Later Version

EXE: TOO_i2c_command.exe
Config: inputs/config.ini

Supported Host I2c Command for the TOO operation has below:
1.	Clear RPMC Container Command register and EC_FW-to-BROM SRAM Mailbox (0000b)
2.	Select EC_FW-to-BROM SRAM Mailbox (0001b)
3.	Select RPMC Container Command register (0010b)
4.	Hash of Primary Owner Container (0011b)
5.	Primary Owner Container Status (0100b)
6.	Current Owner Container RPMC value (0101b)
7.	Get Random Value (0110b)
8.	Signed Enable Unrestricted Transfers command (0111b)
9.	Get Primary Owner Container (1000b)
10.	Repair REC Fallback Container (1010b)
11.	Get Primary Revocation Emulation Container (1011b)
12.	Restore Primary Revocation Emulation Container (1100b)
13.	Get Revocation Emulation Container Status (1101b)
14.	Current Revocation Emulation Container RPMC value (1110b)


Supported commands are specified in the config file.

Execution from the command line option:

Command as below:
TOO_i2c_command.exe -c inputs\config.ini
==========================================================================
TOO I2C Command FTDI Utility Version 1.0 Dated 07/08/2022
==========================================================================
**************************************************************************
TOO_i2c_command.exe utility to send and receive commands from the Command prompt
Version 11.0.0 07/08/2022
**************************************************************************


For ex:
Clear RPMC Container Command register and EC_FW-to-BROM SRAM Mailbox
1.	Config.ini 
[Clear_RPMC_Container]
Use_Clear_RPMC_Container_Reg=true
2.	Command: TOO_I2C_command\Ftdi>TOO_i2c_command.exe -i config\config_Clear_RPMC_container.ini

Hash of the Primary container
1.	Config.ini
[Hash_primary_container]
Use_Hash_primary_container=true
2.	TOO_i2c_command.exe -i config\config_Hash_primary_container.ini
3.	It read the from the device and output as SHA38(primary container) in binary file of hash_of_primary_container.bin
==========================================================================
Reading of the hash_of_primary_container.bin
Processing |████████████████████████████████| 48/48
Reading of the hash_of_primary_container.bin completed



Get Random number 
1.	Config.ini
[Get_random]
Use_Get_random=true
2.	TOO_i2c_command.exe -i config\config_Get_random.ini
3.	It read the from the device and output as random number in binary file of get_random_value.bin

	Primary container status
1.	Config.ini
[Primary_container_status]
Use_Primary_container_status=true
2.	TOO_i2c_command.exe -i config\ config_Primary_container_status.ini
3.	It read the from the device and output as  Primary_container_status in binary file

Transfer of Owner A -> Owner B:
Sequence of steps:
1.	Owner B provides the owner container parameter/image KHB and TAGx image
2.	Read the hash of the primary container from the device
TOO_i2c_command.exe -i config\config_Hash_primary_container.ini
It read the from the device and output as SHA38(primary container) in binary file of hash_of_primary_container.bin
3.	Read the Get random number from the device
TOO_i2c_command.exe -i config\config_Get_random.ini
It read the from the device and output as random number in binary file of get_random_value.bin
4.	Generate the SIGNED EOT file
cd RPMC_flash_container
RPMC_flash_container.exe  -i rpmc_cfg_eot.ini -c f
copy /y rpmc\contatenate_enable_unrestricted_container_signature.bin ..\ftdi\. 
cd ..
5.	Send the SIGNED EOT file using the below command:
TOO_i2c_command.exe -i config_Select_EC_FW_To_BROM.ini
6.	Device got restarted and ready fro the transfer to another owner 
7.	Read the hash of the primary container from the device
TOO_i2c_command.exe -i config\config_Hash_primary_container.ini
It read the from the device and output as SHA38(primary container) in binary file of hash_of_primary_container.bin
8.	Generate the Update container file
cd RPMC_flash_container
RPMC_flash_container.exe  -i rpmc_cfg_toc.ini -c 7
copy /y rpmc\contatenate_update_container_subcommand_1_signature.bin ..\ftdi\.
9.	Clear the RPMC container and send the Update container file to the EC_FW which does the transfer of owner from A to B
TOO_i2c_command.exe -i config\config_Clear_RPMC_container.ini
TOO_i2c_command.exe -i config_Select_EC_FW_To_BROM.ini
10.	Check the UART or I2C build number command to check the status of the owner via trace or build number to identify that the new owner has been transferred.








Transfer of Owner A-> Intermediate Entity -> Owner B
Sequence of steps:

1.	Owner B provides the owner container parameter/image KHB and TAGx image
2.	Read the hash of the primary container from the device
TOO_i2c_command.exe -i config\config_Hash_primary_container.ini
It read the from the device and output as SHA38(primary container) in binary file of hash_of_primary_container.bin
3.	Read the Get random number from the device
TOO_i2c_command.exe -i config\config_Get_random.ini
It read the from the device and output as random number in binary file of get_random_value.bin
4.	Generate the file for the command UpdateOTAKey which is required for signing the Update OTAK Key command binary 
RPMC_flash_container.exe  -i rpmc_cfg.ini -c 1f
Send the file to the EC_FW  
TOO_i2c_command.exe -i config\config_Clear_RPMC_container.ini
TOO_i2c_command.exe -i config_Select_EC_FW_To_BROM.ini
5.	Owner A executes Enable Unrestricted Transfers command to add OTAKpub key to Owner Container and enable I2C crisis interface to process ownership commands.
Generate the SIGNED EOT file
cd RPMC_flash_container
RPMC_flash_container.exe  -i rpmc_cfg_eot.ini -c f
copy /y rpmc\contatenate_enable_unrestricted_container_signature.bin ..\ftdi\. 
cd ..
6.	Send the SIGNED EOT file using the below command:
TOO_i2c_command.exe -i config_Select_EC_FW_To_BROM.ini
7.	Device got restarted and ready fro the transfer to another owner and it is in intermediate Entity state
8.	Read the hash of the primary container from the device
TOO_i2c_command.exe -i config\config_Hash_primary_container.ini
It read the from the device and output as SHA38(primary container) in binary file of hash_of_primary_container.bin
9.	Generate the Update container file
cd RPMC_flash_container
RPMC_flash_container.exe  -i rpmc_cfg_toc.ini -c 7
copy /y rpmc\contatenate_update_container_subcommand_1_signature.bin ..\ftdi\.
10.	Clear the RPMC container and send the Update container file to the EC_FW which does the transfer of owner from A to B
TOO_i2c_command.exe -i config\config_Clear_RPMC_container.ini
TOO_i2c_command.exe -i config_Select_EC_FW_To_BROM.ini
11.	Check the UART or I2C build number command to check the status of the owner via trace or build number to identify that the new owner has been transferred

		