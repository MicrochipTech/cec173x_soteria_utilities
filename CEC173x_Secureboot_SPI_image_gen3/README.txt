
 MCHP - SPI Image generator for GLACIER
===========================
THIS FOLDER CONTAINS FOLLOWING FILES:

Secureboot SPI image gen3  readme.txt
----------------------------------------------------------
Dir keys

ECDSA_keys           : ECDSA 384 test keys of private/public for EC_FW signature calculation


fw_test_keys         :  ECDSA384 test keys of private/public keys used for the AP_FW signature calculation

input_test_keys      : ECDSA test keys of private /public keys of plain keys for AP public
			key hash blob 0/1 binary

AP_FW_Images :     AP0/1.bin , GAP0/1.bin ,blink_led.bin : Test Binaries 

Dir ECDH_bin
ECDH_bin :  ecdh2pubkey.bin : Test binaries of the ECDSA public key of 384 curve

	ecdh2pubkey.bin             : ECDSA 384 Public bin of the test keys 
				This is ECDH2 public key and specify this file in
				the spi configuration under the below section 
	[DEVICE]
	DevECDH2Pubkey = Keys/ECDH_bin/ecdh2pubkey.bin

Tools\Glacier_key_hash: 
Glacier_key_hash.exe :Tool used to generate the KHB0/1 binaries

keycfg.txt : Configuration of the Glacier_key_hash.exe tools
			KeyHashBlob.bin of Test KHB0/1 of the generated from the Glacier_key_hash.exe

Tools\Merge_utility: 
Merge.exe  : Merge tool used to merge the source into destination file with the length
			merge.txt  of  configuration file used for the merge.exe tool

secureboot_spi_image_gen_3.exe     : SPI Image Generator 64 bit Executable file.

Relase.txt              : Command usage and release notes

spi_cfg_port_0_comp_0.txt    : A sample config file  for the port 0/comp0

Dir FW_Test_keys :  fw_key_gen.bat  Batch script to generate the ECDSA384 key pair
Dir Generate_ECDSA_key : Generate the ECDSA key pair using the generate_key.bat


Tool generate the as follows :

spi_image.bin :  EC_FW related image , can be used to update in the internal Flash 

External Flash : 
spi_image_port_<number>_comp_<number>.bin : based on the port/comp binaries

ec_fw_entry_hash_blob.bin : AP public key hash blob 0/1 which is the hash of hash of AP public key


auto_spi_img_gen.bat : batch script to genertae the spi image using the HEX/SPI configuration file

Dir Input_Hex:  Glacier_GEN3_secureboot_app.hex : Test Hex file 
auto_spi_img_gen.bat   < HEX file >    <spi_cfg.ini configuration> 

steps_to_generate_spi_image.txt : It involve the steps involved in generating the spi image
readme.txt              : This File

release.txt : spi configuration for EC_FW



 ~~~~~~~~~End of Document~~~~~~~~~
