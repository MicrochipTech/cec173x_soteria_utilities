
 keys Folder - Readme.txt
===============================================================================
THE FOLDER CONTENTS :
Dir Keys	: This folder has keys files used for calculating AP public key 
			 hash and EC fw signature calculation
 
ECDSA_keys           : ECDSA 384 test keys of private/public used for the 
						key hash blob generation and calcualting 
						signature for the EC_FW image 

fw_test_keys         :  ECDSA384 test keys of private/public keys for signing 
						the AP FW images 

input_test_keys      : ECDSA test keys of private /public keys of plain keys 

Dir ECDH_bin
	ecdh2pubkey.bin             : ECDSA 384 Public bin of the test keys 
				This is ECDH2 public key and specify this file in
				the spi configuration under the below section 
	[DEVICE]
	DevECDH2Pubkey = Keys/ECDH_bin/ecdh2pubkey.bin

readme.txt                  : This File

¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                              E.N.D  O.F  D.O.C.U.M.E.N.T
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤