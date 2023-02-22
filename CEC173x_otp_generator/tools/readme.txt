Tools Dir Contains the following files
--------------------------------------
1. CEC173x_sha384_ecdhkey.exe  -> Tool to extract Key content , generate the EC privayte keys 0-47 , ECDH2 public key 
2. CEC173xROMP384Prod_crt.pem  ->  ROM public key 
3. openssl.exe                   -> Tool to generate Keys
4. srec_cat.exe                 -> Tool for bin to hex conversion
5.sqtp_to_otp_ini.exe        -> This tool is to convert the SQTP file into the otpconfig.ini
This tool is to DUMP the OTP offset and OTP data in the form of otpconfig.ini
Generated otpconfig.ini can be given to the efuse tool to generate the SQTP/OTPhex/OTP bin for
verification

Windows executable :
sqtp_to_efuse_ini.exe : This tool is to convert the SQTP file into the efuseconfig.ini


Generated SQTP into the efuseconfig.ini

Command : sqtp_to_efuse_ini.exe < Example SQTP> <output in INI>

Ex : sqtp_to_efuse_ini.exe efuse_sqpt.txt efuseconfig.ini
        
------------------------------<E.N.D..O.F..F.I.E.L>-----------------------------    
        