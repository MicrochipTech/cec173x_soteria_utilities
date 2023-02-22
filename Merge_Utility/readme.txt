            MCHP - Secure Boot CEC1702 Update project 
===============================================================================
This tool is to extract and copy the content form one file to another for the
given offset and length


merge.exe : merge.exe to extract the image content from input file for the length
            given and copy to the offset address provided for the output file

NOTE :  CHECK that the source binary should not override the Destination file with 
         the offset and data 
        Please provide the source file with the offset/Data to be copied into the Destination file
        From the DEV_IK_GEN tool , Generate the two files as  OTP DEVIK  signature and PUF DEVIK signature into 
        Binaries Directory specify the name of the binaries into efuseconfig.ini configuration file
        OTPDEVIKsign.bin and PUFDEVIKsign.bin into the efuse region 
	OTP DEVIK cert and PUF DEVIK cert of Binary file into the internal spi image using the merge tool
       For ex: OTP_DEVIK_SIGNED.bin and PUF_DEVIK_SIGNED.bin merge into the internal SPI		
Usage :Merge.exe read the merge.txt file
Usage shoule be like in the text file :
Section MERGE 0 for single merge of file
    <From File>  - Input file to get the content
    <From offset>- Base offset in hex to get the content
    <To file>    - Input file to copy the content
    <To offset>  - Base offset in hex to copy the content
    <Length>     - Total length of bytes in hex to extract

For ex :  In the merge.txt 
[MERGE "0"]
FROM_FILE = cert.bin
FROM_OFFSET =0
TO_FILE = spi_image.bin
TO_OFFSET =10000
LENGTH =290
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                              E.N.D  O.F  D.O.C.U.M.E.N.T
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤