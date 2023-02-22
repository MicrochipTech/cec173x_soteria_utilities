            MCHP - Secure Boot CEC1702 Update project 
===============================================================================
This tool is to extract and copy the content form one file to another for the
given offset and length

merge.exe : merge.exe to extract the image content from input file for the length
            given and copy to the offset address provided for the output file
		
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
FROM_FILE = spi_image_port_0_comp_0.bin
FROM_OFFSET =80000
TO_FILE = 908.bin
TO_OFFSET =80000
LENGTH =70000
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                              E.N.D  O.F  D.O.C.U.M.E.N.T
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤