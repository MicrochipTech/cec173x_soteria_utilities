 spi_image_extractor_gen2 Folder - Readme.txt
===============================================================================

This tool is to extract and copy the content form one file to another for the
given offset and length

extractor.exe : extractor.exe to extract the image content from input file for the length
            given and copy to the offset address provided for the output file

Usage :extractor.exe read the extract.ini file
Usage shoule be like in the text file :
Section MERGE 0 for single merge of file
    <From File>  - Input file to get the content
    <From offset>- Base offset in hex to get the content
    <To file>    - Input file to copy the content , specify the name of the file to be copied
    <Length>     - Total length of bytes in hex to extract

For ex : In the extract.ini 
[EXTRACT "0"]
FROM_FILE = spi_image_port_0_comp_0.bin
FROM_OFFSET =80000
TO_FILE = extract.bin
LENGTH =70000

THE FOLDER CONTENTS :
Folder 'spi_image_extractor_gen2'  : This folder has the extractor.exe to extract the spi_image_port_0_comp_0.bin which is generated from the secure_boot_spi_gen_2 generator tool	and generate the extractor image 

1) copy the spi_image_port_0_comp_0.bin from the secure_boot_spi_gen_2.exe  to this DIR
2) Run this Utility as in command prompt as 
   simply run as  extractor.exe 
   provide valid information in the extract.ini file for different section to extract the 
   image from the spi image 
3) It generate the varoius image from the spi_image_port_0_comp_0.bin and 
   specify the image name to be extracted from the SPI image
  
   
  
readme.txt                  : This File

¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                              E.N.D  O.F  D.O.C.U.M.E.N.T
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤