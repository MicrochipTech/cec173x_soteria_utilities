 Image extractor Readme.txt
===============================================================================

This tool is used to copy the content from application image binary file and generate
header, key hash blob and firmware image binary file.

Usage : extract.ini file

    <From File>  - Input file - application binary image 
    <From offset>- Base offset in hex
    <To file>    - Output file - file name
    <Length>     - Total length of bytes in hex to extract

For example : extract.ini 
    [EXTRACT "0"]
    FROM_FILE = application_image.bin
    FROM_OFFSET =2000
    TO_FILE = header.bin
    LENGTH =380

Steps to run:
1) copy the application_image.bin in to the inputs DIR
2) Run this Utility in command prompt "extractor.exe" 
   provide valid information in the extract.ini file for different section to extract the 
   image from the spi image 
3) It generates the header, key hash blob and firmware image binary fileS
  
readme.txt                  : This File

¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                              E.N.D  O.F  D.O.C.U.M.E.N.T
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤