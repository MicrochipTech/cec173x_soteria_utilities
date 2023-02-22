
 SREC_CAT Folder - Readme.txt
===============================================================================
THE FOLDER CONTENTS :
Dir SREC_CAT	: This folder has srec_cat batch script and exe 
 
srec.bat  :   This batch script is used to convert the mplabx IDE generated hex 
				into intel binary format

SREC_CAT tool:

Tool is to convert the MPLABX IDE generated HEX file into Binary file using the below command 

srec_cat.exe <MPLABX IDE HEX> -intel -offset -0xD0000 -O temp.hex -intel
srec_cat.exe temp.hex -intel -O CEC173x_GEN3_secureboot_app.bin -binary
readme.txt                  : This File

¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                              E.N.D  O.F  D.O.C.U.M.E.N.T
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤