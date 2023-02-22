                custom_file_gen.exe Version 4.00 Usage for the SOteria-G3 parts
                ----------------------------------------       
 SB_Custom_file_gen_2 Folder - Readme.txt
===============================================================================
THE FOLDER CONTENTS :
Dir autobuild: 
    p4label2.txt : Information about each build

Dir SB_Custom_file_generator    : This folder has required files
                                 to generate the custom efuse region of (576-863)
                                 of the OTP region 
Custom_file_generator.exe : This tool to generate the secureboot efuse region (576-863)
  AP_BA_PTR0
  AP_BA_PTR1
  AP_CFG Authentication key mask byte 0-3
  Ap public key count
  AP Optional Feature conf byte 1/2/3/4
  Feature option source 
  Feature optonal 1/2/3/4/5/6
  AP_BA_PTR_CERT Base pointer byte 0-3
  Hash table address byte 0-3

                            Click the "GENERATE_SB_EFUSE_DATA"  
help.txt                  : It has the information of how to run this tool
mchp.ico                  : microchip icon to be display in the GUI                         

Dir mchp_signed : 
    Custom_file_generator.exe: Signed Exe with the MCHP Public CA



Note : Refer the Datasheet for the SOTERIA G2 features &  provided
        in this tool to generate the efuse custom_file.txt in the region
        672-959

readme.txt                  : This File

¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                              E.N.D  O.F  D.O.C.U.M.E.N.T
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
  
