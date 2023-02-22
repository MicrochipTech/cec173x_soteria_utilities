PLDM Header generation tool:

-----> Generates pldm_header_package.bin

Input:  pldm_package_cfg.ini
Output: pldm_header_package.bin
===================================================================================================================


Refer the PLDM Firmware Update spec (DSP267_1.1.0) and provide the value for the following sections in ini:
    Package Header
    Firmware Identification
    Downstream identification - Not supported (Do not modify DownstreamDeviceIDENT section in ini)
    Component information area
		ini can be updated to support multiple components
		Change respective fields under each compoenents, make sure to update ComponentImageCount in case of addition / deletion
		Also change, ComponentLocationOffset, ComponentImage name accordingly


Command line execution under the current directory:   
 open the command prompt
 PLDM_package_creation_Utility>pldm_package_gen.exe


readme.txt : This file


===================================================================================================================