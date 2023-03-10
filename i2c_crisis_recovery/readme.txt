i2c Utility written in Python for testing the I2C communication for sending and receiving data

Content in this folder //i2c_crisis_recovery
    1. i2c_host.exe            -->  Will run in Windows python 3.8.5 installed
    2. script.txt              -->  script file provided with the exe for testing purpose. 
	                                Supports FW Image Update without authentication
    3. script_fa_mode.txt      -->  script file provided with the exe for testing purpose. 
	                                Supports FA Mode
    4. script_qa_mode.txt      -->  script file provided with the exe for testing purpose. 
	                                Supports QA Mode 
    5. script_with_auth.txt    -->  script file provided with the exe for testing purpose. 
	                                Supports FW Image Update with authentication	
    6. script_user_mode.txt    -->  script file provided with the exe for testing purpose. 
	                                Used to Update FW Image with authentication
    7. script_enable_debug.txt --> 	script file to provided with exe. Supports Enable Debug 							  
    8. readme.txt              -->  This file
    9. src                     -->  Contains Source files with extension .py
	10. inputs                 -->  This folder will contain:
						            image files or Key files - Required for command execution
							        config.ini - Host configuration settings
    11  outputs                -->  This folder will contain the files generated by utility 
	                                while processing commands. e.g log files
	12  docs                   -->  User Manual	
	13  build.bat              -->  Will Create i2c_host.exe and runs development tests
	
**************************************************************************
i2c_host.exe utility to send and receive commands from the Command prompt
                        Version 8.0.0
**************************************************************************

Usage : i2c_host.exe -c <ConfigFile> -f <ScriptFile>  -test -help

		 -c <ConfigFIle>   -  Will get the Host Configuration Settings as 
							  Protocol, speed and spi image settings
		 -f <ScriptFile>   -  will get the input from the file to send and receive data
	 	 -test             -  Used to run unit tests. For development purpose only.
		 -help             -  Display the usage summary
		 
	1. i2c_host.exe -c <ConfigFile> -f <ScriptFile>
	     The Utility will run commands from ScriptFile.
	   E.g:  i2c_host.exe -c inputs/config.ini -f script.txt
		
	2  i2c_host.exe -c <ConfigFile>
		 The utility will enter into shell prompt.
		 The user can input commands manually.
	   E.g: i2c_host.exe  -c inputs/config.ini
		 
	3	i2c_host.exe -test
	     The utility will run unit test for crisis recovery command/response bytes sequence.
		 Used for development testing.
		E.g: i2c_host.exe -test
		
	4   i2c_host.exe -help
	      Displays usage summary.
		 
	The device will be auto detected at start-up, if FT4222H is plugged-in 

		