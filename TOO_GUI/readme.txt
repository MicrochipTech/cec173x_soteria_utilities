TOO UI tool to do the transfer of ownership image

Transfer_Ownership_UI.exe : EXE to do the transfer of ownership image

Dir RPMC_flash_container : It contains the exe/configuration file to generate the RPMC i2c command binaries to do the transfer 

Dir ftdi : It cContains the FTDI related exe/configuration to help on EC_FW and host communication to do the transfer of ownership

Transfer of Owner A -> Owner B
1.	Double-click the exe and it will show the below fields
2.	Select the transfer to new owner, Specify the fields in the Updatecontainer request command
3.	Click here to generate the files and execute the i2c command to communicate to the EC_FW
4.	Owner B provides the owner container parameter/image KHB and TAGx image 
Select the owner x and it will generate /read from the device and stored in binary format for the below command 
Get hash of the primary container
Get Primary container status
Primary container 
Get random number
Get RPMC count value  
5.	Select the Enable Unrestricted transfer command
6.	Fill the specified fields for the Enable unrestricted transfer command
Click here to generate the file
Click Here to Trigger the Command and send it to EC_FW
Once the EC_FW has received the EOT file and device will get restarted , it comes to post auth state , it is ready for the transfer
7.	Select the UpdateContainerRequest transfer
Fill the specified fields/Generate the files/Trigger the Command will be send to EC_FW
8.	Check the UART or I2C build number command to check the status of the owner via trace or build number to identify that the new owner has been transferred.


Transfer of Owner A -> Intermediate Entity -> Owner B
1.	Double-click the exe and it will show the below fields
2.	Select the transfer to new owner, Specify the fields in the Updatecontainer request command
3.	Click here to generate the files and execute the i2c command to communicate to the EC_FW
4.	Owner B provides the owner container parameter/image KHB and TAGx image 
Select the owner x and it will generate /read from the device and stored in binary format for the below command 
Get hash of the primary container
Get Primary container status
Primary container 
Get random number
             Get RPMC count value  
5.	Generate the file for the command UpdateOTAKey which is required for signing the Update OTAK Key command binary 
Click Here to Generate the File
Click Here to Trigger the Command
6.	EC_FW will be restarted /went to post auth state/it will be in intermediate state

7.	Select the Enable Unrestricted transfer command
 
8.	Fill the specified fields for the Enable unrestricted transfer command
Click here to generate the file
Click Here to Trigger the Command and send it to EC_FW
Once the EC_FW has received the EOT file and device will get restarted , it comes to post auth state , it is ready for the transfer
 
9.	Select the UpdateContainerRequest transfer
Fill the specified fields/Generate the files/Trigger the Command will be send to EC_FW
 
10.	Check the UART or I2C build number command to check the status of the owner via trace or build number to identify that the new owner has been transferred.
