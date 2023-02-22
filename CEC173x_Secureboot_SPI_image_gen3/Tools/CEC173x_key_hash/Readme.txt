     GLACIER_KEY_HASH Version 7.0 2020-10-30
 ==============================================
Hash Utility - 
    > glacier_key_hash.exe 
            -i <cfg_file_name> 
                -o <output_spi_file_name> 
                    -m <merge_file>
                        -d <Debug help -d t>

Running "glacier_key_hash.exe" from command prompt will take 
    "keycfg.txt" as a default configuration file and 
    generators the output "spi_image.bin"

Other options:
==============    
    -i cfg_file_name 
        Specifies the text config file for the SPI chip & images.
        Defaults to keycfg.txt

    -o output_spi_file_name
        Specifies the SPI binary output file name.
        Defaults to spi_keyhashspiimage.bin

    -m merge_file
        Read merge file as an existing SPI binary image and create FW images 
        inside it.
        No default value
    
    -d Debug help 
        t or T will display the debug details for each key
        
Configuration Details:
======================        
Glacier Public key hash configuration file 

Output files:
============
    1. KeyHashBlob.bin      - Key Hash Blob binary image 
                            - File size various by customers
                               0672 Bytes for Owner  01  
                               0864 Bytes for Owners 01 & 02 
                               1056 Bytes for Owners 01 & 02 & 03 
    2. KeyHashSpiImage.bin  - Merged above file with the input file provided
                              with -m option
    3. Owner01PubKey.bin    - Owner01s Public key in binary format
    4. Owner02PubKey.bin    - Owner02s Public key in binary format(optional)
    5. Owner03PubKey.bin    - Owner03s Public key in binary format(optional)


SPI Configuration:
-----------------
    [SPI]
    ;SPI Flash Image SIze in Megabits 128 =>  16MB; 256 = 32 MB
    SPISizeMegabits = 128

    ;Key Bank specific location for the final SPI image
    KeyHashLoc =<hex value >

Owner Key Configuration:
------------------------
    ; If authentication is enabled in the device Owner 01 key is required
    Owner01PvtKeyFile = <A ECC384 Private Key PEM file for Owner 1> 
    
    ; Owner2 and Owner3 are optional keys if there are multiple owners present
    Owner02PvtKeyFile = <A ECC384 Private Key PEM file for Owner 2> 
    Owner03PvtKeyFile = <A ECC384 Private Key PEM file for Owner 3> 
    
Key Configuration:
--------------------
    ; Provide the Public key offset and the Public key 
    ; The following keys formats will be accepted
    ; A Private key is ECDSAPvtKeyFile = < pem private key >
    ; or a Pubkeys either in PEM or CRT fomrat ECDSAPubKeyFile = < pem public key >
    ; Total 8 Keys will be accepted [KEY "7"]
    [KEY "x"] 
    ; x can be value from 0 till 7
    
    ; Provide the public key PEM or CRT format
    ECDSAPubKeyFile = <An ECC384 Public Key>
    
    [UPDTKEY]
    ; Current Owners update key for feature updates.
    UpdatePubKeyFile = <An ECC384 Public Key>    

    [ECFWENTRY]
    ;Entry the binary file for the ECFW_Entry data - total 96 bytes
    EcfwEntryData = <Filename.bin>


¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
                                E.N.D  O.F  D.O.C.U.M.E.N.T
¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤