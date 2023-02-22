FlashDownload
=============
FlashDownload - This Folder Contains MPLABx Prebuild project and Loads the SPI Image in to flash

flash_program_exec.X.production.unified.hex  - Flash Program Executive with Bootrom integrated for FPGA Build 37
                                                  which writes register 0x4000FE40 |= 0x5050
                                                  

flash_program_exec.X.production.hex          - Flash Program Ececutive without bootrom. Used for EVB.
                                                  writes register 0x4000FE40 |= 0x5050