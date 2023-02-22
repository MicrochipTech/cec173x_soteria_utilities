import os
import platform
os_value =0
if platform.system() =='Windows':
    print("Windows")
    os_value =1
else:
    print("Linux OS")
    os_value=0
if os_value ==1:
    from ttk import Frame, Button, Label, Style, Combobox
    from functools import partial
    from ttk import Entry
    from tkinter import *
    from tkinter import ttk
    import tkinter as tk
    from tkinter import Tk, BOTH, W, N, E, S
    from tkinter.filedialog import askopenfilename
    from tkinter.filedialog import askdirectory
    from tkinter import messagebox
import argparse
import xlrd
import random
import sys
import os
import struct
import binascii
import configparser
import time
import datetime
import cryptography
import pytz
import pem
import xlrd
import xlwt
import sys
import numpy as np
from optparse import OptionParser
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec ,rsa
from cryptography import x509
from functools import partial
crypto_be = cryptography.hazmat.backends.default_backend()
max_efuse_bytes = 1024
# try:
#     # Python2
#     import Tkinter as tk
# except ImportError:
#     # Python3
#    import tkinter as tk
dummy_buffer = []
efuse_data_table = []
custom_data = []
msgidx = 0
headerflag = 0
warningMSG = 0
sqtpflag = 0
MultipleDev = 0
tool_config_file = 0
otp_config_file =0
otp_config = []
tool_config = []
ref_active = 0
help_active = 0
pathfilename = []
cust_content = []
custdatexd = 0
jtag_disbale_flag = 0
rom_aes_flag = 0
rom_ecdh_flag = 0
ecdhkeyenc_en_flag = 0
display_done = 1
MaskVal = ""
PatternVal = ""
TypeVal = ""
error_msg = 0
exit_code = 0
DSW_flag = 0
MOB_flag = 0
COMP_flag =0
write_flag =0
dswgpiosel = 0
primgpiosel_0 =0
WDTDelayg = 0
KeyRFlagsCrnt = 0

tool_config_1 = []

write_lock_flag_15 = 0
write_lock_flag_16 = 0
write_lock_flag_17 = 0
write_lock_flag_18 = 0
write_lock_flag_19 = 0
write_lock_flag_20 = 0
write_lock_flag_21 = 0
write_lock_flag_22 = 0
write_lock_flag_23 = 0
write_lock_flag_24 = 0
write_lock_flag_25 = 0
write_lock_flag_26 = 0
write_lock_flag_27 = 0
write_lock_flag_28 = 0
write_lock_flag_29 = 0
write_lock_flag_30 = 0

otp_lock_15 = 0
otp_lock_16 = 0
otp_lock_17 = 0
otp_lock_18 = 0
otp_lock_19 = 0
otp_lock_20 = 0
otp_lock_21 = 0
otp_lock_22 = 0
otp_lock_23 = 0
otp_lock_24 = 0
otp_lock_25 = 0 
otp_lock_26 = 0
otp_lock_27 = 0
otp_lock_28 = 0
otp_lock_29 = 0
otp_lock_30 = 0
otp_write_lock_en = 0

setting_win_flag = 0
general_win_flag_active = 0
mobile_win_flag_active = 0
desktop_win_flag_active =0
mobile_com_win_flag_active = 0
gen_com_win_flag_active =0
first_win_flag = 0
cust_enter_var = 0
browse_custom_file_val = 0
AEMvar_flag = 0
browsefldr_flag =0
settings_windox_browse_flag =0

error_windox3_flag =0

cust_idx_enter_flag =0
cust_data_enter_flag = 0
generate_efuse_data = 0
warning_main_wind_flag = 0
key_count =0
ap_key_window_active =0

browse_flag =0
ENCT_ENBALE_BIT      =  (1<<0)
RAES_ENBALE_BIT      =  (1<<1)
ECDH_ENBALE_BIT      =  (1<<2)

mfg_test = False
prod = False
dev = False

ToolVersion="8.0"
message = ["CEC173x OTP Generator Tool Ver: 8.00"#0
            ,"Set Environment Variables"             #1
            ,"Settings"                              #2
            ,"Parsing error - input files missing"   #3   
            ,"Please enter Filename"                 #4
            ,"Choose OpenSSL path Missing"           #6
            ,"Error in Key Generation"               #7
            ,"Custom Data space reached limit 991"  #8
            ,"Custom Data space reached limit 991"  #9
            ,"Overwriting Custom Data with ECDH Pub" #10
            ,"SQTP Header Configuration"#11
            ,"ECDSA(P-384) Key count is zero " ]           #12        

class VerticalScrolledFrame:
    """
    A vertically scrolled Frame that can be treated like any other Frame
    ie it needs a master and layout and it can be a master.
    :width:, :height:, :bg: are passed to the underlying Canvas
    :bg: and all other keyword arguments are passed to the inner Frame
    note that a widget layed out in this frame will have a self.master 3 layers deep,
    (outer Frame, Canvas, inner Frame) so 
    if you subclass this there is no built in way for the children to access it.
    You need to provide the controller separately.
    """
    def __init__(self, master, **kwargs):
        width = kwargs.pop('width', None)
        height = kwargs.pop('height', None)
        bg = kwargs.pop('bg', kwargs.pop('background', None))
        self.outer = tk.Frame(master, **kwargs)

        self.vsb = tk.Scrollbar(self.outer, orient=tk.VERTICAL)
        self.vsb.pack(fill=tk.Y, side=tk.RIGHT)
        self.canvas = tk.Canvas(self.outer, highlightthickness=0, width=600, height=500, bg=bg)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.canvas['yscrollcommand'] = self.vsb.set
        # mouse scroll does not seem to work with just "bind"; You have
        # to use "bind_all". Therefore to use multiple windows you have
        # to bind_all in the current widget
        self.canvas.bind("<Enter>", self._bind_mouse)
        self.canvas.bind("<Leave>", self._unbind_mouse)
        self.vsb['command'] = self.canvas.yview

        self.inner = tk.Frame(self.canvas, bg=bg)
        # pack the inner Frame into the Canvas with the topleft corner 4 pixels offset
        self.canvas.create_window(4, 4, window=self.inner, anchor='nw')
        self.inner.bind("<Configure>", self._on_frame_configure)

        self.outer_attr = set(dir(tk.Widget))

    def __getattr__(self, item):
        if item in self.outer_attr:
            # geometry attributes etc (eg pack, destroy, tkraise) are passed on to self.outer
            return getattr(self.outer, item)
        else:
            # all other attributes (_w, children, etc) are passed to self.inner
            return getattr(self.inner, item)

    def _on_frame_configure(self, event=None):
        x1, y1, x2, y2 = self.canvas.bbox("all")
        height = self.canvas.winfo_height()
        self.canvas.config(scrollregion = (0,0, x2, max(y2, height)))

    def _bind_mouse(self, event=None):
        self.canvas.bind_all("<4>", self._on_mousewheel)
        self.canvas.bind_all("<5>", self._on_mousewheel)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_mouse(self, event=None):
        self.canvas.unbind_all("<4>")
        self.canvas.unbind_all("<5>")
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event):
        """Linux uses event.num; Windows / Mac uses event.delta"""
        if event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-1, "units" )
        elif event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(1, "units" )
if os_value ==1:
        class Root(Frame):
             def __init__(self, master):
                global DSW_flag
                global MOB_flag
                global COMP_flag
                global general_win_flag_active
                global mobile_win_flag_active
                global first_win_flag
                global generate_efuse_data
                global warning_main_wind_flag
               
                self.master = master
                self.frame = Frame(self.master)
                (FrameSizeX, FrameSizeY, FramePosX, FramePosY) = get_screen_resolution(self.master, -400,-100)
                #new.geometry("%dx%d+%d+%d" % (size + (x, y)))
                geom1 ="400x100+"+FramePosX+"+"+FramePosY
                self.master.geometry(geom1)
                self.master.title("Glacier Efuse Generator Tool Ver: 3.09")

                self.frame.pack()
                if os.path.exists("mchp.ico"):
                  self.master.iconbitmap('mchp.ico') 
                self.device_name_list = StringVar()
                self.label = Label(self.frame, text ="Select the Device Package available:")
                self.label.grid(column=1 ,row=0, sticky=W, padx=0, pady=1)
                
                self.combo = Combobox(self.frame, state="readonly",width =25,textvariable =self.device_name_list)
                self.combo['values'] = ("Soteria-G3")
                self.combo.grid(column=1 ,row=1, sticky=W, padx=0, pady=1)
                self.combo.set("Soteria-G3")


                self.button_1 = Button(self.frame,text ="OK",width = 6,command = self.new_window)
                self.button_1.grid(column=1 ,row=2, sticky=W, padx=0, pady=1)

                self.button_2 = Button(self.frame,text ="Refresh",width = 6,command = self.enable_button)
                self.button_2.grid(column=2 ,row=2, sticky=W, padx=0, pady=1)
                self.button_2.config(state='disabled')
                first_win_flag = 1
                generate_efuse_data = 0
                warning_main_wind_flag =0

             def enable_button(self):
                global general_win_flag_active
                global mobile_win_flag_active
                global desktop_win_flag_active
                global mobile_com_win_flag_active
                global gen_com_win_flag_active
                global setting_win_flag
                global DSW_flag
                global MOB_flag
                global COMP_flag
                global generate_efuse_data
                global warning_main_wind_flag
                

                if 1 == general_win_flag_active or 1 ==mobile_win_flag_active or 1 == desktop_win_flag_active or 1 == mobile_com_win_flag_active or 1==gen_com_win_flag_active :
                        self.combo.config(state='normal')
                        self.combo.config(state="readonly")
                        self.button_1.config(state='normal')
                        general_win_flag_active = 0
                        mobile_win_flag_active = 0
                        desktop_win_flag_active =0
                        mobile_com_win_flag_active = 0
                        gen_com_win_flag_active =0
                        setting_win_flag =0
                        DSW_flag = False
                        MOB_flag = False
                        COMP_flag = False
                        generate_efuse_data =0
                        warning_main_wind_flag =0
                        
                        
                
             def new_window(self):
                global soteria_flag
                global soteria_cus_flag
                global write_flag
                global DSW_flag
                global MOB_flag
                global COMP_flag
                global general_win_flag_active
                global mobile_win_flag_active
                global setting_win_flag
                if "General" == self.combo.get():
                    MOB_flag = False
                    DSW_flag = False
                    COMP_flag = False
                    soteria_flag = False
                    soteria_cus_flag = True
                    write_flag = False
                    setting_win_flag =0
                    self.combo.config(state='disabled')
                    self.button_1.config(state='disabled')
                    self.newWindow = tk.Toplevel(self.master)
                    self.app = Key_gen(self.newWindow)
                    self.button_2.config(state='normal')
                elif "Soteria-G3"==self.combo.get():
                    MOB_flag = False
                    DSW_flag = False
                    COMP_flag = False
                    soteria_flag = True
                    soteria_cus_flag = False
                    write_flag = False
                    setting_win_flag =0
                    self.combo.config(state='disabled')
                    self.button_1.config(state='disabled')
                    self.newWindow = tk.Toplevel(self.master)
                    self.app = Key_gen(self.newWindow)
                    self.button_2.config(state='normal')
                elif "Soteria-G3"==self.combo.get():
                    MOB_flag = False
                    DSW_flag = False
                    COMP_flag = False
                    soteria_flag = True
                    soteria_cus_flag = True
                    write_flag = True
                    setting_win_flag =0
                    self.combo.config(state='disabled')
                    self.button_1.config(state='disabled')
                    self.newWindow = tk.Toplevel(self.master)
                    self.app = Key_gen(self.newWindow)
                    self.button_2.config(state='normal')
                elif "Mobile" == self.combo.get():
                   MOB_flag = True
                   DSW_flag = False
                   COMP_flag = False
                   soteria_flag = False
                   setting_win_flag =0
                   soteria_cus_flag = True
                   write_flag = False
                   self.combo.config(state='disabled')
                   self.button_1.config(state='disabled')
                   self.newWindow = tk.Toplevel(self.master)
                   self.app = Key_gen(self.newWindow)
                   self.button_2.config(state='normal')
                elif "Desktop" == self.combo.get():
                   DSW_flag = True
                   MOB_flag = False
                   COMP_flag = False
                   soteria_flag = False
                   setting_win_flag =0
                   soteria_cus_flag = True
                   write_flag = False
                   self.combo.config(state='disabled')
                   self.button_1.config(state='disabled')
                   self.newWindow = tk.Toplevel(self.master)
                   self.app = Key_gen(self.newWindow)
                   self.button_2.config(state='normal')
                elif "Mobile & Comparator" == self.combo.get():
                   DSW_flag = False
                   MOB_flag = True
                   COMP_flag = True
                   soteria_flag = False
                   soteria_cus_flag = True
                   write_flag = False
                   setting_win_flag =0
                   self.combo.config(state='disabled')
                   self.button_1.config(state='disabled')
                   self.newWindow = tk.Toplevel(self.master)
                   self.app = Key_gen(self.newWindow)
                   self.button_2.config(state='normal')
                elif "General & Comparator" == self.combo.get():
                   DSW_flag = False
                   MOB_flag = False
                   COMP_flag = True
                   soteria_flag = False
                   soteria_cus_flag = False
                   write_flag = False
                   setting_win_flag =0
                   self.combo.config(state='disabled')
                   self.button_1.config(state='disabled')
                   self.newWindow = tk.Toplevel(self.master)
                   self.app = Key_gen(self.newWindow)
                   self.button_2.config(state='normal')

         
        class Key_gen(Frame):
            def onFrameConfigure(self, event):
                '''Reset the scroll region to encompass the inner frame'''
                self.canvas.configure(scrollregion=self.canvas.bbox("all"))        
            def __init__(self, master):
                Frame.__init__(self, master)   
                self.master.title(message[0])
                self.master.protocol("WM_DELETE_WINDOW", self.on_closing_main)
                self.master = master
                frame = VerticalScrolledFrame(master, 
                width=800, 
                borderwidth=2, 
                relief=tk.SUNKEN) 
                #background="light green")
            #frame.grid(column=0, row=0, sticky='nsew') # fixed size
                frame.pack(fill=tk.BOTH, expand=True)
                # self.canvas = tk.Canvas(master, borderwidth=0, background="#ffffff")
                # self.frame = tk.Frame(self.canvas, background="#ffffff")
                # self.vsb = tk.Scrollbar(master, orient="vertical", command=self.canvas.yview)
                # self.canvas.configure(yscrollcommand=self.vsb.set)

                # self.vsb.pack(side="right", fill="y")
                # self.canvas.pack(side="left", fill="both", expand=True)
                # self.canvas.create_window(0,0, window=self.frame, anchor="nw", 
                #                           tags="self.frame")
                # self.canvas.update_idletasks()
                # self.canvas.configure(scrollregion=self.canvas.bbox('all'), 
                #          yscrollcommand=self.vsb.set)
                # self.frame.bind("<Configure>", self.onFrameConfigure)
                # self.vsb.pack(fill='y', side='right')

                #self.populate()
                #for i in range(30):
                #  label = tk.Label(frame, text="This is a label "+str(i))
                #  label.grid(column=1, row=i, sticky=tk.W)

                #  text = tk.Entry(frame, textvariable="text")
                #  text.grid(column=2, row=i, sticky=tk.W)
                #self.initUI()
                

            #def initUI(self):
                global tool_config_file
                global tool_config
                global MultipleDev
                global ap_key_window_active
                ap_key_window_active =0

                self.opensslpath=StringVar()
                self.outdir=StringVar()
                self.ecdsakey=StringVar() 
                self.ecdsapass=StringVar()
                self.ecdhkey=StringVar()
                self.ecdhpass=StringVar()
                self.aeskey=StringVar()
                self.tagAddr=StringVar()
                self.tagAddr1=StringVar()
                self.custIDX=StringVar()
                self.custOFF=StringVar()
                self.custDAT=StringVar()
                self.CustFilekey=StringVar()
                self.ATEvar = IntVar()
                self.JTAGvar = IntVar()
                self.COMPvar = IntVar()
                self.SUSvar = IntVar()
                self.AUTHvar = IntVar()
                self.ENCvar = IntVar()
                self.ECDHENCvar = IntVar()
                self.ECDHLCKvar = IntVar()
                self.ECDSALCKvar = IntVar()
                self.securebootlckvar = IntVar()
                self.sg2lckvar = IntVar()
                self.tag0lckvar = IntVar()
                self.tag1lckvar = IntVar()
                self.flashlckvar = IntVar()

                self.ECDHPrivLCKvar = IntVar()
                self.ECDHPubLCKvar = IntVar()
                self.AESvar = IntVar()
                self.AEMvar = IntVar()
                self.TAGvar = IntVar()
                self.CUSvar = IntVar()
                self.Hex2Dec = IntVar()
                self.CustmDatDirPath=StringVar()
                self.WDTDelay = IntVar()
                self.WDTENvar = IntVar()
                self.DSWvar = IntVar()
                self.DESWvar = IntVar()
                self.DSWgpio = StringVar()
                
                self.dicevar = IntVar()
                self.dice_hash_var = IntVar()
                self.Rollvar = IntVar()
                self.MRollvar = IntVar()
                self.ecdsakeyvar = IntVar()
                self.Mecdsakeyvar = IntVar()
                self.PRIMvar0 = IntVar()
                self.PRIMvar1 = IntVar()
                self.Tagflashvar_0 = IntVar()
                self.Tagflashvar_2 = IntVar()
                self.Tagflashvar_1 = IntVar()
                self.Tagflashvar_3 = IntVar()
                self.flashcomp1 = StringVar()
                self.customerrev = StringVar()
                self.plat_id = StringVar()
                self.ap1_reset_var = IntVar()
                self.extrst_var = IntVar()
                self.authen_enable_status_var =IntVar()
                self.sel_ecdhkeyvar = IntVar()
                self.ecdhkeyvar = IntVar()
                self.ecdh_key_var = IntVar()
                self.custom_ecdh_key_bin=StringVar()
                self.custom_ecdh_pass_key_bin=StringVar()
                self.ecdh_key_bin=StringVar()
                self.ecdh_en_key_var = IntVar()
                self.ecdh_en_key_bin=StringVar()
                
                self.AUTHEnvar = IntVar()
                self.ecdsa_key_hash_bin=StringVar()
                self.ecdsa_key_hash_check_var = IntVar()
                self.ecdsaaddress = StringVar()
                self.ecdsaaddress_1 = StringVar()
                self.eckeycount = IntVar()
                self.ECCP384var = IntVar()
                self.secureboot = StringVar() 
                self.PRIMgpio_0 = StringVar()
                self.PRIMgpio_1 = StringVar()
                self.TAGvar_1 = IntVar()
                self.otp_write_lock_var_0 = IntVar()
                self.otp_write_lock_byte_var_0 = StringVar()
                self.otp_read_lock_var_0 = IntVar()
                self.otp_read_lock_byte_var_0 = StringVar()        

                self.otp_crc_var =StringVar()

                if(True == tool_config_file):
                    self.process_efuse_gen_from_ini()
                    self.generate_efuse()
                    print("Generated Efuse binaries stored in the <efuse_generator>\efuse\efuse_<YYYYMMDD>_<WHHMMSS> ")
                    sys.exit(2)  
                
                #self.master.title(message[0])

                #self.master.protocol("WM_DELETE_WINDOW", self.on_closing_main)
                if os.path.exists("mchp.ico"):
                  self.master.iconbitmap('mchp.ico') 

                #self.pack(fill=BOTH, expand=False)
                #self.pack(fill=BOTH,anchor=CENTER, expand=False)
                myrow = 0
                global msgidx
                global custom_data
                global setting_win_flag
                msgidx = 0
                labelframe11 = LabelFrame(frame, text="Environment Variables  ")
                labelframe11.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)
                #myrow = myrow +1
                #self.opensslpath=StringVar()
                Label(labelframe11, text=message[1]).grid(row=myrow,column = 0,sticky='NW', padx=5, pady=2)
                labelframe11.settings = Button( labelframe11, text = message[2],width = 12, command = self.new_window_settings )
                labelframe11.settings.grid(row = myrow, column=2, sticky='E', padx=15, pady=10)

                custom_data = []
                
                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="OutPut Directory ")
                labelframe1.grid( row = myrow,sticky=W,column = 0)
                myrow = myrow +1
                self.lbl = Label(labelframe1, text="Output Dir").grid(row = myrow,column=0,sticky=W)
               # self.outdir=StringVar()
                outdirbar=Entry(labelframe1) 
                #sticky=W+E,ipady=0, ipadx=40
                outdirbar.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=60)
                #outdirbar.grid(row=myrow, column=1,sticky=W,pady=20, padx=6)
                outdirbar["textvariable"] = self.outdir
                outdirbar.bind("<Enter>")
                self.bbutton2= Button(labelframe1, text="Browse",width = 12, command=self.browsefldr)
                self.bbutton2.grid(row=myrow, column=4, sticky=W,pady=10)

                # myrow = myrow +1
                # self.ecdsa_key_lbl = Label(labelframe1, state="normal",text="ECDSA(P-384) Key Hash Bin").grid(sticky=W, pady=0, padx=1)
                # self.ecdsa_key_hash_bin=StringVar()
                # self.ecdsa_key_outdirbar=Entry(labelframe1,state="disabled")
                # self.ecdsa_key_outdirbar.grid(row=myrow, column=1,sticky=W+E)
                # self.ecdsa_key_outdirbar["textvariable"] = self.ecdsa_key_hash_bin
                # self.ecdsa_key_outdirbar.bind("<Enter>")
                # self.ecdsa_key_hash_button= Button(labelframe1, text="Browse",width = 12, command=self.hashbrowsefldr,state="disabled")
                # self.ecdsa_key_hash_button.grid(row=myrow, column=2, sticky=W, pady=0, padx=1)
                # myrow = myrow +1
                # self.ecdsa_key_lbl = Label(labelframe1, state="normal",text="ECDSA(P-384) Key Hash Bin").grid(sticky=W, pady=0, padx=1)
                # self.ecdsa_key_hash_bin=StringVar()
                # self.ecdsa_key_outdirbar=Entry(labelframe1,state="disabled")
                # self.ecdsa_key_outdirbar.grid(row=myrow, column=1,sticky=W+E)
                # self.ecdsa_key_outdirbar["textvariable"] = self.ecdsa_key_hash_bin
                # self.ecdsa_key_outdirbar.bind("<Enter>")
                # self.ecdsa_key_hash_button= Button(labelframe1, text="Browse",width = 12, command=self.hashbrowsefldr,state="disabled")
                # self.ecdsa_key_hash_button.grid(row=myrow, column=2, sticky=W, pady=0, padx=1)
                #self.bbutton2.place(relx=5, x=20, y=20, anchor=E)
                '''
                myrow = myrow +1
                self.ATElbl = Label(self, text="ATE Mode")
                self.ATElbl.grid( row = myrow, sticky=W)
                #self.ATEvar = IntVar()
                self.R2 = Radiobutton(self, text="Disable", variable=self.ATEvar, value=0, command=self.ATEsel)
                self.R2.grid(row=myrow, column = 1, sticky = E )
                self.R1 = Radiobutton(self, text="Enable", variable=self.ATEvar, value=1, command=self.ATEsel)
                self.R1.grid(row=myrow, column = 1, sticky = W )
                self.ATEvar.set(1)        
                '''
                myrow = myrow +1
               # self.JTAGvar = IntVar()
                labelframe1 = LabelFrame(frame, text="JTAG Variables  ")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=50, ipady=5)
                myrow = myrow +1
                # self.JTAGlbl = Label(labelframe1, text="JTAG Debug Disable")
                # self.JTAGlbl.grid( row = myrow, sticky=W, padx=5, pady=2)
                # self.R3 = Radiobutton(labelframe1, text="Enabled", variable=self.JTAGvar, value=0, command=self.JTAGsel)
                # self.R3.grid(row=myrow, column = 1, sticky=W, padx=5, pady=2 )
                # self.R4 = Radiobutton(labelframe1, text="Disabled", variable=self.JTAGvar, value=1, command=self.JTAGsel)
                # self.R4.grid(row=myrow, column = 2, sticky=W, padx=5, pady=2 )
                # val = self.JTAGvar.get()
                # self.JTAGvar.set(val)        

                #self.uart_crisis_var = IntVar()
                #myrow = myrow +1
                #self.uart_lbl = Label(labelframe1, text="UART Crisis Recovery Option Select ")
                #self.uart_lbl.grid( row = myrow, sticky=W, padx=5, pady=2)
                #self.uart_R3 = Radiobutton(labelframe1, text="Load Failure", variable=self.uart_crisis_var, value=0,command=self.dumm)
                #self.uart_R3.grid(row=myrow, column = 1, sticky=W, padx=5, pady=2 )
                #self.uart_R4 = Radiobutton(labelframe1, text="Strap", variable=self.uart_crisis_var, value=1,command=self.dumm)
                #self.uart_R4.grid(row=myrow, column = 2, sticky=W, padx=5, pady=2 )
                #val = self.uart_crisis_var.get()
                #self.uart_crisis_var.set(val)

                #self.uart_crisis_rec_var = IntVar()
                #myrow = myrow +1
                #self.uart_crisis_rec_var_lbl = Label(labelframe1, text="UART Crisis Recovery Enable ")
                #self.uart_crisis_rec_var_lbl.grid( row = myrow, sticky=W, padx=5, pady=2)
                #self.uart_crisis_rec_var_R3 = Radiobutton(labelframe1, text="Disabled", variable=self.uart_crisis_rec_var, value=0,command=self.dumm)
                #self.uart_crisis_rec_var_R3.grid(row=myrow, column = 1, sticky=W, padx=5, pady=2 )
                #self.uart_crisis_rec_var_R4 = Radiobutton(labelframe1, text="Enabled", variable=self.uart_crisis_rec_var, value=1,command=self.dumm)
                #self.uart_crisis_rec_var_R4.grid(row=myrow, column = 2, sticky=W, padx=5, pady=2 )
                #val = self.uart_crisis_rec_var.get()
                #self.uart_crisis_rec_var.set(val)

                self.debug_disable_var = IntVar()
                myrow = myrow +1
                self.debug_disable_var_lbl = Label(labelframe1, text="Debug Disable Lock ")
                self.debug_disable_var_lbl.grid( row = myrow, sticky=W, padx=5, pady=2)
                self.debug_disable_var_R3 = Radiobutton(labelframe1, text="Debug capability (0)", variable=self.debug_disable_var, value=0,command=self.dumm)
                self.debug_disable_var_R3.grid(row=myrow, column = 1, sticky=W, padx=5, pady=2 )
                self.debug_disable_var_R4 = Radiobutton(labelframe1, text="Debug port disabled(1)", variable=self.debug_disable_var, value=1,command=self.dumm)
                self.debug_disable_var_R4.grid(row=myrow, column = 2, sticky=W, padx=5, pady=2 )
                val = self.debug_disable_var.get()
                self.debug_disable_var.set(val)

                #self.check_debug_var = IntVar()
                #myrow = myrow +1
                #self.check_debug_var_lbl = Label(labelframe1, text="Check for Debugger Feature ")
                #self.check_debug_var_lbl.grid( row = myrow, sticky=W, padx=5, pady=2)
                #self.check_debug_var_R3 = Radiobutton(labelframe1, text="Disabled", variable=self.check_debug_var, value=0,command=self.dumm)
                #elf.check_debug_var_R3.grid(row=myrow, column = 1, sticky=W, padx=5, pady=2 )
                #self.check_debug_var_R4 = Radiobutton(labelframe1, text="Enabled", variable=self.check_debug_var, value=1,command=self.dumm)
                #self.check_debug_var_R4.grid(row=myrow, column = 2, sticky=W, padx=5, pady=2 )
                #val = self.check_debug_var.get()
                #self.check_debug_var.set(val)

                self.debug_pun_var = IntVar()
                myrow = myrow +1
                self.debug_pun_var_lbl = Label(labelframe1, text="DEBUG_PU_EN")
                self.debug_pun_var_lbl.grid( row = myrow, sticky=W, padx=5, pady=2)
                self.debug_pun_var_R3 = Radiobutton(labelframe1, text="Disabled", variable=self.debug_pun_var, value=0,command=self.dumm)
                self.debug_pun_var_R3.grid(row=myrow, column = 1, sticky=W, padx=5, pady=2 )
                self.debug_pun_var_R4 = Radiobutton(labelframe1, text="Enabled", variable=self.debug_pun_var, value=1,command=self.dumm)
                self.debug_pun_var_R4.grid(row=myrow, column = 2, sticky=W, padx=5, pady=2 )
                val = self.debug_pun_var.get()
                self.debug_pun_var.set(val)

                myrow = myrow +1
                self.Clear_customer_var = IntVar()
                self.WDT_activation_var = IntVar()
                self.rolling_ec_bootloader_var = IntVar()
                self.enable_tagx_image_var = IntVar()
                # labelframe1 = LabelFrame(frame, text="Custom Features ")
                # labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                #          padx=5, pady=5, ipadx=50, ipady=5)
                    #myrow = myrow +1
                    #self.soft_jtag_wire_lbl = Label(labelframe1, text="DEBUG SELECT")
                    #self.soft_jtag_wire_lbl.grid( row = myrow, sticky='E', padx=5, pady=2)
                    #self.soft_jtag_wire_R3 = Radiobutton(labelframe1, text="2-Wire SWD ", variable=self.soft_jtag_wire, value=0, command=self.dumm)
                    #self.soft_jtag_wire_R3.grid(row=myrow, column = 1, sticky='E', padx=5, pady=2 )
                    #self.soft_jtag_wire_R4 = Radiobutton(labelframe1, text="4-Wire JTAG", variable=self.soft_jtag_wire, value=1, command=self.dumm)
                    #self.soft_jtag_wire_R4.grid(row=myrow, column = 2, sticky='E', padx=5, pady=2 )
                    #val = self.soft_jtag_wire.get()
                    #self.soft_jtag_wire.set(val)


                if( True == COMP_flag):
                    myrow = myrow +1
                   # self.JTAGvar = IntVar()
                    labelframe1 = LabelFrame(frame, text="Comparator Strap ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=50, ipady=5)
                    myrow = myrow +1
                    self.COMPlbl = Label(labelframe1, text="CMP_STRAP ")
                    self.COMPlbl.grid( row = myrow, sticky=E,padx=5, pady=2)
                    self.COMPlblR3 = Radiobutton(labelframe1, text="Enable", variable=self.COMPvar, value=1, command=self.COMPsel)
                    self.COMPlblR3.grid(row=myrow, column = 1, sticky = W,padx=5, pady=2 )
                    self.COMPlblR4 = Radiobutton(labelframe1, text="Disable", variable=self.COMPvar, value=0, command=self.COMPsel)
                    self.COMPlblR4.grid(row=myrow, column = 2, sticky = E ,padx=5, pady=2)  
                    val = self.COMPvar.get()
                    self.COMPvar.set(val)


               
               #  myrow = myrow +1
               # # self.AUTHvar = IntVar()
               #  self.AUTHlbl = Label(self, text="Authentication ")
               #  self.AUTHlbl.grid( row = myrow, sticky=W)
               #  self.R7 = Radiobutton(self, text="Enable", variable=self.AUTHvar, value=1, command=self.AUTHsel)
               #  self.R7.grid(row=myrow, column = 1, sticky = W )
               #  self.R8 = Radiobutton(self, text="Disable", variable=self.AUTHvar, value=0, command=self.AUTHsel)
               #  self.R8.grid(row=myrow, column = 1, sticky = E )
               #  val = self.AUTHvar.get()
               #  self.AUTHvar.set(val)

                myrow = myrow +1
                #self.AUTHEnvar = IntVar()
                labelframe1 = LabelFrame(frame, text="ECDSA Authentication")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)
                myrow = myrow +1
                #labelframe1.pack(fill="both", expand="yes")
                self.Albl = Label(labelframe1, text="Authentication ")
                self.Albl.grid( row = myrow, sticky=W)
                self.AR7 = Radiobutton(labelframe1, text="Enable", variable=self.AUTHEnvar, value=1, command=self.AUTHselen)
                self.AR7.grid(row=myrow, column = 1, sticky = W )
                self.AR8 = Radiobutton(labelframe1, text="Disable", variable=self.AUTHEnvar , value=0, command=self.AUTHselen)
                self.AR8.grid(row=myrow, column = 2, sticky = W )
                val = self.AUTHEnvar.get()
                self.AUTHEnvar.set(val)

                myrow = myrow +1
                labelframe_1 = LabelFrame(labelframe1, text="ECDSA Key Hash Bin Available ")
                labelframe_1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)
                myrow = myrow +1
                #self.ecdsa_key_hash_check_var = IntVar()
                self.ecdsa_key_hash_lbl = Label(labelframe_1, text="SHA384(Owner 1 Public Key) Hash available ",state="normal")
                self.ecdsa_key_hash_lbl.grid( row = myrow, sticky=W)
                self.ecdsa_key_hash_lbl = Label(labelframe_1, text="")
                self.ecdsa_key_hash_lbl.grid( row = myrow,column = 1, sticky=W)
                self.ecdsa_key_hash_check = Checkbutton(labelframe_1, variable=self.ecdsa_key_hash_check_var, onvalue = 1, offvalue = 0, command=self.ecdsa_key_hash_check_sel,state="disabled")
                self.ecdsa_key_hash_check.grid(row=myrow, column = 1, sticky = W )
                val = self.ecdsa_key_hash_check_var.get()
                self.ecdsa_key_hash_check_var.set(val)

                
                myrow = myrow +1
                self.ecdsa_key_lbl = Label(labelframe_1, state="normal",text="SHA384(Owner 1 Public Key) Hash Bin").grid(sticky=W, pady=0, padx=1)
                #self.ecdsa_key_hash_bin=StringVar()
                self.ecdsa_key_outdirbar=Entry(labelframe_1,state="disabled")
                self.ecdsa_key_outdirbar.grid(row=myrow, column=1,sticky=W)
                self.ecdsa_key_outdirbar["textvariable"] = self.ecdsa_key_hash_bin
                self.ecdsa_key_outdirbar.bind("<Enter>")
                self.ecdsa_key_hash_button= Button(labelframe_1, text="Browse",width = 12, command=self.hashbrowsefldr,state="disabled")
                self.ecdsa_key_hash_button.grid(row=myrow, column=2, sticky=W, pady=0, padx=1)
                
               #  myrow = myrow +1
               #  lbl = Label(self, text="ECDSA Key filename").grid(row=myrow, sticky=W, pady=0, padx=1)
               # # self.ecdsakey=StringVar()
               #  if "" == self.ecdsakey.get():
               #      self.ecdsakey.set("Enter ECDSA Key filename to generate")
               #      #self.ecdsakey.set("efuse/test_keys/ecprivkey001.pem") #AK
                
               #  self.ecdsabar=Entry(self, state = "disabled")
               #  self.ecdsabar.grid(row=myrow, column=1,sticky=W+E)
               #  self.ecdsabar["textvariable"] = self.ecdsakey 
               #  self.ecdsabar.bind("<Enter>",self.clearcontent3) 
                

                # lbl = Label(self, text="ECDSA password").grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.ecdsapass=StringVar()

                # if "" == self.ecdsapass.get():
                #     self.ecdsapass.set("Enter ECDSA Password")
                    #self.ecdsapass.set("ECPRIVKEY001") #AK
                #self.ecdsapassbar=Entry(self, state = "disabled")
                #self.ecdsapassbar.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                #self.ecdsapassbar["textvariable"] = self.ecdsapass
                #self.ecdsapassbar.bind("<Enter>",self.clearcontent4) 

                # myrow = myrow +1
                # #self.ecdsaaddress = StringVar()
                # self.ecdsaaddresslbl = Label(labelframe1, text="ECDSA Key Storage Flash Address 0(HEX)",state = "normal")
                # self.ecdsaaddresslbl.grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.ecdsaaddress.trace("w", self.ecdsa_clearcontentvalue_2)
                # self.ecdsaaddressbar0=Entry(labelframe1, state="disabled")
                # self.ecdsaaddressbar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                # self.ecdsaaddressbar0["textvariable"] = self.ecdsaaddress
                # self.ecdsaaddressbar0.bind("<Enter>",self.ecdsa_clearcontentvalue) 
                # self.ecdsaaddress.set(0)

                # myrow = myrow +1
                # #self.ecdsaaddress_1 = StringVar()
                # self.ecdsaaddress_1_lbl = Label(labelframe1, text="ECDSA Key Storage Flash Address 1(HEX)",state = "normal")
                # self.ecdsaaddress_1_lbl.grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.ecdsaaddress_1.trace("w", self.ecdsa_clearcontentvalue_1)
                # self.ecdsaaddressbar_1=Entry(labelframe1, state="disabled")
                # self.ecdsaaddressbar_1.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                # self.ecdsaaddressbar_1["textvariable"] = self.ecdsaaddress_1
                # self.ecdsaaddressbar_1.bind("<Enter>",self.ecdsa_clearcontentvalue_func) 
                # self.ecdsaaddress_1.set(0)
                myrow = myrow +1
                labelframe2 = LabelFrame(labelframe1, text="ECDSA Key Hash Generation")
                labelframe2.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)        

                myrow = myrow +1 

                self.ECCP384var = IntVar()
                self.ECCP384lbl = Label(labelframe2, text="SHA384(Owner 1 Public Key) Hash ",state = "disabled")
                self.ECCP384lbl.grid( row = myrow, sticky=W)
                self.ECCR11 = Radiobutton(labelframe2, text="Generate", variable=self.ECCP384var, value=1, state = "disabled",command=  self.ECCP384sel)
                self.ECCR11.grid(row=myrow, column = 1, sticky = W )
                self.ECCR12 = Radiobutton(labelframe2, text="Not Generate", variable=self.ECCP384var, value=0, state = "disabled",command=self.ECCP384sel)
                self.ECCR12.grid(row=myrow, column = 2, sticky = W )
                val = self.ECCP384var.get()
                self.ECCP384var.set(val)

                myrow = myrow +1
                self.ecdsa_sha384_key_lbl = Label(labelframe2, state="disabled",text="Enter SHA384(Owner 1 Public Key) Hash Key")
                self.ecdsa_sha384_key_lbl.grid(sticky=W, pady=0, padx=1)
                self.ecdsa_sha384_key_hash_bin=StringVar()
                self.ecdsa_sha384_key_outdirbar=Entry(labelframe2,state="disabled")
                self.ecdsa_sha384_key_outdirbar.grid(row=myrow, column=1,sticky=W)
                self.ecdsa_sha384_key_outdirbar["textvariable"] = self.ecdsa_sha384_key_hash_bin
                self.ecdsa_sha384_key_outdirbar.bind("<Enter>")
                self.ecdsa_sha384_key_hash_button= Button(labelframe2,text="Browse",width = 12, command=self.hashbrowsefldr_1,state="disabled")
                self.ecdsa_sha384_key_hash_button.grid(row=myrow, column=2, sticky=W, pady=0, padx=1)

                # myrow = myrow +1
                # #self.ECDHLCKvar = IntVar()
                # self.ECDSALCKlbl = Label(labelframe1, text="Write Lock ECDSA Key Hash Blob")
                # self.ECDSALCKlbl.grid( row = myrow, sticky=W)
                # self.ECDSALCKlbl = Label(labelframe1, text="")
                # self.ECDSALCKlbl.grid( row = myrow,column = 1, sticky=E)
                # self.ECDSALCK_CB = Checkbutton(labelframe1, variable=self.ECDSALCKvar, onvalue = 1, offvalue = 0, command=self.ECDSALCKsel,state="disabled")
                # self.ECDSALCK_CB.grid(row=myrow, column = 1, sticky = W )
                # val = self.ECDSALCKvar.get()
                # self.ECDSALCKvar.set(val)
                #labelframe1.pack(fill="both", expand="yes")

                if False:
                    myrow = myrow +1
                    self.ECDSA_key_revocation_byte_0_var = StringVar()
                   # self.ENCvar = IntVar()
                    labelframe1 = LabelFrame(frame, text="ECDSA Key Revocation Byte-0  ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=15, ipady=15)
                    myrow = myrow +1

                    
                    self.ENC_revo_lbl1 = Label(labelframe1, text="ECDSA Key Revocation Byte-0 (HEX)")
                    self.ENC_revo_lbl1.grid( row = myrow, sticky=W)
                    self.ECDSA_key_revocation_byte_0_var.trace("w", self.ecdsa_key_rev_clearcontentvalue_2)
                    self.ENC_revo_bar0=Entry(labelframe1)
                    self.ENC_revo_bar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                    self.ENC_revo_bar0["textvariable"] = self.ECDSA_key_revocation_byte_0_var
                    self.ENC_revo_bar0.bind("<Enter>",self.ecdsa_key_rev_clearcontentvalue) 
                    self.ECDSA_key_revocation_byte_0_var.set(0)


                    myrow = myrow +1
                   # self.ENCvar = IntVar()
                    self.otp_crc_var = StringVar()
                    labelframe1 = LabelFrame(frame, text="OTP CRC Byte  ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=15, ipady=15)
                    myrow = myrow +1
        	        #self.ecdsaaddress = StringVar()
                    self.otp_crc_lbl = Label(labelframe1, text="OTP CRC Byte (HEX)",state = "normal")
                    self.otp_crc_lbl.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.otp_crc_var.trace("w", self.otp_clearcontentvalue_2)
                    self.otp_crc_bar0=Entry(labelframe1)
                    self.otp_crc_bar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                    self.otp_crc_bar0["textvariable"] = self.otp_crc_var
                    self.otp_crc_bar0.bind("<Enter>",self.otp_clearcontentvalue) 
                    self.otp_crc_var.set(0)

                 #    myrow = myrow +1
                 #   # self.ENCvar = IntVar()
                 #    labelframe1 = LabelFrame(frame, text="Customer Revision  ")
                 #    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                 #         padx=5, pady=5, ipadx=15, ipady=15)
                 #    myrow = myrow +1
        	        # #self.ecdsaaddress = StringVar()
                 #    self.cus_revision_var_lbl = Label(labelframe1, text="Customer Revision (HEX)",state = "normal")
                 #    self.cus_revision_var_lbl.grid(row=myrow, sticky=W, pady=0, padx=1)
                 #    self.cus_revision_var.trace("w", self.customer_clearcontentvalue_2)            
                 #    self.cus_revision_var_bar0=Entry(labelframe1)
                 #    self.cus_revision_var_bar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                 #    self.cus_revision_var_bar0["textvariable"] = self.cus_revision_var
                 #    self.cus_revision_var_bar0.bind("<Enter>",self.customer_clearcontentvalue) 
                 #    self.cus_revision_var.set(0)

                if True:
                    myrow = myrow +1
                   # self.ENCvar = IntVar()
                    labelframe1 = LabelFrame(frame, text="EC FW Encryption ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=15, ipady=15)
                    myrow = myrow +1

                    myrow = myrow +1
                    self.ENClbl1 = Label(labelframe1, text="EC FW Encryption Enable")
                    self.ENClbl1.grid( row = myrow, sticky=W)
                    self.ENClbl = Label(labelframe1, text="")
                    self.ENClbl.grid( row = myrow,column = 1, sticky=E)
                    self.CB5 = Checkbutton(labelframe1, variable=self.ENCvar, onvalue = 1, offvalue = 0, command=self.ENCsel)
                    self.CB5.grid(row=myrow, column = 1, sticky = W )
                    val = self.ENCvar.get()
                    self.ENCvar.set(val)

                    myrow = myrow +1
                    #self.sel_ecdhkeyvar = IntVar()
                    self.sel_ecdhkey_lbl = Label(labelframe1, text="Select Encryption Key Input  ",state = "normal")
                    self.sel_ecdhkey_lbl.grid( row = myrow, sticky=W)
                    self.sel_ecdhkey_R11 = Radiobutton(labelframe1, text="Provide ECDH keys", variable=self.sel_ecdhkeyvar, value=0, state = "disabled",command=  self.sel_ecdhkeysel)
                    self.sel_ecdhkey_R11.grid(row=myrow, column = 1, sticky = W )
                    self.sel_ecdhkey_R12 = Radiobutton(labelframe1, text="ECDH Private Key Encrypted - Direct Input ", variable=self.sel_ecdhkeyvar, value=1, state = "disabled",command=self.sel_ecdhkeysel)
                    self.sel_ecdhkey_R12.grid(row=myrow, column = 2, sticky = E )
                    val = self.sel_ecdhkeyvar.get()
                    self.sel_ecdhkeyvar.set(val)

                    myrow = myrow +1
                   # self.ENCvar = IntVar()
                    labelframe2 = LabelFrame(labelframe1, text="Input ECDH Key ")
                    labelframe2.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=15, ipady=15)




                    
                    myrow = myrow +1
                    lbl = Label(labelframe2, text="ECDH Key filename").grid(row=myrow, sticky=W, pady=0, padx=1)
                   # self.ecdhkey=StringVar()
                    if "" == self.ecdhkey.get():
                        self.ecdhkey.set("Enter ECDH Key filename to generate")
                        #self.ecdhkey.set("efuse/test_keys/ecprivkey002.pem") #AK
                    self.ecdhbar=Entry(labelframe2,state="disabled")
                    self.ecdhbar.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=60)
                    self.ecdhbar["textvariable"] = self.ecdhkey
                    self.ecdhbar.bind("<Enter>",self.clearcontent1)
                    self.ecdhbar_button= Button(labelframe2, text="Browse",width = 12, command=self.ecdh_key_browsefldr_1,state="disabled")
                    self.ecdhbar_button.grid(row=myrow, column=2, sticky=W, pady=0, padx=1)

                    myrow = myrow +1
                    lbl = Label(labelframe2, text="Enter ECDH Password").grid(row=myrow, sticky=W, pady=0, padx=1)
                   # self.ecdhpass=StringVar()
                    if "" == self.ecdhpass.get():
                        self.ecdhpass.set("Enter ECDH Password")
                        #self.ecdhpass.set("ECPRIVKEY002") #AK
                    self.ecdhpassbar=Entry(labelframe2,state="disabled")
                    self.ecdhpassbar.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=60)
                    self.ecdhpassbar["textvariable"] = self.ecdhpass
                    self.ecdhpassbar.bind("<Enter>",self.clearcontent2) 
                    
                    myrow = myrow +1
                    #self.ECDHENCvar = IntVar()
                    self.ECDHENClbl1 = Label(labelframe2, text="Encrypt ECDH Key",state = "normal")
                    self.ECDHENClbl1.grid( row = myrow, sticky=W)
                    self.ECDHENClbl = Label(labelframe2, text="")
                    self.ECDHENClbl.grid( row = myrow,column = 1, sticky=E)
                    self.ECDHENC_CB = Checkbutton(labelframe2, variable=self.ECDHENCvar, onvalue = 1, offvalue = 0, command=self.ECDHENCsel,state="disabled")
                    self.ECDHENC_CB.grid(row=myrow, column = 1, sticky = W )
                    val = self.ECDHENCvar.get()
                    self.ECDHENCvar.set(val)

                    myrow = myrow +1
                    #self.ecdhkeyvar = IntVar()
                    self.ecdhkey_lbl = Label(labelframe2, text="Custom Input ECDH2 key  ",state = "normal")
                    self.ecdhkey_lbl.grid( row = myrow, sticky=W)
                    self.ecdhkey_R11 = Label(labelframe2, text="")
                    self.ecdhkey_R11.grid( row = myrow, sticky=E)
                    #self.ecdhkey_R11 = Radiobutton(labelframe2, text="Disable", variable=self.ecdhkeyvar, value=0, state = "disabled",command=  self.ecdhkeysel)
                    #self.ecdhkey_R11.grid(row=myrow, column = 1, sticky = W )
                    self.ecdhkey_R12 = Checkbutton(labelframe2, variable=self.ecdhkeyvar, onvalue = 1, offvalue = 0, command=self.ecdhkeysel,state="disabled")
                    #self.ecdhkey_R12 = Radiobutton(labelframe2, text="Custom Key", variable=self.ecdhkeyvar, value=1, state = "disabled",command=self.ecdhkeysel)
                    self.ecdhkey_R12.grid(row=myrow, column = 1, sticky = W )
                    val = self.ecdhkeyvar.get()
                    self.ecdhkeyvar.set(val)

                    myrow = myrow +1
                    self.custom_ecdh_key_lbl = Label(labelframe2, state="normal",text="ECDH2 Key").grid(sticky=W, pady=0, padx=1)
                    #self.custom_ecdh_key_bin=StringVar()
                    self.custom_ecdh_key_outdirbar=Entry(labelframe2,state="disabled")
                    self.custom_ecdh_key_outdirbar.grid(row=myrow, column=1,sticky=W+E)
                    self.custom_ecdh_key_outdirbar["textvariable"] = self.custom_ecdh_key_bin
                    self.custom_ecdh_key_outdirbar.bind("<Enter>")
                    self.custom_ecdh_key_hash_button= Button(labelframe2, text="Browse",width = 12, command=self.custom_ecdh_key_browsefldr,state="disabled")
                    self.custom_ecdh_key_hash_button.grid(row=myrow, column=2, sticky=W, pady=0, padx=1)

                    myrow = myrow +1
                    self.custom_ecdh_pass_key_lbl = Label(labelframe2, state="normal",text="ECDH2 Key Password").grid(sticky=W, pady=0, padx=1)
                    #self.custom_ecdh_pass_key_bin=StringVar()
                    self.custom_ecdh_pass_key_outdirbar=Entry(labelframe2,state="disabled")
                    self.custom_ecdh_pass_key_outdirbar.grid(row=myrow, column=1,sticky=W+E)
                    self.custom_ecdh_pass_key_outdirbar["textvariable"] = self.custom_ecdh_pass_key_bin
                    self.custom_ecdh_pass_key_outdirbar.bind("<Enter>")

                    myrow = myrow +1
                   # self.ENCvar = IntVar()
                    labelframe3 = LabelFrame(labelframe1, text="Input Encryption ECDH Key ")
                    labelframe3.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=15, ipady=15)
                    myrow = myrow +1
                    #myrow = myrow +1
                    #self.ecdh_key_var = IntVar()
                    self.ecdh_key_var_lbl = Label(labelframe3, text="Enc ECDH Key Bin available ",state="normal")
                    self.ecdh_key_var_lbl.grid( row = myrow, sticky=W)
                    self.ecdh_key_var_lbl = Label(labelframe3, text="")
                    self.ecdh_key_var_lbl.grid( row = myrow,column = 1, sticky=E)
                    self.ecdh_key_var_check = Checkbutton(labelframe3, variable=self.ecdh_key_var, onvalue = 1, offvalue = 0, command=self.ecdh_key_var_sel,state="disabled")
                    self.ecdh_key_var_check.grid(row=myrow, column = 1, sticky = W )
                    val = self.ecdh_key_var.get()
                    self.ecdh_key_var.set(val)

                    myrow = myrow +1
                    self.ecdh_key_lbl = Label(labelframe3, state="normal",text="Encrypted ECDH Key Bin").grid(sticky=W, pady=0, padx=1)
                    #self.ecdh_key_bin=StringVar()
                    self.ecdh_key_outdirbar=Entry(labelframe3,state="disabled")
                    self.ecdh_key_outdirbar.grid(row=myrow, column=1,sticky=W+E)
                    self.ecdh_key_outdirbar["textvariable"] = self.ecdh_key_bin
                    self.ecdh_key_outdirbar.bind("<Enter>")
                    self.ecdh_key_hash_button= Button(labelframe3, text="Browse",width = 12, command=self.ecdh_key_browsefldr,state="disabled")
                    self.ecdh_key_hash_button.grid(row=myrow, column=2, sticky=W, pady=0, padx=1)
                    myrow = myrow +1
                    #self.ecdh_en_key_var = IntVar()
                    self.ecdh_en_key_var_lbl = Label(labelframe3, text="ECDH II Pub Bin available ",state="normal")
                    self.ecdh_en_key_var_lbl.grid( row = myrow, sticky=W)
                    self.ecdh_en_key_var_lbl = Label(labelframe3, text="")
                    self.ecdh_en_key_var_lbl.grid( row = myrow,column = 1, sticky=E)
                    self.ecdh_en_key_var_check = Checkbutton(labelframe3, variable=self.ecdh_en_key_var, onvalue = 1, offvalue = 0, command=self.ecdh_en_key_var_sel,state="disabled")
                    self.ecdh_en_key_var_check.grid(row=myrow, column = 1, sticky = W )
                    val = self.ecdh_en_key_var.get()
                    self.ecdh_en_key_var.set(val)

                    myrow = myrow +1
                    self.ecdh_en_key_lbl = Label(labelframe3, state="normal",text="ECDH II Pub Key Bin").grid(sticky=W, pady=0, padx=1)
                    #self.ecdh_en_key_bin=StringVar()
                    self.ecdh_en_key_outdirbar=Entry(labelframe3,state="disabled")
                    self.ecdh_en_key_outdirbar.grid(row=myrow, column=1,sticky=W+E)
                    self.ecdh_en_key_outdirbar["textvariable"] = self.ecdh_en_key_bin
                    self.ecdh_en_key_outdirbar.bind("<Enter>")
                    self.ecdh_en_key_hash_button= Button(labelframe3, text="Browse",width = 12, command=self.ecdh_en_key_browsefldr,state="disabled")
                    self.ecdh_en_key_hash_button.grid(row=myrow, column=2, sticky=W, pady=0, padx=1)

                    # myrow = myrow +1
                    # #self.ECDHLCKvar = IntVar()
                    # self.ECDHPrivLCKlbl1 = Label(labelframe1, text="Lock ECDH Private Key")
                    # self.ECDHPrivLCKlbl1.grid( row = myrow, sticky=W)
                    # self.ECDHPrivLCKlbl = Label(labelframe1, text="")
                    # self.ECDHPrivLCKlbl.grid( row = myrow,column = 1, sticky=E)
                    # self.ECDHPrivLCK_CB = Checkbutton(labelframe1, variable=self.ECDHPrivLCKvar, onvalue = 1, offvalue = 0, command=self.ECDHPrivLCKsel,state="normal")
                    # self.ECDHPrivLCK_CB.grid(row=myrow, column = 1, sticky = W )
                    # val = self.ECDHPrivLCKvar.get()
                    # self.ECDHPrivLCKvar.set(val)

                    # myrow = myrow +1
                    # #self.ECDHLCKvar = IntVar()
                    # self.ECDHPubLCKlbl1 = Label(labelframe1, text="Lock ECDH Public II Key")
                    # self.ECDHPubLCKlbl1.grid( row = myrow, sticky=W)
                    # self.ECDHPubLCKlbl = Label(labelframe1, text="")
                    # self.ECDHPubLCKlbl.grid( row = myrow,column = 1, sticky=E)
                    # self.ECDHPubLCK_CB = Checkbutton(labelframe1, variable=self.ECDHPubLCKvar, onvalue = 1, offvalue = 0, command=self.ECDHPubLCKsel,state="normal")
                    # self.ECDHPubLCK_CB.grid(row=myrow, column = 1, sticky = W )
                    # val = self.ECDHPubLCKvar.get()
                    # self.ECDHPubLCKvar.set(val)

                
                    myrow = myrow +1
                   # self.AUTHvar = IntVar()
                    self.AEMlbl = Label(labelframe1, text="AES Encryption Mandatory")
                    self.AEMlbl.grid( row = myrow, sticky=W)
                    self.AEMR7 = Radiobutton(labelframe1, text="Enable", variable=self.AEMvar, value=1, command=self.AEMsel)
                    self.AEMR7.grid(row=myrow, column = 1, sticky = W )
                    self.AEMR8 = Radiobutton(labelframe1, text="Disable", variable=self.AEMvar, value=0, command=self.AEMsel)
                    self.AEMR8.grid(row=myrow, column = 2, sticky = E )
                    val = self.AEMvar.get()
                    self.AEMvar.set(val)            

                    myrow = myrow +1
                    self.fullvar = IntVar()
                    self.fullvarlbl = Label(labelframe1, text="Fully Provioned ")
                    self.fullvarlbl.grid( row = myrow, sticky=W)
                    self.fullvarR7 = Radiobutton(labelframe1, text="Fully provisioned. Boot Normally ", variable=self.fullvar, value=1, command=self.fullysel)
                    self.fullvarR7.grid(row=myrow, column = 1, sticky = W )
                    self.fullvar8 = Radiobutton(labelframe1, text="Either Blank or Partially Provisioned", variable=self.fullvar, value=0, command=self.fullysel)
                    self.fullvar8.grid(row=myrow, column = 2, sticky = E )
                    val = self.fullvar.get()
                    self.fullvar.set(val)

                myrow = myrow +1
                #self.secureboot = StringVar() 
                # self.sb = Label(self, text="Secure Boot  (HEX)",state = "normal")
                # self.sb.grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.secureboot.trace("w", self.update2)
                # self.sbbar=Entry(self, state="normal")
                # self.sbbar.grid(row=myrow, column=1,sticky=W)
                # self.sbbar["textvariable"] = self.secureboot
                # self.sbbar.bind("<Enter>",self.clearcontentvalue)        
                # self.security_features_var = StringVar()
                # if False == soteria_flag or True ==soteria_cus_flag or True == soteria_flag:
                #     myrow = myrow +1
                #     labelframe1 = LabelFrame(frame, text="Security Features ")
                #     labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                #          padx=5, pady=5, ipadx=5, ipady=5)     
                #     myrow = myrow +1
                #     self.security_features_lbl1 = Label(labelframe1, text="Securuty Features Byte(HEX)")
                #     self.security_features_lbl1.grid( row = myrow, sticky=W)
                #     self.security_features_var.trace("w", self.security_features_clearcontentvalue_2)
                #     self.security_features_bar0=Entry(labelframe1)
                #     self.security_features_bar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                #     self.security_features_bar0["textvariable"] = self.security_features_var
                #     self.security_features_bar0.bind("<Enter>",self.security_features_clearcontentvalue) 
                #     self.security_features_var.set(0)       
                    # self.Rollbl = Label(labelframe1, text="Rollback Protection Feature")
                    # self.Rollbl.grid( row = myrow, sticky=W,pady=0, padx=1)
                    # self.RollR1 = Radiobutton(labelframe1, text="Enable", variable=self.Rollvar, value=1, command=self.Rollsel)
                    # self.RollR1.grid(row=myrow, column = 1, sticky = W )
                    # self.RollR2 = Radiobutton(labelframe1, text="Disable", variable=self.Rollvar, value=0, command=self.Rollsel)
                    # self.RollR2.grid(row=myrow, column = 2, sticky = W,pady=0, padx=1 )
                    # val = self.Rollvar.get()
                    # self.Rollvar.set(val)

                    # #myrow = myrow +1
                    # #self.Rollbackvar = StringVar() 
                    # # self.Rollback = Label(self, text="Rollback Protection (HEX)",state = "normal")
                    # # self.Rollback.grid(row=myrow, sticky=W, pady=0, padx=1)
                    # # self.Rollbackvar.trace("w", self.update2)
                    # # self.Rollbackbar=Entry(self, state="normal")
                    # # self.Rollbackbar.grid(row=myrow, column=1,sticky=W)
                    # # self.Rollbackbar["textvariable"] = self.Rollbackvar
                    # # self.Rollbackbar.bind("<Enter>",self.clearcontentvalue)        

                    # myrow = myrow +1
                    # self.MRollbl = Label(labelframe1, text="Manual Rollback Protection Feature")
                    # self.MRollbl.grid( row = myrow, sticky=W,pady=0, padx=1)
                    # self.MRollR1 = Radiobutton(labelframe1, text="Enable", state="disabled",variable=self.MRollvar, value=1, command=self.MRollsel)
                    # self.MRollR1.grid(row=myrow, column = 1, sticky = W )
                    # self.MRollR2 = Radiobutton(labelframe1, text="Disable", state="disabled",variable=self.MRollvar, value=0, command=self.MRollsel)
                    # self.MRollR2.grid(row=myrow, column = 2, sticky =W,pady=0, padx=1)
                    # val = self.MRollvar.get()
                    # self.MRollvar.set(val)

                    # myrow = myrow +1
                    
                    # self.ecdsabl = Label(labelframe1, text="ECDSA Key Revocation Feature")
                    # self.ecdsabl.grid( row = myrow, sticky=W,pady=0, padx=1)
                    # self.ecdsakeyR1 = Radiobutton(labelframe1, text="Enable", variable=self.ecdsakeyvar, value=1, command=self.ecdsakeysel)
                    # self.ecdsakeyR1.grid(row=myrow, column = 1, sticky = W )
                    # self.ecdsakeyR2 = Radiobutton(labelframe1, text="Disable", variable=self.ecdsakeyvar, value=0, command=self.ecdsakeysel)
                    # self.ecdsakeyR2.grid(row=myrow, column = 2, sticky = W ,pady=0, padx=1)
                    # val = self.ecdsakeyvar.get()
                    # self.ecdsakeyvar.set(val)

                    # #myrow = myrow +1
                    # #self.ecdsabackvar = StringVar() 
                    # # self.ecdsaback = Label(self, text="ECDSA Key Revocation (HEX)",state = "normal")
                    # # self.ecdsaback.grid(row=myrow, sticky=W, pady=0, padx=1)
                    # # self.ecdsabackvar.trace("w", self.update2)
                    # # self.ecdsabackbar=Entry(self, state="normal")
                    # # self.ecdsabackbar.grid(row=myrow, column=1,sticky=W)
                    # # self.ecdsabackbar["textvariable"] = self.ecdsabackvar
                    # # self.ecdsabackbar.bind("<Enter>",self.clearcontentvalue)        

                    # myrow = myrow +1
                    
                    # self.Mecdsabl = Label(labelframe1, text="Manual Key Revocation Feature")
                    # self.Mecdsabl.grid( row = myrow, sticky=W,pady=0, padx=1)
                    # self.MecdsakeyR1 = Radiobutton(labelframe1, text="Enable", state="disabled",variable=self.Mecdsakeyvar, value=1, command=self.Mecdsakeysel)
                    # self.MecdsakeyR1.grid(row=myrow, column = 1, sticky = W )
                    # self.MecdsakeyR2 = Radiobutton(labelframe1, text="Disable", state="disabled",variable=self.Mecdsakeyvar, value=0, command=self.Mecdsakeysel)
                    # self.MecdsakeyR2.grid(row=myrow, column = 2, sticky = W ,pady=0, padx=1)
                    # val = self.Mecdsakeyvar.get()
                    # self.Mecdsakeyvar.set(val)

                    # self.ap1_reset = Label(labelframe1, text="AP_1 Reset Feature")
                    # self.ap1_reset.grid( row = myrow, sticky=W,pady=0, padx=1)
                    # self.ap1_resetR1 = Radiobutton(labelframe1, text="PP-Low output", variable=self.ap1_reset_var, value=1, command=self.dumm)
                    # self.ap1_resetR1.grid(row=myrow, column = 1, sticky = W )
                    # self.ap1_resetR2 = Radiobutton(labelframe1, text="Hardware Default", variable=self.ap1_reset_var, value=0, command=self.dumm)
                    # self.ap1_resetR2.grid(row=myrow, column = 2, sticky = W ,pady=0, padx=1)
                    # val = self.ap1_reset_var.get()
                    # self.ap1_reset_var.set(val)

                    # myrow = myrow +1
                    
                    # self.extrst = Label(labelframe1, text="EXTRST Feature")
                    # self.extrst.grid( row = myrow, sticky=W,pady=0, padx=1)
                    # self.extrstR1 = Radiobutton(labelframe1, text="PP-Low output", variable=self.extrst_var, value=1, command=self.dumm)
                    # self.extrstR1.grid(row=myrow, column = 1, sticky = W )
                    # self.extrstR2 = Radiobutton(labelframe1, text="Hardware Default", variable=self.extrst_var, value=0, command=self.dumm)
                    # self.extrstR2.grid(row=myrow, column = 2, sticky = W,pady=0, padx=1 )
                    # val = self.extrst_var.get()
                    # self.extrst_var.set(val)

                    # myrow = myrow +1
                    # #self.ECDHLCKvar = IntVar()
                    # self.securebootlcklbl = Label(labelframe1, text="Write Lock Secureboot ")
                    # self.securebootlcklbl.grid( row = myrow, sticky=W,pady=0, padx=1)
                    # self.securebootlcklbl = Label(labelframe1, text="")
                    # self.securebootlcklbl.grid( row = myrow,column = 1, sticky=E)
                    # self.securebootlckLCK_CB = Checkbutton(labelframe1, variable=self.securebootlckvar, onvalue = 1, offvalue = 0, command=self.dumm)
                    # self.securebootlckLCK_CB.grid(row=myrow, column = 2, sticky = W,pady=0, padx=1 )
                    # val = self.securebootlckvar.get()
                    # self.securebootlckvar.set(val)

                if False == soteria_flag:
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="DICE Features  ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    #self.dicevar = IntVar()
                    self.dice = Label(labelframe1, text="DICE Feature ")
                    self.dice.grid( row = myrow, sticky=W,pady=0, padx=1)
                    self.diceR1 = Radiobutton(labelframe1, text="Enable", variable=self.dicevar, value=1, command=self.dicesel)
                    self.diceR1.grid(row=myrow, column = 1, sticky = W )
                    self.diceR2 = Radiobutton(labelframe1, text="Disable", variable=self.dicevar, value=0, command=self.dicesel)
                    self.diceR2.grid(row=myrow, column = 2, sticky = W ,pady=0, padx=1)
                    val = self.dicevar.get()
                    self.dicevar.set(val)
                    
                    myrow = myrow +1
                    #self.dicevar = IntVar()
                    self.dice_hash = Label(labelframe1, text="DICE Hash select ")
                    self.dice_hash.grid( row = myrow, sticky=W,pady=0, padx=1)
                    self.dice_hash_R1 = Radiobutton(labelframe1, text="SHA-256", variable=self.dice_hash_var, value=0, command=self.dumm)
                    self.dice_hash_R1.grid(row=myrow, column = 1, sticky = W )
                    self.dice_hash_R2 = Radiobutton(labelframe1, text="SHA-384", variable=self.dice_hash_var, value=1, command=self.dumm)
                    self.dice_hash_R2.grid(row=myrow, column = 2, sticky = W ,pady=0, padx=1)
                    val = self.dice_hash_var.get()
                    self.dice_hash_var.set(val)

                # if True == DSW_flag:
                #     myrow = myrow +1
                #     labelframe1 = LabelFrame(frame, text="Features  ")
                #     labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                #          padx=5, pady=5, ipadx=5, ipady=5)
                #     myrow = myrow +1
                #    # self.JTAGvar = IntVar()
                    # self.SUSlbl = Label(labelframe1, text="SUS_5V ")
                    # self.SUSlbl.grid( row = myrow, sticky=W,pady=0, padx=1)
                    # self.SUSR3 = Radiobutton(labelframe1, text="Enable", variable=self.SUSvar, value=1, command=self.SUSsel)
                    # self.SUSR3.grid(row=myrow, column = 1, sticky = W )
                    # self.SUSR4 = Radiobutton(labelframe1, text="Disable", variable=self.SUSvar, value=0, command=self.SUSsel)
                    # self.SUSR4.grid(row=myrow, column = 2, sticky = W ,pady=0, padx=1)  
                    # val = self.SUSvar.get()
                    # self.SUSvar.set(val)
                    #myrow = myrow +1
                    # self.DESWlbl2 = Label(labelframe1, text="DPWROK")
                    # self.DESWlbl2.grid( row = myrow, sticky=W,pady=0, padx=1)
                    # self.DESWR22 = Radiobutton(labelframe1, text="Enable", variable=self.DESWvar, value=1 , command=self.DESWsel)
                    # self.DESWR22.grid(row=myrow, column = 1, sticky = W )
                    # self.DESWR23 = Radiobutton(labelframe1, text="Disable", variable=self.DESWvar, value=0, command=self.DESWsel)
                    # self.DESWR23.grid(row=myrow, column = 2, sticky = W,pady=0, padx=1 )
                    # self.DESWvar.set(0)

                if True == MOB_flag:
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="Mobile Features  ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    self.DSWlbl2 = Label(labelframe1, text="DSW_PWROK")
                    self.DSWlbl2.grid( row = myrow, sticky=W,pady=0, padx=1)
                    self.R22 = Radiobutton(labelframe1, text="Enable", variable=self.DSWvar, value=1 , command=self.DSWsel)
                    self.R22.grid(row=myrow, column = 1, sticky = W )
                    self.R23 = Radiobutton(labelframe1, text="Disable", variable=self.DSWvar, value=0, command=self.DSWsel)
                    self.R23.grid(row=myrow, column = 2, sticky = W,pady=0, padx=1 )
                    self.DSWvar.set(0)
                    
                    myrow = myrow +1
                    self.DSWlbl3 = Label(labelframe1, text="DSW_PWROK GPIO_NO (HEX)",state = "disabled")
                    self.DSWlbl3.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.DSWgpio.trace("w", self.update)
                    self.DSWbar=Entry(labelframe1, state="disabled")
                    self.DSWbar.grid(row=myrow, column=1,sticky=W)
                    self.DSWbar["textvariable"] = self.DSWgpio
                    self.DSWbar.bind("<Enter>",self.clearcontent5)
                    
                if(True == DSW_flag or True == MOB_flag):
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="WatchDog Features  ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    self.WDTbl2 = Label(labelframe1, text="WDT delay " ,state = "disabled")
                    self.WDTbl2.grid( row = myrow, sticky=W)
                    self.WDTEN_CB = Checkbutton(labelframe1, variable=self.WDTENvar, onvalue = 1, offvalue = 0, command=self.WDTENsel,state="disabled")
                    self.WDTEN_CB.grid(row=myrow, column = 0, sticky = E )
                    self.R18 = Radiobutton(labelframe1, text="150 ms",width=4,variable=self.WDTDelay, value=0 ,state = "disabled",command=self.WDTdelayset)
                    self.R18.grid(row=myrow, column = 1, sticky = W )
                    self.R19 = Radiobutton(labelframe1, text="500 ms",variable=self.WDTDelay, value=1 ,state = "disabled",command=self.WDTdelayset)
                    self.R19.grid(row=myrow, column = 1 )
                    self.R20 = Radiobutton(labelframe1, text="1 s", width=2,variable=self.WDTDelay, value=2,state = "disabled" ,command=self.WDTdelayset)
                    self.R20.grid(row=myrow, column = 1,sticky = E )
                    self.R21 = Radiobutton(labelframe1, text="4 s", width=2,variable=self.WDTDelay, value=3,state = "disabled" ,command=self.WDTdelayset)
                    self.R21.grid(row=myrow, column = 2  )
                    self.WDTDelay.set(0)

                    #myrow = myrow +1
                    
                    #self.PRIMgpio_0 = StringVar()
                    # self.PRIM0 = Label(labelframe1, text="PRIM_PWRGD GPIO Select Byte-0/1")
                    # self.PRIM0.grid( row = myrow, sticky=W)
                    # self.PR0 = Radiobutton(labelframe1, text="Enable", variable=self.PRIMvar0, value=1 , command=self.PRIMsel)
                    # self.PR0.grid(row=myrow, column = 1, sticky = W )
                    # self.PR1 = Radiobutton(labelframe1, text="Disable", variable=self.PRIMvar0, value=0, command=self.PRIMsel)
                    # self.PR1.grid(row=myrow, column = 1, sticky = E )
                    # self.PRIMvar0.set(0)
                    
                    # myrow = myrow +1
                    # self.PRIMlbl3 = Label(labelframe1, text="PRIM_PWRGD GPIO_NO (HEX)",state = "disabled")
                    # self.PRIMlbl3.grid(row=myrow, sticky=W, pady=0, padx=1)
                    # self.PRIMgpio_0.trace("w", self.update2)
                    # self.PRIMbar=Entry(labelframe1, state="disabled")
                    # self.PRIMbar.grid(row=myrow, column=1,sticky=W)
                    # self.PRIMbar["textvariable"] = self.PRIMgpio_0
                    # self.PRIMbar.bind("<Enter>",self.clearcontent5)
                    
                    # myrow = myrow +1
                    
                    # #self.PRIMgpio_1 = StringVar()
                    # self.PRIM1 = Label(labelframe1, text="RSMRST GPIO Select Byte-0/1")
                    # self.PRIM1.grid( row = myrow, sticky=W)
                    # self.PR2 = Radiobutton(labelframe1, text="Enable", variable=self.PRIMvar1, value=1 , command=self.PRIMsel1)
                    # self.PR2.grid(row=myrow, column = 1, sticky = W )
                    # self.PR3 = Radiobutton(labelframe1, text="Disable", variable=self.PRIMvar1, value=0, command=self.PRIMsel1)
                    # self.PR3.grid(row=myrow, column = 1, sticky = E )
                    # self.PRIMvar1.set(0)
                    
                    # myrow = myrow +1
                    # self.PRIM1 = Label(labelframe1, text="RSMRST GPIO_NO (HEX)",state = "disabled")
                    # self.PRIM1.grid(row=myrow, sticky=W, pady=0, padx=1)
                    # self.PRIMgpio_1.trace("w", self.update2)
                    # self.PRIMbar1=Entry(labelframe1, state="disabled")
                    # self.PRIMbar1.grid(row=myrow, column=1,sticky=W)
                    # self.PRIMbar1["textvariable"] = self.PRIMgpio_1
                    # self.PRIMbar1.bind("<Enter>",self.clearcontent5)
                

                myrow = myrow +1   
                labelframe1 = LabelFrame(frame, text="Platform Identification  ")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)
                myrow = myrow +1
                self.pb = Label(labelframe1, text="Platform ID  (2-byte)",state = "normal")
                self.pb.grid(row=myrow, sticky=W, pady=0, padx=1)
                self.plat_id.trace("w", self.platform_ID_clearcontentvalue_2)
                self.platfrombar=Entry(labelframe1, state="normal")
                self.platfrombar.grid(row=myrow, column=1,sticky=W)
                self.platfrombar["textvariable"] = self.plat_id
                self.platfrombar.bind("<Enter>",self.platform_ID_clearcontentvalue)        
                self.plat_id.set(0)

                self.prod_debug = StringVar()
                myrow = myrow +1   
                labelframe1 = LabelFrame(frame, text="Production Owner Debug  ")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)
                myrow = myrow +1
                self.pb_1 = Label(labelframe1, text="Production Owner Debug  (1-byte)",state = "normal")
                self.pb_1.grid(row=myrow, sticky=W, pady=0, padx=1)
                self.prod_debug.trace("w", self.prod_debug_clearcontentvalue_2)
                self.prod_debug_bar=Entry(labelframe1, state="normal")
                self.prod_debug_bar.grid(row=myrow, column=1,sticky=W)
                self.prod_debug_bar["textvariable"] = self.prod_debug
                self.prod_debug_bar.bind("<Enter>",self.prod_debug_clearcontentvalue)        
                self.prod_debug.set(0)

                self.otp_rollback_var_0 = StringVar()
                self.otp_rollback_var_1 = StringVar()
                self.otp_rollback_var_2 = StringVar()
                self.otp_rollback_var_3 = StringVar()
                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="Rollback Protection Byte 0-15  ")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=50, ipady=5)
                self.otp_rollback_var_0_lbl2 = Label(labelframe1, text="Rollback Protection Byte 0-3 (HEX)")
                self.otp_rollback_var_0_lbl2.grid(row=myrow, sticky=W, pady=0, padx=1)
                #self.tagAddr=StringVar()
                if "" == self.otp_rollback_var_0.get():
                    self.otp_rollback_var_0.set("00000000")
                self.otp_rollback_var_0.trace("w", self.otp_rollback_var_0_callback)
                self.otp_rollback_var_0_bar=Entry(labelframe1)
                self.otp_rollback_var_0_bar.grid(row=myrow, column=1,sticky=W)
                #lbl = Label(self, text="Hex value - bit[31:2]").grid(row=myrow, column=1,sticky=E, pady=0, padx=1)
                self.otp_rollback_var_0_bar["textvariable"] = self.otp_rollback_var_0
                self.otp_rollback_var_0_bar.bind("<Enter>",self.otp_rollback_var_0_clearcontent5)        

                myrow = myrow +1
                self.otp_rollback_var_1_lbl2 = Label(labelframe1, text="Rollback Protection Byte 4-7 (HEX)")
                self.otp_rollback_var_1_lbl2.grid(row=myrow, sticky=W, pady=0, padx=1)
                #self.tagAddr=StringVar()
                if "" == self.otp_rollback_var_1.get():
                    self.otp_rollback_var_1.set("00000000")
                self.otp_rollback_var_1.trace("w", self.otp_rollback_var_1_callback)
                self.otp_rollback_var_1_bar=Entry(labelframe1)
                self.otp_rollback_var_1_bar.grid(row=myrow, column=1,sticky=W)
                #lbl = Label(self, text="Hex value - bit[31:2]").grid(row=myrow, column=1,sticky=E, pady=0, padx=1)
                self.otp_rollback_var_1_bar["textvariable"] = self.otp_rollback_var_1
                self.otp_rollback_var_1_bar.bind("<Enter>",self.otp_rollback_var_1_clearcontent5)        

                myrow = myrow +1
                self.otp_rollback_var_2_lbl2 = Label(labelframe1, text="Rollback Protection Byte 8-11 (HEX)")
                self.otp_rollback_var_2_lbl2.grid(row=myrow, sticky=W, pady=0, padx=1)
                #self.tagAddr=StringVar()
                if "" == self.otp_rollback_var_2.get():
                    self.otp_rollback_var_2.set("00000000")
                self.otp_rollback_var_2.trace("w", self.otp_rollback_var_2_callback)
                self.otp_rollback_var_2_bar=Entry(labelframe1)
                self.otp_rollback_var_2_bar.grid(row=myrow, column=1,sticky=W)
                #lbl = Label(self, text="Hex value - bit[31:2]").grid(row=myrow, column=1,sticky=E, pady=0, padx=1)
                self.otp_rollback_var_2_bar["textvariable"] = self.otp_rollback_var_2
                self.otp_rollback_var_2_bar.bind("<Enter>",self.otp_rollback_var_2_clearcontent5) 

                myrow = myrow +1
                self.otp_rollback_var_3_lbl2 = Label(labelframe1, text="Rollback Protection Byte 12-15 (HEX)")
                self.otp_rollback_var_3_lbl2.grid(row=myrow, sticky=W, pady=0, padx=1)
                #self.tagAddr=StringVar()
                if "" == self.otp_rollback_var_3.get():
                    self.otp_rollback_var_3.set("00000000")
                self.otp_rollback_var_3.trace("w", self.otp_rollback_var_3_callback)
                self.otp_rollback_var_3_bar=Entry(labelframe1)
                self.otp_rollback_var_3_bar.grid(row=myrow, column=1,sticky=W)
                #lbl = Label(self, text="Hex value - bit[31:2]").grid(row=myrow, column=1,sticky=E, pady=0, padx=1)
                self.otp_rollback_var_3_bar["textvariable"] = self.otp_rollback_var_3
                self.otp_rollback_var_3_bar.bind("<Enter>",self.otp_rollback_var_3_clearcontent5) 


                self.ecdsa_rollback_var_0 = StringVar()
                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="ECDSA Key Revocation   ")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=50, ipady=5)
                self.ecdsa_rollback_var_0_lbl2 = Label(labelframe1, text="ECDSA Key Revocation Byte 0-3 (HEX)")
                self.ecdsa_rollback_var_0_lbl2.grid(row=myrow, sticky=W, pady=0, padx=1)
                #self.tagAddr=StringVar()
                if "" == self.ecdsa_rollback_var_0.get():
                    self.ecdsa_rollback_var_0.set("00000000")
                self.ecdsa_rollback_var_0.trace("w", self.ecdsa_rollback_var_0_callback)
                self.ecdsa_rollback_var_0_bar=Entry(labelframe1)
                self.ecdsa_rollback_var_0_bar.grid(row=myrow, column=1,sticky=W)
                #lbl = Label(self, text="Hex value - bit[31:2]").grid(row=myrow, column=1,sticky=E, pady=0, padx=1)
                self.ecdsa_rollback_var_0_bar["textvariable"] = self.ecdsa_rollback_var_0
                self.ecdsa_rollback_var_0_bar.bind("<Enter>",self.ecdsa_rollback_var_0_clearcontent5)        

                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="OTP CRC Value  ")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=50, ipady=5)
                self.otp_crc_var_lbl2 = Label(labelframe1, text="OTP CRC Value (HEX)")
                self.otp_crc_var_lbl2.grid(row=myrow, sticky=W, pady=0, padx=1)
                #self.tagAddr=StringVar()
                if "" == self.otp_crc_var.get():
                    self.otp_crc_var.set("00000000")
                self.otp_crc_var.trace("w", self.otp_crc_var_callback)
                self.otp_crc_var_bar=Entry(labelframe1)
                self.otp_crc_var_bar.grid(row=myrow, column=1,sticky=W)
                #lbl = Label(self, text="Hex value - bit[31:2]").grid(row=myrow, column=1,sticky=E, pady=0, padx=1)
                self.otp_crc_var_bar["textvariable"] = self.otp_crc_var
                self.otp_crc_var_bar.bind("<Enter>",self.otp_crc_var_clearcontent5)

                self.security_features_var = StringVar() 
                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="Security Features ")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                   padx=5, pady=5, ipadx=5, ipady=5)     
                myrow = myrow +1
                self.security_features_lbl1 = Label(labelframe1, text="Securuty Features Byte(HEX)")
                self.security_features_lbl1.grid( row = myrow, sticky=W)
                self.security_features_var.trace("w", self.security_features_clearcontentvalue_2)
                self.security_features_bar0=Entry(labelframe1)
                self.security_features_bar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                self.security_features_bar0["textvariable"] = self.security_features_var
                self.security_features_bar0.bind("<Enter>",self.security_features_clearcontentvalue) 
                self.security_features_var.set(0)       

                self.dice_riot_feature_var = StringVar() 
                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="DICE_RIOT & Optional Features")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                   padx=5, pady=5, ipadx=5, ipady=5)     
                myrow = myrow +1
                self.dice_riot_feature_var_lbl1 = Label(labelframe1, text="DICE_RIOT & Optional Features(HEX)(1-Byte)")
                self.dice_riot_feature_var_lbl1.grid( row = myrow, sticky=W)
                self.dice_riot_feature_var.trace("w", self.dice_riot_feature_var_clearcontentvalue_2)
                self.dice_riot_feature_var_bar0=Entry(labelframe1)
                self.dice_riot_feature_var_bar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                self.dice_riot_feature_var_bar0["textvariable"] = self.dice_riot_feature_var
                self.dice_riot_feature_var_bar0.bind("<Enter>",self.dice_riot_feature_var_clearcontentvalue) 
                self.dice_riot_feature_var.set(0)          

                self.crisis_flash_feature_var = StringVar() 
                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="Crisis Flash & Load Failure Recovery")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                   padx=5, pady=5, ipadx=5, ipady=5)     
                myrow = myrow +1
                self.crisis_flash_feature_var_lbl1 = Label(labelframe1, text="Crisis Flash & Load Failure Recovery (HEX)(1-Byte)")
                self.crisis_flash_feature_var_lbl1.grid( row = myrow, sticky=W)
                self.crisis_flash_feature_var.trace("w", self.crisis_flash_feature_var_clearcontentvalue_2)
                self.crisis_flash_feature_var_bar0=Entry(labelframe1)
                self.crisis_flash_feature_var_bar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                self.crisis_flash_feature_var_bar0["textvariable"] = self.crisis_flash_feature_var
                self.crisis_flash_feature_var_bar0.bind("<Enter>",self.crisis_flash_feature_var_clearcontentvalue) 
                self.crisis_flash_feature_var.set(0)  

                self.optional_feature_var = StringVar() 
                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="Optional Features")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                   padx=5, pady=5, ipadx=5, ipady=5)     
                myrow = myrow +1
                self.optional_feature_var_lbl1 = Label(labelframe1, text="Optional Features (HEX)(1-Byte)")
                self.optional_feature_var_lbl1.grid( row = myrow, sticky=W)
                self.optional_feature_var.trace("w", self.optional_feature_var_clearcontentvalue_2)
                self.optional_feature_var_bar0=Entry(labelframe1)
                self.optional_feature_var_bar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                self.optional_feature_var_bar0["textvariable"] = self.optional_feature_var
                self.optional_feature_var_bar0.bind("<Enter>",self.optional_feature_var_clearcontentvalue) 
                self.optional_feature_var.set(0)  

                self.secure_boot_var = StringVar()
                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="Secure Boot Features  ")
                labelframe1.grid( row = myrow,sticky=W,column = 0)
                myrow = myrow +1
                self.secure_boot_var_lb = Label(labelframe1, text="Secure Boot   (1-byte) (HEX)",state = "normal")
                self.secure_boot_var_lb.grid(row=myrow, sticky=W, pady=0, padx=1)
                self.secure_boot_var.trace("w", self.secure_boot_clearcontentvalue_2)
                self.secure_boot_var_lb_bar=Entry(labelframe1, state="normal")
                self.secure_boot_var_lb_bar.grid(row=myrow, column=1,sticky=W)
                self.secure_boot_var_lb_bar["textvariable"] = self.secure_boot_var
                self.secure_boot_var_lb_bar.bind("<Enter>",self.secure_boot_clearcontentvalue)        
                self.secure_boot_var.set(0)
                
                self.custom_features_var = StringVar()
                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="Custom Features ")
                labelframe1.grid( row = myrow,sticky=W,column = 0)
                myrow = myrow +1
                self.custom_features_var_lb = Label(labelframe1, text="Custom Features   (1-byte) (HEX)",state = "normal")
                self.custom_features_var_lb.grid(row=myrow, sticky=W, pady=0, padx=1)
                self.custom_features_var.trace("w", self.custom_features_var_clearcontentvalue_2)
                self.custom_features_var_lb_bar=Entry(labelframe1, state="normal")
                self.custom_features_var_lb_bar.grid(row=myrow, column=1,sticky=W)
                self.custom_features_var_lb_bar["textvariable"] = self.custom_features_var
                self.custom_features_var_lb_bar.bind("<Enter>",self.custom_features_var_clearcontentvalue)        
                self.custom_features_var.set(0)        

                self.crisis_mode_var = StringVar()
                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="Crisis Mode ")
                labelframe1.grid( row = myrow,sticky=W,column = 0)
                myrow = myrow +1
                self.crisis_mode_var_lb = Label(labelframe1, text="Crisis Mode   (1-byte) (HEX)",state = "normal")
                self.crisis_mode_var_lb.grid(row=myrow, sticky=W, pady=0, padx=1)
                self.crisis_mode_var.trace("w", self.crisis_mode_var_clearcontentvalue_2)
                self.crisis_mode_var_lb_bar=Entry(labelframe1, state="normal")
                self.crisis_mode_var_lb_bar.grid(row=myrow, column=1,sticky=W)
                self.crisis_mode_var_lb_bar["textvariable"] = self.crisis_mode_var
                self.crisis_mode_var_lb_bar.bind("<Enter>",self.crisis_mode_var_clearcontentvalue)        
                self.crisis_mode_var.set(0)
                # myrow = myrow +1
                # labelframe1 = LabelFrame(frame, text="Secureboot G2 Features to Lock  ")
                # labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                #          padx=5, pady=5, ipadx=5, ipady=5)
                # myrow = myrow +1
                # #self.ECDHLCKvar = IntVar()
                # self.sg2lbl = Label(labelframe1, text="Write Lock Secureboot G2 Features")
                # self.sg2lbl.grid( row = myrow, sticky=W)
                # self.sg2lbl = Label(labelframe1, text="")
                # self.sg2lbl.grid( row = myrow,column = 1, sticky=E)
                # self.sg2_CB = Checkbutton(labelframe1, variable=self.sg2lckvar, onvalue = 1, offvalue = 0, command=self.dumm)
                # self.sg2_CB.grid(row=myrow, column = 1, sticky = W )
                # val = self.sg2lckvar.get()
                # self.sg2lckvar.set(val)

                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="TAG 0/1/Flash Components 1/CR_FLASH TAG  Base Address - Byte 0-3   ")
                labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)
                myrow = myrow +1
               # self.TAGvar = IntVar()
                self.TAGlbl1 = Label(labelframe1, text="Use Alternate Tag0 Location ")
                self.TAGlbl1.grid( row = myrow, sticky=W)
                self.CB2 = Checkbutton(labelframe1, variable=self.TAGvar, onvalue = 1, offvalue = 0, command=self.TAG0sel)
                self.CB2.grid(row=myrow, column = 1, sticky = W )
                
                myrow = myrow +1
                self.TAGlbl2 = Label(labelframe1, text="TAG0 SPI Address Pointer (HEX)",state="disabled")
                self.TAGlbl2.grid(row=myrow, sticky=W, pady=0, padx=1)
                #self.tagAddr=StringVar()
                if "" == self.tagAddr.get():
                    self.tagAddr.set("00000000")
                self.tagAddr.trace("w", self.callback)
                self.tagbar=Entry(labelframe1, state="disabled")
                self.tagbar.grid(row=myrow, column=1,sticky=W)
                #lbl = Label(self, text="Hex value - bit[31:2]").grid(row=myrow, column=1,sticky=E, pady=0, padx=1)
                self.tagbar["textvariable"] = self.tagAddr
                self.tagbar.bind("<Enter>",self.clearcontent5)

                myrow = myrow +1
                
                self.Tagflashvar_0bl = Label(labelframe1, text="TAG0 Flash Component ",state="disabled")
                self.Tagflashvar_0bl.grid( row = myrow, sticky=W)
                self.Tagflashvar_0_R1 = Radiobutton(labelframe1, text="Comp 1", variable=self.Tagflashvar_0,state="disabled", value=1, command=self.dumm)
                self.Tagflashvar_0_R1.grid(row=myrow, column = 1, sticky = W )
                self.Tagflashvar_0_R2 = Radiobutton(labelframe1, text="Comp 0", variable=self.Tagflashvar_0,state="disabled", value=0, command=self.dumm)
                self.Tagflashvar_0_R2.grid(row=myrow, column = 1, sticky = E )
                val = self.Tagflashvar_0.get()
                self.Tagflashvar_0.set(val)

                myrow = myrow +1
                val = ["0","1"]
                
                # self.tagflash0l1=Label(labelframe1,text="TAG0 Flash [0] ",state="disabled")
                # self.tagflash0l1.grid(column=0, row=myrow,sticky=W)
                # self.tag_flash_0_cb_0 = Radiobutton(labelframe1, text="Enable ", variable=self.Tagflashvar_2,state="disabled", value=1, command=self.tagflashkeysel0)
                # self.tag_flash_0_cb_0.grid(row=myrow, column = 1, sticky = W )
                # self.tag_flash_0_cb_1 = Radiobutton(labelframe1, text="Disable ", variable=self.Tagflashvar_2,state="disabled", value=0, command=self.tagflashkeysel0)
                # self.tag_flash_0_cb_1.grid(row=myrow, column = 1, sticky = E )
                # val = self.Tagflashvar_2.get()
                # self.Tagflashvar_2.set(val)
                # self.tag_flash_0_cb=ttk.Combobox(self,values=val,width=10,state="disabled",command=self.combokeysel)
                # self.tag_flash_0_cb.grid(column=1, row=myrow,sticky = W)
                # self.tag_flash_0_cb.current(0)

                myrow = myrow +1
                #self.TAGvar_1 = IntVar()
                self.TAG_1_lbl1 = Label(labelframe1, text="Tag1 Alternate location ")
                self.TAG_1_lbl1.grid( row = myrow, sticky=W)
                self.CB2_1 = Checkbutton(labelframe1, variable=self.TAGvar_1, onvalue = 1, offvalue = 0, command=self.TAG1sel)
                self.CB2_1.grid(row=myrow, column = 1, sticky = W )

                myrow = myrow +1
                self.TAGlbl23 = Label(labelframe1, text="TAG1 SPI Address Pointer (HEX)",state="disabled")
                self.TAGlbl23.grid(row=myrow, sticky=W, pady=0, padx=1)
                #self.tagAddr=StringVar()
                if "" == self.tagAddr1.get():
                    self.tagAddr1.set("00000000")
                self.tagAddr1.trace("w", self.callback1)
                self.tagbar1=Entry(labelframe1, state="disabled")
                self.tagbar1.grid(row=myrow, column=1,sticky=W)
                #lbl = Label(self, text="Hex value - bit[31:2]").grid(row=myrow, column=1,sticky=E, pady=0, padx=1)
                self.tagbar1["textvariable"] = self.tagAddr1
                self.tagbar1.bind("<Enter>",self.clearcontenttag1)

                myrow = myrow +1
                
                self.Tagflashvar_1bl = Label(labelframe1, text="TAG1 Flash Component",state="disabled")
                self.Tagflashvar_1bl.grid( row = myrow, sticky=W)
                self.Tagflashvar_1_R1 = Radiobutton(labelframe1, text="Comp 1", variable=self.Tagflashvar_1,state="disabled", value=1, command=self.dumm)
                self.Tagflashvar_1_R1.grid(row=myrow, column = 1, sticky = W )
                self.Tagflashvar_1_R2 = Radiobutton(labelframe1, text="Comp 0", variable=self.Tagflashvar_1, value=0, state="disabled",command=self.dumm)
                self.Tagflashvar_1_R2.grid(row=myrow, column = 1, sticky = E )
                val = self.Tagflashvar_1.get()
                self.Tagflashvar_1.set(val)

                # myrow = myrow +1
                # val = ["0","1"]
                
                # self.tagflash1l1=Label(labelframe1,text="TAG1 Flash [0] ",state="disabled")
                # self.tagflash1l1.grid(column=0, row=myrow,sticky=W)
                # self.tag_flash_0_cb_2 = Radiobutton(labelframe1, text="Enable ", variable=self.Tagflashvar_3,state="disabled", value=1, command=self.dumm)
                # self.tag_flash_0_cb_2.grid(row=myrow, column = 1, sticky = W )
                # self.tag_flash_0_cb_3 = Radiobutton(labelframe1, text="Disable ", variable=self.Tagflashvar_3,state="disabled", value=0, command=self.dumm)
                # self.tag_flash_0_cb_3.grid(row=myrow, column = 1, sticky = E )
                # val = self.Tagflashvar_3.get()
                # self.Tagflashvar_3.set(val)
                # self.tag_flash_1_cb=ttk.Combobox(self,values=val,width=10,state="disabled")
                # self.tag_flash_1_cb.grid(column=1, row=myrow,sticky = W)
                # self.tag_flash_1_cb.current(0)

                #myrow = myrow +1
                # labelframe1 = LabelFrame(frame, text="Flash Components 1   ")
                # labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                #          padx=5, pady=5, ipadx=5, ipady=5)
                myrow = myrow +1
                
                self.flashcomp1lbl = Label(labelframe1, text="Flash Comp 1 Base Address (HEX)",state = "normal",)
                self.flashcomp1lbl.grid(row=myrow, sticky=W, pady=0, padx=1)
                self.flashcomp1.trace("w", self.flash_clearcontent4_update2)
                self.flashcomp1bar0=Entry(labelframe1, state="normal")
                self.flashcomp1bar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                self.flashcomp1bar0["textvariable"] = self.flashcomp1
                self.flashcomp1bar0.bind("<Enter>",self.flash_clearcontent4) 
                self.flashcomp1.set(0)        

                self.cr_flashcomp1 = StringVar()
                myrow = myrow +1
                
                self.cr_flashcomp1_lbl = Label(labelframe1, text="CR_FLASH TAG  Base Address - Byte (0-3) (HEX)(4-byte)",state = "normal",)
                self.cr_flashcomp1_lbl.grid(row=myrow, sticky=W, pady=0, padx=1)
                self.cr_flashcomp1.trace("w", self.cr_flashcomp1_clearcontent4_update2)
                self.cr_flashcomp1_bar0=Entry(labelframe1, state="normal")
                self.cr_flashcomp1_bar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                self.cr_flashcomp1_bar0["textvariable"] = self.cr_flashcomp1
                self.cr_flashcomp1_bar0.bind("<Enter>",self.cr_flashcomp1_clearcontent4) 
                self.cr_flashcomp1.set(0)

                # myrow = myrow +1
                # #self.ECDHLCKvar = IntVar()
                # self.flashlcklbl = Label(labelframe1, text="Write Lock TagX BA/Flash Comp1 BA")
                # self.flashlcklbl.grid( row = myrow, sticky=W)
                # self.flashlcklbl = Label(labelframe1, text="")
                # self.flashlcklbl.grid( row = myrow,column = 1, sticky=E)
                # self.flashlck_CB = Checkbutton(labelframe1, variable=self.flashlckvar, onvalue = 1, offvalue = 0, command=self.dumm)
                # self.flashlck_CB.grid(row=myrow, column = 1, sticky = W )
                # val = self.flashlckvar.get()
                # self.flashlckvar.set(val)

                myrow = myrow +1
                labelframe2 = LabelFrame(frame, text="SHA384(PlatKPUB) Generation")
                labelframe2.grid( row = myrow,columnspan=7, sticky='W', \
                         padx=5, pady=5, ipadx=5, ipady=5)        

                myrow = myrow +1 

                self.plat_ECCP384var = IntVar()
                self.plat_ECCP384lbl = Label(labelframe2, text="SHA384(PlatKPUB) Hash ",state = "normal")
                self.plat_ECCP384lbl.grid( row = myrow, sticky=W)
                self.plat_ECCR11 = Radiobutton(labelframe2, text="Generate", variable=self.plat_ECCP384var, value=1, state = "normal",command=  self.plat_ECCP384sel)
                self.plat_ECCR11.grid(row=myrow, column = 1, sticky = W )
                self.plat_ECCR12 = Radiobutton(labelframe2, text="Not Generate", variable=self.plat_ECCP384var, value=0, state = "normal",command=self.plat_ECCP384sel)
                self.plat_ECCR12.grid(row=myrow, column = 2, sticky = W )
                val = self.plat_ECCP384var.get()
                self.plat_ECCP384var.set(val)

                myrow = myrow +1
                self.plat_ecdsa_sha384_key_lbl = Label(labelframe2, state="normal",text="SHA384(PlatKPUB) Hash Bin").grid(sticky=W, pady=0, padx=1)
                self.plat_ecdsa_sha384_key_hash_bin=StringVar()
                self.plat_ecdsa_sha384_key_outdirbar=Entry(labelframe2,state="normal")
                self.plat_ecdsa_sha384_key_outdirbar.grid(row=myrow, column=1,sticky=W)
                self.plat_ecdsa_sha384_key_outdirbar["textvariable"] = self.plat_ecdsa_sha384_key_hash_bin
                self.plat_ecdsa_sha384_key_outdirbar.bind("<Enter>")
                self.plat_ecdsa_sha384_key_hash_button= Button(labelframe2,text="Browse",width = 12, command=self.plat_hashbrowsefldr_1,state="normal")
                self.plat_ecdsa_sha384_key_hash_button.grid(row=myrow, column=2, sticky=W, pady=0, padx=1)
                
                if True:
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="Write Lock Byte [3-0]  ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                             padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    self.otp_write_lock_var_0 = IntVar()
                    self.otp_write_lock_lbl_0 = Label(labelframe1, text="Write Lock Byte [3-0] Enable")
                    self.otp_write_lock_lbl_0.grid( row = myrow, sticky=W)
                    self.otp_write_lock_lbl_0 = Label(labelframe1, text="")
                    self.otp_write_lock_lbl_0.grid( row = myrow,column = 1, sticky=E)
                    self.otp_write_lock_CB_0 = Checkbutton(labelframe1, variable=self.otp_write_lock_var_0, onvalue = 1, offvalue = 0, command=self.otpwritelcksel)#,state="disabled")
                    self.otp_write_lock_CB_0.grid(row=myrow, column = 1, sticky = W )
                    val = self.otp_write_lock_var_0.get()
                    self.otp_write_lock_var_0.set(val)

                    myrow = myrow +1   
                    self.otp_write_lock_byte_var_0 = StringVar()
                    self.otp_write_lock_byte_0 = Label(labelframe1, text="Write Lock Byte [3-0](HEX)(4-byte)  ",state = "disabled")
                    self.otp_write_lock_byte_0.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.otp_write_lock_byte_var_0.trace("w", self.otp_write_lock_clearcontentvalue_2)
                    self.otp_write_lock_byte_0_bar=Entry(labelframe1, state="disabled")
                    self.otp_write_lock_byte_0_bar.grid(row=myrow, column=1,sticky=W)
                    self.otp_write_lock_byte_0_bar["textvariable"] = self.otp_write_lock_byte_var_0
                    self.otp_write_lock_byte_0_bar.bind("<Enter>",self.otp_write_lock_clearcontentvalue) 

                if True:
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="Read Lock Byte [3-0]  ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                             padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    #self.otp_read_lock_var_0 = IntVar()
                    self.otp_read_lock_lbl_0 = Label(labelframe1, text="Read Lock Byte [3-0] Enable")
                    self.otp_read_lock_lbl_0.grid( row = myrow, sticky=W)
                    self.otp_read_lock_lbl_0 = Label(labelframe1, text="")
                    self.otp_read_lock_lbl_0.grid( row = myrow,column = 1, sticky=E)
                    self.otp_read_lock_CB_0 = Checkbutton(labelframe1, variable=self.otp_read_lock_var_0, onvalue = 1, offvalue = 0, command=self.otpreadlcksel)#,state="disabled")
                    self.otp_read_lock_CB_0.grid(row=myrow, column = 1, sticky = W )
                    val = self.otp_read_lock_var_0.get()
                    self.otp_read_lock_var_0.set(val)

                    myrow = myrow +1   
                    #self.otp_read_lock_byte_var_0 = StringVar()
                    self.otp_read_lock_byte_0 = Label(labelframe1, text="Read Lock Byte [3-0](HEX)(4-byte)  ",state = "disabled")
                    self.otp_read_lock_byte_0.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.otp_read_lock_byte_var_0.trace("w", self.otp_read_lock_clearcontentvalue_2)
                    self.otp_read_lock_byte_0_bar=Entry(labelframe1, state="disabled")
                    self.otp_read_lock_byte_0_bar.grid(row=myrow, column=1,sticky=W)
                    self.otp_read_lock_byte_0_bar["textvariable"] = self.otp_read_lock_byte_var_0
                    self.otp_read_lock_byte_0_bar.bind("<Enter>",self.otp_read_lock_clearcontentvalue)

                if True:
                    self.otp_write_secure_lock_byte = StringVar()
                    self.otp_write_secure_lock = IntVar()
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="OTP WRITE SECURE_LOCK ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                             padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    #self.otp_read_lock_var_0 = IntVar()
                    self.otp_write_secure_lock_lbl_0 = Label(labelframe1, text="OTP WRITE SECURE_LOCK Enable ")
                    self.otp_write_secure_lock_lbl_0.grid( row = myrow, sticky=W)
                    self.otp_write_secure_lock_lbl_0 = Label(labelframe1, text="")
                    self.otp_write_secure_lock_lbl_0.grid( row = myrow,column = 1, sticky=E)
                    self.otp_write_secure_lock_CB_0 = Checkbutton(labelframe1, variable=self.otp_write_secure_lock, onvalue = 1, offvalue = 0, command=self.otp_write_secure_lock_sel)#,state="disabled")
                    self.otp_write_secure_lock_CB_0.grid(row=myrow, column = 1, sticky = W )
                    val = self.otp_write_secure_lock.get()
                    self.otp_write_secure_lock.set(val)

                    myrow = myrow +1   
                    #self.otp_read_lock_byte_var_0 = StringVar()
                    self.otp_write_secure_lock_byte_lb_0 = Label(labelframe1, text="OTP WRITE SECURE_LOCK (HEX)(1-byte)  ",state = "disabled")
                    self.otp_write_secure_lock_byte_lb_0.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.otp_write_secure_lock_byte.trace("w", self.otp_write_secure_lock_byte_clearcontentvalue_2)
                    self.otp_write_secure_lock_byte_bar=Entry(labelframe1, state="disabled")
                    self.otp_write_secure_lock_byte_bar.grid(row=myrow, column=1,sticky=W)
                    self.otp_write_secure_lock_byte_bar["textvariable"] = self.otp_write_secure_lock_byte
                    self.otp_write_secure_lock_byte_bar.bind("<Enter>",self.otp_write_secure_lock_byte_clearcontentvalue)

                if True:
                    self.otp_read_secure_lock_byte = StringVar()
                    self.otp_read_secure_lock = IntVar()
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="OTP READ SECURE_LOCK ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                             padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    #self.otp_read_lock_var_0 = IntVar()
                    self.otp_read_secure_lock_lbl_0 = Label(labelframe1, text="OTP READ SECURE_LOCK Enable ")
                    self.otp_read_secure_lock_lbl_0.grid( row = myrow, sticky=W)
                    self.otp_read_secure_lock_lbl_0 = Label(labelframe1, text="")
                    self.otp_read_secure_lock_lbl_0.grid( row = myrow,column = 1, sticky=E)
                    self.otp_read_secure_lock_CB_0 = Checkbutton(labelframe1, variable=self.otp_read_secure_lock, onvalue = 1, offvalue = 0, command=self.otp_read_secure_lock_sel)#,state="disabled")
                    self.otp_read_secure_lock_CB_0.grid(row=myrow, column = 1, sticky = W )
                    val = self.otp_read_secure_lock.get()
                    self.otp_read_secure_lock.set(val)

                    myrow = myrow +1   
                    #self.otp_read_lock_byte_var_0 = StringVar()
                    self.otp_read_secure_lock_byte_lb_0 = Label(labelframe1, text="OTP READ SECURE_LOCK (HEX)(1-byte)  ",state = "disabled")
                    self.otp_read_secure_lock_byte_lb_0.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.otp_read_secure_lock_byte.trace("w", self.otp_read_secure_lock_byte_clearcontentvalue_2)
                    self.otp_read_secure_lock_byte_bar=Entry(labelframe1, state="disabled")
                    self.otp_read_secure_lock_byte_bar.grid(row=myrow, column=1,sticky=W)
                    self.otp_read_secure_lock_byte_bar["textvariable"] = self.otp_read_secure_lock_byte
                    self.otp_read_secure_lock_byte_bar.bind("<Enter>",self.otp_read_secure_lock_byte_clearcontentvalue)

                if True:
                    self.cfg_lock_byte_0 = IntVar()
                    self.cfg_lock_byte_0_val = StringVar()
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="CFG_LOCK Byte 0 ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                             padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    #self.otp_read_lock_var_0 = IntVar()
                    self.cfg_lock_byte_0_lbl_0 = Label(labelframe1, text="CFG_LOCK Byte 0 Enable ")
                    self.cfg_lock_byte_0_lbl_0.grid( row = myrow, sticky=W)
                    self.cfg_lock_byte_0_lbl_0 = Label(labelframe1, text="")    
                    self.cfg_lock_byte_0_lbl_0.grid( row = myrow,column = 1, sticky=E)
                    self.cfg_lock_byte_0_CB_0 = Checkbutton(labelframe1, variable=self.cfg_lock_byte_0, onvalue = 1, offvalue = 0, command=self.cfg_lock_byte_0_sel)#,state="disabled")
                    self.cfg_lock_byte_0_CB_0.grid(row=myrow, column = 1, sticky = W )
                    val = self.cfg_lock_byte_0.get()
                    self.cfg_lock_byte_0.set(val)

                    myrow = myrow +1   
                    #self.otp_read_lock_byte_var_0 = StringVar()
                    self.cfg_lock_byte_0_val_lb_0 = Label(labelframe1, text="CFG_LOCK Byte 0 (HEX)(1-byte)  ",state = "disabled")
                    self.cfg_lock_byte_0_val_lb_0.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.cfg_lock_byte_0_val.trace("w", self.cfg_lock_byte_0_val_clearcontentvalue_2)
                    self.cfg_lock_byte_0_val_bar=Entry(labelframe1, state="disabled")
                    self.cfg_lock_byte_0_val_bar.grid(row=myrow, column=1,sticky=W)
                    self.cfg_lock_byte_0_val_bar["textvariable"] = self.cfg_lock_byte_0_val
                    self.cfg_lock_byte_0_val_bar.bind("<Enter>",self.cfg_lock_byte_0_val_clearcontentvalue)
                
                if True:
                    self.cfg_lock_byte_1 = IntVar()
                    self.cfg_lock_byte_1_val = StringVar()
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="CFG_LOCK Byte 1 ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                             padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    #self.otp_read_lock_var_0 = IntVar()
                    self.cfg_lock_byte_1_lbl_0 = Label(labelframe1, text="CFG_LOCK Byte 1 Enable ")
                    self.cfg_lock_byte_1_lbl_0.grid( row = myrow, sticky=W)
                    self.cfg_lock_byte_1_lbl_0 = Label(labelframe1, text="")
                    self.cfg_lock_byte_1_lbl_0.grid( row = myrow,column = 1, sticky=E)
                    self.cfg_lock_byte_1_CB_0 = Checkbutton(labelframe1, variable=self.cfg_lock_byte_1, onvalue = 1, offvalue = 0, command=self.cfg_lock_byte_1_sel)#,state="disabled")
                    self.cfg_lock_byte_1_CB_0.grid(row=myrow, column = 1, sticky = W )
                    val = self.cfg_lock_byte_1.get()
                    self.cfg_lock_byte_1.set(val)

                    myrow = myrow +1   
                    #self.otp_read_lock_byte_var_0 = StringVar()
                    self.cfg_lock_byte_1_val_lb_0 = Label(labelframe1, text="CFG_LOCK Byte 1 (HEX)(1-byte)  ",state = "disabled")
                    self.cfg_lock_byte_1_val_lb_0.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.cfg_lock_byte_1_val.trace("w", self.cfg_lock_byte_1_val_clearcontentvalue_2)
                    self.cfg_lock_byte_1_val_bar=Entry(labelframe1, state="disabled")
                    self.cfg_lock_byte_1_val_bar.grid(row=myrow, column=1,sticky=W)
                    self.cfg_lock_byte_1_val_bar["textvariable"] = self.cfg_lock_byte_1_val
                    self.cfg_lock_byte_1_val_bar.bind("<Enter>",self.cfg_lock_byte_1_val_clearcontentvalue)

                if True:
                    self.cfg_lock_byte_2 = IntVar()
                    self.cfg_lock_byte_2_val = StringVar()
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="CFG_LOCK Byte 2 ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                             padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    #self.otp_read_lock_var_0 = IntVar()
                    self.cfg_lock_byte_2_lbl_0 = Label(labelframe1, text="CFG_LOCK Byte 2 Enable ")
                    self.cfg_lock_byte_2_lbl_0.grid( row = myrow, sticky=W)
                    self.cfg_lock_byte_2_lbl_0 = Label(labelframe1, text="")
                    self.cfg_lock_byte_2_lbl_0.grid( row = myrow,column = 1, sticky=E)
                    self.cfg_lock_byte_2_CB_0 = Checkbutton(labelframe1, variable=self.cfg_lock_byte_2, onvalue = 1, offvalue = 0, command=self.cfg_lock_byte_2_sel)#,state="disabled")
                    self.cfg_lock_byte_2_CB_0.grid(row=myrow, column = 1, sticky = W )
                    val = self.cfg_lock_byte_2.get()
                    self.cfg_lock_byte_2.set(val)

                    myrow = myrow +1   
                    #self.otp_read_lock_byte_var_0 = StringVar()
                    self.cfg_lock_byte_2_val_lb_0 = Label(labelframe1, text="CFG_LOCK Byte 2 (HEX)(1-byte)  ",state = "disabled")
                    self.cfg_lock_byte_2_val_lb_0.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.cfg_lock_byte_2_val.trace("w", self.cfg_lock_byte_2_val_clearcontentvalue_2)
                    self.cfg_lock_byte_2_val_bar=Entry(labelframe1, state="disabled")
                    self.cfg_lock_byte_2_val_bar.grid(row=myrow, column=1,sticky=W)
                    self.cfg_lock_byte_2_val_bar["textvariable"] = self.cfg_lock_byte_2_val
                    self.cfg_lock_byte_2_val_bar.bind("<Enter>",self.cfg_lock_byte_2_val_clearcontentvalue)        

                if True:
                    self.cfg_lock_byte_3 = IntVar()
                    self.cfg_lock_byte_3_val = StringVar()
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="CFG_LOCK Byte 3 ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                             padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    #self.otp_read_lock_var_0 = IntVar()
                    self.cfg_lock_byte_3_lbl_0 = Label(labelframe1, text="CFG_LOCK Byte 3 Enable ")
                    self.cfg_lock_byte_3_lbl_0.grid( row = myrow, sticky=W)
                    self.cfg_lock_byte_3_lbl_0 = Label(labelframe1, text="")
                    self.cfg_lock_byte_3_lbl_0.grid( row = myrow,column = 1, sticky=E)
                    self.cfg_lock_byte_3_CB_0 = Checkbutton(labelframe1, variable=self.cfg_lock_byte_3, onvalue = 1, offvalue = 0, command=self.cfg_lock_byte_3_sel)#,state="disabled")
                    self.cfg_lock_byte_3_CB_0.grid(row=myrow, column = 1, sticky = W )
                    val = self.cfg_lock_byte_3.get()
                    self.cfg_lock_byte_3.set(val)

                    myrow = myrow +1   
                    #self.otp_read_lock_byte_var_0 = StringVar()
                    self.cfg_lock_byte_3_val_lb_0 = Label(labelframe1, text="CFG_LOCK Byte 3 (HEX)(1-byte)  ",state = "disabled")
                    self.cfg_lock_byte_3_val_lb_0.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.cfg_lock_byte_3_val.trace("w", self.cfg_lock_byte_3_val_clearcontentvalue_2)
                    self.cfg_lock_byte_3_val_bar=Entry(labelframe1, state="disabled")
                    self.cfg_lock_byte_3_val_bar.grid(row=myrow, column=1,sticky=W)
                    self.cfg_lock_byte_3_val_bar["textvariable"] = self.cfg_lock_byte_3_val
                    self.cfg_lock_byte_3_val_bar.bind("<Enter>",self.cfg_lock_byte_3_val_clearcontentvalue)        

                if True:
                    self.cfg_lock_byte_4 = IntVar()
                    self.cfg_lock_byte_4_val = StringVar()
                    myrow = myrow +1
                    labelframe1 = LabelFrame(frame, text="CFG_LOCK Byte 4 ")
                    labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                             padx=5, pady=5, ipadx=5, ipady=5)
                    myrow = myrow +1
                    #self.otp_read_lock_var_0 = IntVar()
                    self.cfg_lock_byte_4_lbl_0 = Label(labelframe1, text="CFG_LOCK Byte 4 Enable ")
                    self.cfg_lock_byte_4_lbl_0.grid( row = myrow, sticky=W)
                    self.cfg_lock_byte_4_lbl_0 = Label(labelframe1, text="")
                    self.cfg_lock_byte_4_lbl_0.grid( row = myrow,column = 1, sticky=E)
                    self.cfg_lock_byte_4_CB_0 = Checkbutton(labelframe1, variable=self.cfg_lock_byte_4, onvalue = 1, offvalue = 0, command=self.cfg_lock_byte_4_sel)#,state="disabled")
                    self.cfg_lock_byte_4_CB_0.grid(row=myrow, column = 1, sticky = W )
                    val = self.cfg_lock_byte_4.get()
                    self.cfg_lock_byte_4.set(val)

                    myrow = myrow +1   
                    #self.otp_read_lock_byte_var_0 = StringVar()
                    self.cfg_lock_byte_4_val_lb_0 = Label(labelframe1, text="CFG_LOCK Byte 4 (HEX)(1-byte)  ",state = "disabled")
                    self.cfg_lock_byte_4_val_lb_0.grid(row=myrow, sticky=W, pady=0, padx=1)
                    self.cfg_lock_byte_4_val.trace("w", self.cfg_lock_byte_4_val_clearcontentvalue_2)
                    self.cfg_lock_byte_4_val_bar=Entry(labelframe1, state="disabled")
                    self.cfg_lock_byte_4_val_bar.grid(row=myrow, column=1,sticky=W)
                    self.cfg_lock_byte_4_val_bar["textvariable"] = self.cfg_lock_byte_4_val
                    self.cfg_lock_byte_4_val_bar.bind("<Enter>",self.cfg_lock_byte_4_val_clearcontentvalue)
                # if False == soteria_flag:
                #     myrow = myrow +1
                #     labelframe1 = LabelFrame(frame, text="Customer Revision    ")
                #     labelframe1.grid( row = myrow,columnspan=7, sticky='W', \
                #          padx=5, pady=5, ipadx=5, ipady=5) 
                #     myrow = myrow +1
                    
                #     self.customerrevlbl = Label(labelframe1, text="Customer Revision (HEX)",state = "normal")
                #     self.customerrevlbl.grid(row=myrow, sticky=W, pady=0, padx=1)
                #     self.customerrev.trace("w", self.update2)
                #     self.customerrevbar0=Entry(labelframe1, state="normal")
                #     self.customerrevbar0.grid(row=myrow, column=1,sticky=W+E,ipady=0, ipadx=40)
                #     self.customerrevbar0["textvariable"] = self.customerrev
                #     self.customerrevbar0.bind("<Enter>",self.clearcontent4) 

                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="Customer Region    ")
                labelframe1.grid( row = myrow,columnspan=3, sticky='W', \
                         pady=0, padx=1,ipadx=1, ipady=0)        
                myrow = myrow +1
             #   self.CUSvar = IntVar()
                self.CUSlbl1 = Label(labelframe1, text="Use Custom space")
                self.CUSlbl1.grid( row = myrow, columnspan=3, sticky='W', \
                         pady=0, padx=1,ipadx=1, ipady=0)
                self.CB3 = Checkbutton(labelframe1, variable=self.CUSvar, onvalue = 1, offvalue = 0, command=self.CUSsel)
                self.CB3.grid(row=myrow, column = 1, columnspan=3, sticky='W', \
                         pady=0, padx=1,ipadx=1, ipady=0)
                val = self.CUSvar.get()
                self.CUSvar.set(val)

                myrow = myrow +1
                lbl = Label(labelframe1, text="Custom input").grid(row=myrow, sticky=W, column=0,pady=0, padx=1,ipadx=1, ipady=0)
               # self.custIDX=StringVar()
                if "" == self.custIDX.get():
                    self.custIDX.set("240")#("C0")
                    #self.custIDX.set("1E0")#("C0")
                self.custIDX.trace("w", self.CusIDXEntryVald) 
                lbl = Label(labelframe1, text="IDX").grid(row=myrow, column=1,sticky=W+E)
                self.custIDXbar=Entry(labelframe1, state="disabled",width = 2)
                self.custIDXbar.grid(row=myrow, column=2,sticky=W+E,pady=0, padx=1,ipadx=1, ipady=0)
                self.custIDXbar["textvariable"] = self.custIDX
                self.custIDXbar.bind("<Enter>")

                self.custDAT=StringVar()
                self.custDAT.set("00")
                self.custDAT.trace("w", self.CusDATEntryVald)
                self.custDATbar=Entry(labelframe1, state="disabled",width = 2)
                self.custDATbar.grid(row=myrow, column=3,sticky=W+E,pady=0, padx=1,ipadx=1, ipady=0)
                lbl = Label(labelframe1, text="Data").grid(row=myrow, column=4,sticky=W+E,pady=0, padx=1,ipadx=1, ipady=0)
                self.custDATbar["textvariable"] = self.custDAT
                self.custDATbar.bind("<Enter>")
                self.Ebutton= Button(labelframe1, text="Enter",width = 5, command=self.Custenter, state="disabled")
                self.Ebutton.grid(row=myrow, column=5, sticky=W,pady=0, padx=1,ipadx=1, ipady=0)
               # self.Hex2Dec = IntVar()
                self.hex = Radiobutton(labelframe1, text="Hex", variable=self.Hex2Dec, value=1, state="disabled", command=self.hex2dec)
                self.hex.grid(row=myrow, column = 6, sticky = W ,pady=0, padx=1,ipadx=1, ipady=0)
                self.dec = Radiobutton(labelframe1, text="Dec", variable=self.Hex2Dec, value=0, state="disabled", command=self.hex2dec)
                self.dec.grid(row=myrow, column = 7, sticky = W ,pady=0, padx=1,ipadx=1, ipady=0)  
                self.Hex2Dec.set(1)
                
                myrow = myrow +1
                lbl = Label(labelframe1, text="Custom input from File").grid(row=myrow, sticky=W, pady=0, padx=1,ipadx=1, ipady=0)
               # self.CustFilekey=StringVar()
                self.CUSTfilebar=Entry(labelframe1,state="disabled")
                self.CUSTfilebar.grid(row=myrow, column=1,sticky=W+E)
                self.CUSTfilebar["textvariable"] = self.CustFilekey
                self.CUSTfilebar.bind("<Enter>")
                self.bbutton2= Button(labelframe1, text="Browse",width = 12, command=self.browse_custom_file, state="disabled")
                self.bbutton2.grid(row=myrow, column=2, sticky=W, pady=0, padx=1,ipadx=1, ipady=0)
                self.ViewCusDButton = Button(labelframe1, text="View",fg="White", bg="grey",state="disabled")
                self.ViewCusDButton.grid(row=myrow, column=1, sticky=E, pady=0, padx=1,ipadx=1, ipady=0)
                self.ViewCusDButton["command"] =self.view_menu



                # myrow = myrow +1
                # self.otp_write_lock_var_1 = IntVar()
                # self.otp_write_lock_lbl_1 = Label(frame, text="Write Lock Byte 1 Enable")
                # self.otp_write_lock_lbl_1.grid( row = myrow, sticky=W)
                # self.otp_write_lock_lbl_1 = Label(frame, text="")
                # self.otp_write_lock_lbl_1.grid( row = myrow,column = 1, sticky=E)
                # self.otp_write_lock_CB_1 = Checkbutton(frame, variable=self.otp_write_lock_var_1, onvalue = 1, offvalue = 0, command=self.ECDSALCKsel,state="disabled")
                # self.otp_write_lock_CB_1.grid(row=myrow, column = 1, sticky = W )
                # val = self.otp_write_lock_var_1.get()
                # self.otp_write_lock_var_1.set(val)

                # myrow = myrow +1   
                # self.otp_write_lock_byte_var_1 = StringVar()
                # self.otp_write_lock_byte_1 = Label(frame, text="Write Lock Byte 1(HEX)  ",state = "normal")
                # self.otp_write_lock_byte_1.grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.otp_write_lock_byte_var_1.trace("w", self.update2)
                # self.otp_write_lock_byte_1_bar=Entry(frame, state="normal")
                # self.otp_write_lock_byte_1_bar.grid(row=myrow, column=1,sticky=W)
                # self.otp_write_lock_byte_1_bar["textvariable"] = self.otp_write_lock_byte_var_1
                # self.otp_write_lock_byte_1_bar.bind("<Enter>",self.clearcontentvalue) 

                # myrow = myrow +1
                # self.otp_write_lock_var_2 = IntVar()
                # self.otp_write_lock_lbl_2 = Label(frame, text="Write Lock Byte 2 Enable")
                # self.otp_write_lock_lbl_2.grid( row = myrow, sticky=W)
                # self.otp_write_lock_lbl_2 = Label(frame, text="")
                # self.otp_write_lock_lbl_2.grid( row = myrow,column = 1, sticky=E)
                # self.otp_write_lock_CB_2 = Checkbutton(frame, variable=self.otp_write_lock_var_2, onvalue = 1, offvalue = 0, command=self.ECDSALCKsel,state="disabled")
                # self.otp_write_lock_CB_2.grid(row=myrow, column = 1, sticky = W )
                # val = self.otp_write_lock_var_2.get()
                # self.otp_write_lock_var_2.set(val)

                # myrow = myrow +1   
                # self.otp_write_lock_byte_var_2 = StringVar()
                # self.otp_write_lock_byte_2 = Label(frame, text="Write Lock Byte 2(HEX)  ",state = "normal")
                # self.otp_write_lock_byte_2.grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.otp_write_lock_byte_var_2.trace("w", self.update2)
                # self.otp_write_lock_byte_2_bar=Entry(frame, state="normal")
                # self.otp_write_lock_byte_2_bar.grid(row=myrow, column=1,sticky=W)
                # self.otp_write_lock_byte_2_bar["textvariable"] = self.otp_write_lock_byte_var_2
                # self.otp_write_lock_byte_2_bar.bind("<Enter>",self.clearcontentvalue)

                # myrow = myrow +1
                # self.otp_write_lock_var_3 = IntVar()
                # self.otp_write_lock_lbl_3 = Label(frame, text="Write Lock Byte 3 Enable")
                # self.otp_write_lock_lbl_3.grid( row = myrow, sticky=W)
                # self.otp_write_lock_lbl_3 = Label(frame, text="")
                # self.otp_write_lock_lbl_3.grid( row = myrow,column = 1, sticky=E)
                # self.otp_write_lock_CB_3 = Checkbutton(frame, variable=self.otp_write_lock_var_3, onvalue = 1, offvalue = 0, command=self.ECDSALCKsel,state="disabled")
                # self.otp_write_lock_CB_3.grid(row=myrow, column = 1, sticky = W )
                # val = self.otp_write_lock_var_3.get()
                # self.otp_write_lock_var_3.set(val)

                # myrow = myrow +1   
                # self.otp_write_lock_byte_var_3 = StringVar()
                # self.otp_write_lock_byte_3 = Label(frame, text="Write Lock Byte 3(HEX)  ",state = "normal")
                # self.otp_write_lock_byte_3.grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.otp_write_lock_byte_var_3.trace("w", self.update2)
                # self.otp_write_lock_byte_3_bar=Entry(frame, state="normal")
                # self.otp_write_lock_byte_3_bar.grid(row=myrow, column=1,sticky=W)
                # self.otp_write_lock_byte_3_bar["textvariable"] = self.otp_write_lock_byte_var_3
                # self.otp_write_lock_byte_3_bar.bind("<Enter>",self.clearcontentvalue)

                myrow = myrow +1
                #self.otp_read_lock_var_0 = IntVar()
                # self.otp_read_lock_lbl_0 = Label(frame, text="Read Lock Byte [3-0] Enable")
                # self.otp_read_lock_lbl_0.grid( row = myrow, sticky=W)
                # self.otp_read_lock_lbl_0 = Label(frame, text="")
                # self.otp_read_lock_lbl_0.grid( row = myrow,column = 1, sticky=E)
                # self.otp_read_lock_CB_0 = Checkbutton(frame, variable=self.otp_read_lock_var_0, onvalue = 1, offvalue = 0, command=self.otpreadlcksel)#,state="disabled")
                # self.otp_read_lock_CB_0.grid(row=myrow, column = 1, sticky = W )
                # val = self.otp_read_lock_var_0.get()
                # self.otp_read_lock_var_0.set(val)

                myrow = myrow +1   
                #self.otp_read_lock_byte_var_0 = StringVar()
                # self.otp_read_lock_byte_0 = Label(frame, text="Read Lock Byte [3-0](HEX)(4-byte)  ",state = "disabled")
                # self.otp_read_lock_byte_0.grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.otp_read_lock_byte_var_0.trace("w", self.update2)
                # self.otp_read_lock_byte_0_bar=Entry(frame, state="disabled")
                # self.otp_read_lock_byte_0_bar.grid(row=myrow, column=1,sticky=W)
                # self.otp_read_lock_byte_0_bar["textvariable"] = self.otp_read_lock_byte_var_0
                # self.otp_read_lock_byte_0_bar.bind("<Enter>",self.clearcontentvalue)

                # myrow = myrow +1
                # self.otp_read_lock_var_1 = IntVar()
                # self.otp_read_lock_lbl_1 = Label(frame, text="Read Lock Byte 1 Enable")
                # self.otp_read_lock_lbl_1.grid( row = myrow, sticky=W)
                # self.otp_read_lock_lbl_1 = Label(frame, text="")
                # self.otp_read_lock_lbl_1.grid( row = myrow,column = 1, sticky=E)
                # self.otp_read_lock_CB_1 = Checkbutton(frame, variable=self.otp_read_lock_var_1, onvalue = 1, offvalue = 0, command=self.ECDSALCKsel,state="disabled")
                # self.otp_read_lock_CB_1.grid(row=myrow, column = 1, sticky = W )
                # val = self.otp_read_lock_var_1.get()
                # self.otp_read_lock_var_1.set(val)

                # myrow = myrow +1   
                # self.otp_read_lock_byte_var_1 = StringVar()
                # self.otp_read_lock_byte_1 = Label(frame, text="Read Lock Byte 1(HEX)  ",state = "normal")
                # self.otp_read_lock_byte_1.grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.otp_read_lock_byte_var_1.trace("w", self.update2)
                # self.otp_read_lock_byte_1_bar=Entry(frame, state="normal")
                # self.otp_read_lock_byte_1_bar.grid(row=myrow, column=1,sticky=W)
                # self.otp_read_lock_byte_1_bar["textvariable"] = self.otp_read_lock_byte_var_1
                # self.otp_read_lock_byte_1_bar.bind("<Enter>",self.clearcontentvalue)

                # myrow = myrow +1
                # self.otp_read_lock_var_2 = IntVar()
                # self.otp_read_lock_lbl_2 = Label(frame, text="Read Lock Byte 2 Enable")
                # self.otp_read_lock_lbl_2.grid( row = myrow, sticky=W)
                # self.otp_read_lock_lbl_2 = Label(frame, text="")
                # self.otp_read_lock_lbl_2.grid( row = myrow,column = 1, sticky=E)
                # self.otp_read_lock_CB_2 = Checkbutton(frame, variable=self.otp_read_lock_var_2, onvalue = 1, offvalue = 0, command=self.ECDSALCKsel,state="disabled")
                # self.otp_read_lock_CB_2.grid(row=myrow, column = 1, sticky = W )
                # val = self.otp_read_lock_var_2.get()
                # self.otp_read_lock_var_2.set(val)

                # myrow = myrow +1   
                # self.otp_read_lock_byte_var_2 = StringVar()
                # self.otp_read_lock_byte_2 = Label(frame, text="Read Lock Byte 2(HEX)  ",state = "normal")
                # self.otp_read_lock_byte_2.grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.otp_read_lock_byte_var_2.trace("w", self.update2)
                # self.otp_read_lock_byte_2_bar=Entry(frame, state="normal")
                # self.otp_read_lock_byte_2_bar.grid(row=myrow, column=1,sticky=W)
                # self.otp_read_lock_byte_2_bar["textvariable"] = self.otp_read_lock_byte_var_2
                # self.otp_read_lock_byte_2_bar.bind("<Enter>",self.clearcontentvalue)

                # myrow = myrow +1
                # self.otp_read_lock_var_3 = IntVar()
                # self.otp_read_lock_lbl_3 = Label(frame, text="Read Lock Byte 3 Enable")
                # self.otp_read_lock_lbl_3.grid( row = myrow, sticky=W)
                # self.otp_read_lock_lbl_3 = Label(frame, text="")
                # self.otp_read_lock_lbl_3.grid( row = myrow,column = 1, sticky=E)
                # self.otp_read_lock_CB_3 = Checkbutton(frame, variable=self.otp_read_lock_var_3, onvalue = 1, offvalue = 0, command=self.ECDSALCKsel,state="disabled")
                # self.otp_read_lock_CB_3.grid(row=myrow, column = 1, sticky = W )
                # val = self.otp_read_lock_var_3.get()
                # self.otp_read_lock_var_3.set(val)

                # myrow = myrow +1   
                # self.otp_read_lock_byte_var_3 = StringVar()
                # self.otp_read_lock_byte_3 = Label(frame, text="Read Lock Byte 3(HEX) ",state = "normal")
                # self.otp_read_lock_byte_3.grid(row=myrow, sticky=W, pady=0, padx=1)
                # self.otp_read_lock_byte_var_3.trace("w", self.update2)
                # self.otp_read_lock_byte_3_bar=Entry(frame, state="normal")
                # self.otp_read_lock_byte_3_bar.grid(row=myrow, column=1,sticky=W)
                # self.otp_read_lock_byte_3_bar["textvariable"] = self.otp_read_lock_byte_var_3
                # self.otp_read_lock_byte_3_bar.bind("<Enter>",self.clearcontentvalue)

                myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="")
                #labelframe1.grid( row = myrow,column=2, sticky='W', \
                #         padx=5, pady=5, ipadx=5, ipady=5)
                labelframe1.grid( row =myrow, sticky='S', \
                         padx=8, pady=8, ipadx=2, ipady=1)
                myrow = myrow +1
                KEYGENButton = Button(labelframe1, text="GENERATE_EFUSE_DATA",fg="White", bg="Green")
                KEYGENButton.grid(row=myrow, column=5, sticky='W', padx=5, pady=2)
               # KEYGENButton["command"] =self.key_gen_
                KEYGENButton["command"] =self.generate_efuse

                HELPButton = Button(labelframe1, text="HELP", bg="green", fg="White")
                HELPButton.grid(row=myrow, column=8, sticky='W', padx=5, pady=2)  
                HELPButton["command"] = self.help_menu

                myrow = myrow +1
                #myrow = myrow +1
                labelframe1 = LabelFrame(frame, text="")
                #labelframe1.grid( row = myrow,column=2, sticky='W', \
                #         padx=5, pady=5, ipadx=5, ipady=5)
                labelframe1.grid( row =myrow, sticky='S', \
                         padx=8, pady=8, ipadx=2, ipady=1)
                myrow = myrow +1
                self.quit = Button(labelframe1, text="QUIT", fg="Red", command=self.quit_window) #self.master.destroy)#self.on_closing)
                self.quit.grid(row=myrow, column=8, sticky='W', padx=5, pady=2)  
                #self.quit.pack(side="bottom")
               # EfuseKGButton = Button(self, text="EFUSE_OUT",fg="White", bg="grey")
               # EfuseKGButton.grid(row=myrow, column=1, sticky=E, pady=0, padx=1)
               # EfuseKGButton["command"] =self.efuse_key_gen_

                #self.quit = Button(frame, text="QUIT", fg="Red", command=self.quit_window) #self.master.destroy)#self.on_closing)
                #self.quit.pack(side="bottom")
                
                cfgfile = "ECDSA_Key_info.ini"
                if (os.path.exists(cfgfile)):
                   os.remove(cfgfile)
                   #os.unlink(cfgfile)
                '''
                self.headerfile = IntVar()
                self.Rad8 = Radiobutton(self, variable=self.headerfile, value=1)
                self.headerfile.set(0)
                self.Rad8.grid(row=myrow, column = 6, sticky = E )
                '''
            def process_efuse_gen_from_ini(self):
                global tool_config
                global custom_data
                global custdatexd
                global sqtpflag
                global MaskVal
                global PatternVal
                global TypeVal
                global MultipleDev
                global error_msg
                global exit_code
                global WDTDelayg
                global UPD_flag
                global DSW_flag
                global soteria_flag
                global soteria_cus_flag
                global dswgpiosel
                global primgpiosel_0
                global headerflag
                global otp_lock_15
                global otp_lock_16
                global otp_lock_17
                global otp_lock_18
                global otp_lock_19
                global otp_lock_20
                global otp_lock_21
                global otp_lock_22
                global otp_lock_23
                global otp_lock_24
                global otp_lock_25
                global otp_lock_26
                global otp_lock_27
                global otp_lock_28
                global otp_lock_29
                global otp_lock_30
                global otp_write_lock_en
                global write_lock_flag_15
                global write_lock_flag_16
                global write_lock_flag_17
                global write_lock_flag_18
                global write_lock_flag_19
                global write_lock_flag_20
                global write_lock_flag_21
                global write_lock_flag_22
                global write_lock_flag_23
                global write_lock_flag_24
                global write_lock_flag_25
                global write_lock_flag_26
                global write_lock_flag_27
                global write_lock_flag_28
                global write_lock_flag_29
                global write_lock_flag_30
                headerflag =1
                config = configparser.ConfigParser()
                ini_file = tool_config
                config.read(ini_file)
                exit_code = 200
                try:
                    try:
                        exit_code = 201
                        outdir = config['OUTPUT']['outdir']
                        if outdir == "":
                            self.outdir.set("")
                        else:
                            self.outdir.set(outdir)
                    except:
                        error_msg = 100
                        self.outdir.set("")
                    try:
                        exit_code = 202
                        ATEvar = config['CHIP_CFG']['ATEvar']
                        ATEvar = ATEvar.lower()
                        if ATEvar == "1" or ATEvar == "true":
                            self.ATEvar.set(1)
                        else:     
                            self.ATEvar.set(0)      
                    except:
                        error_msg = 101
                        self.ATEvar.set(0) 
                        
                    try:
                        exit_code = 203
                        JTAGvar = config['CHIP_CFG']['JTAGDISvar'] 
                        JTAGvar= JTAGvar.lower()
                        if JTAGvar == "1" or JTAGvar == "true" :                 
                            self.JTAGvar.set(1)
                        else:
                            if JTAGvar == "0" or JTAGvar == "false":
                                self.JTAGvar.set(0)
                                print("Jtag zero")
                                self.plat_id.set(0)
                                self.flashcomp1.set(0)
                            else:
                                sys.exit(2)
                    except:
                        error_msg = 102
                        print("JTAGDISvar is not valid , please set '0' for enable,'1' for disable the JTAG")
                        print("Please refer the efuseconfig.ini file for the usage of JTAGDISvar to enable/disable the JTAG")
                        self.JTAGvar.set(0)
                        
                    # try:
                    #     exit_code = 204
                    #     AUTHvar = config['ECDSA']['AUTHENTICATION'] 
                    #     AUTHvar= AUTHvar.lower()    
                    #     if "true" == AUTHvar or AUTHvar == "1":                 
                    #         self.AUTHvar.set(1)
                    #         try:
                    #             exit_code = 205    
                    #             ecdsakey = config['ECDSA']['ecdsakey'] 
                    #             if ecdsakey == "":
                    #                 print("ECDSA filename  is not set ")
                    #                 print("Please refer the efuseconfig.ini file for the usage of ecdsakey filename")
                    #                 sys.exit(2)
                    #             else:
                    #                 self.ecdsakey.set(ecdsakey)
                    #         except:
                    #             error_msg = 103
                    #             print("Enter Authentication Key Filename to generate ")
                    #             self.AUTHvar.set(0)
                    #             sys.exit(2)
                    #         try:
                    #             exit_code = 206
                    #             ecdsapass = config['ECDSA']['ecdsapass']
                    #             if ecdsapass == "":
                    #                 print("ECDSA password  is not set ")
                    #                 print("Please refer the efuseconfig.ini file for the usage of ecdsakey password")
                    #                 sys.exit(2)
                    #             else:
                    #                 self.ecdsapass.set(ecdsapass)
                    #         except:
                    #             error_msg = 104                    
                    #             print("Enter Authentication Key Filename Password Missing")
                    #             self.AUTHvar.set(0)
                    #             sys.exit(2)

                    #         try:   # added by PV
                    #             exit_code = 300
                    #             ECDSALCKvar = config['ECDSA']['ECDSAKeyLock']  
                    #             ECDSALCKvar= ECDSALCKvar.lower()    
                    #             if ECDSALCKvar == "1" or  ECDSALCKvar == "true":
                    #                 self.ECDSALCKvar.set(1)
                    #                 update_efuse_ecdsa_lock = True
                    #             else:
                    #                 self.ECDSALCKvar.set(0)
                    #                 if ECDSALCKvar == "0" or ECDSALCKvar == "false":
                    #                     update_efuse_ecdsa_lock = False
                    #                 else:
                    #                     update_efuse_ecdsa_lock = False
                    #                     sys.exit(2)
                    #         except:
                    #             self.ECDSALCKvar.set(0)
                    #             print("ECDSALCKvar  is not valid one ")
                    #             print("Please refer the efuseconfig.ini file for the usage of ECDSALCKvar to Write lock enable/disable")
                    #             sys.exit(2)
                    #     else:
                    #         if "false" == AUTHvar or AUTHvar == "0":
                    #              self.ECDSALCKvar.set(0)
                    #              update_efuse_ecdsa_lock = False
                    #              self.ECDSALCKvar.set(0) # added by PV
                    #              self.AUTHvar.set(0)
                    #              self.ecdsakey.set("")
                    #              self.ecdsapass.set("")
                    #         else:
                    #              print("AUTHENTICATION  is not valid ")
                    #              self.ECDHPrivLCKvar.set(0)
                    #              update_efuse_ecdsa_lock = False
                    #              print("Please refer the efuseconfig.ini file for the usage of AUTHENTICATION to be enable or disable")
                    #              sys.exit(2)
                    # except:
                    #     if(exit_code == 204):
                    #         error_msg = 105
                    #         self.AUTHvar.set(0)
                    #         self.ecdsakey.set("")
                    #         self.ecdsapass.set("")
                    #     else:
                    #         sys.exit(2)

                    #     if(exit_code ==300):
                    #         error_msg = 400
                    #     else:
                    #         sys.exit(2)
                    # try:
                    #     exit_code = 207
                    #     ENCvar = config['ECDH']['ENCRYPTION']  
                    #     ENCvar= ENCvar.lower()    
                    #     if ENCvar == "1":                
                    #         self.ENCvar.set(1)
                    #         try: 
                    #             exit_code = 208
                    #             ecdhkey = config['ECDH']['ecdhkey'] 
                    #             if ecdhkey == "":
                    #                 print("ecdhkey file  is not set ")
                    #                 print("Please refer the efuseconfig.ini file for the usage of ecdhkey filename to be set")
                    #                 sys.exit(2)
                    #             else:
                    #                 self.ecdhkey.set(ecdhkey)
                    #         except:
                    #             error_msg = 106
                    #             print("Enter Encryption Key Filename to generate ")
                    #             self.ENCvar.set(0)
                    #             sys.exit(2)
                    #         try:
                    #             exit_code = 209
                    #             ecdhpass = config['ECDH']['ecdhpass']
                    #             if ecdhpass == "":
                    #                 print("ecdhpass  is not set ")
                    #                 print("Please refer the efuseconfig.ini file for the usage of ecdhpass to be set")
                    #                 sys.exit(2)
                    #             else:
                    #                 self.ecdhpass.set(ecdhpass)
                    #         except:
                    #             error_msg = 107
                    #             print("Enter Encryption Key Filename Password Missing")
                    #             self.ENCvar.set(0)
                    #             sys.exit(2)
                                
                    #         try:
                    #             exit_code = 239
                    #             ECDHPrivLCKvar = config['ECDH']['ECDHPrivKeyLock']  
                    #             ECDHPrivLCKvar= ECDHPrivLCKvar.lower()    
                    #             if "true" == ECDHPrivLCKvar or ECDHPrivLCKvar == "1":
                    #                 self.ECDHPrivLCKvar.set(1)
                    #                 update_efuse_ecdh_priv_lock = True
                    #             else:
                    #                 if "false" == ECDHPrivLCKvar or ECDHPrivLCKvar == "0":
                    #                     self.ECDHPrivLCKvar.set(0)
                    #                     update_efuse_ecdh_priv_lock = False
                    #                 else:
                    #                     print("ECDHPrivKeyLock  is not valid ")
                    #                     self.ECDHPrivLCKvar.set(0)
                    #                     update_efuse_ecdh_priv_lock = False
                    #                     print("Please refer the efuseconfig.ini file for the usage of ECDHPrivKeyLock to be enable or disable the writelock ")
                    #                     sys.exit(2)
                    #         except:
                    #             self.ECDHPrivLCKvar.set(0)
                    #             sys.exit(2)

                    #         try:
                    #             exit_code = 239
                    #             ECDHPubLCKvar = config['ECDH']['ECDHPubKeyLock']  
                    #             ECDHPubLCKvar= ECDHPubLCKvar.lower()    
                    #             if "true" == ECDHPubLCKvar or ECDHPubLCKvar == "1":
                    #                 self.ECDHPubLCKvar.set(1)
                    #                 update_efuse_ecdh_pub_lock = True
                    #             elif "false" == ECDHPubLCKvar or ECDHPubLCKvar == "0":    
                    #                 self.ECDHPubLCKvar.set(0)
                    #                 update_efuse_ecdh_pub_lock = False
                    #             else:
                    #                 if "false" == ECDHPubLCKvar or ECDHPubLCKvar == "0":
                    #                     self.ECDHPubLCKvar.set(0)
                    #                     update_efuse_ecdh_pub_lock = False
                    #                 else:
                    #                     self.ECDHPubLCKvar.set(0)
                    #                     update_efuse_ecdh_pub_lock = False
                    #                     print("ECDHPubKeyLock  is not valid ")
                    #                     print("Please refer the efuseconfig.ini file for the usage of ECDHPubKeyLock to be enable or disable the writelock")
                    #                     sys.exit(2)
                    #         except:
                    #             self.ECDHPubLCKvar.set(0)
                    #             sys.exit(2)

                    #         try:
                    #             AESvar = config['AES_ENC_MANDATORY']['AESENCbit']
                    #             AESvar= AESvar.lower()    
                    #             if AESvar == "1" or AESvar == "true":
                    #                 self.AEMvar.set(1)
                    #             else:
                    #                 if AESvar == "0" or AESvar == "false":    
                    #                     self.AEMvar.set(0)
                    #                 else:
                    #                     self.AEMvar.set(0)
                    #                     sys.exit(2)
                    #         except:
                    #             self.AEMvar.set(0)
                    #             print("AESENCbit  is not valid ")
                    #             print("Please refer the efuseconfig.ini file for the usage of AESENCbit to be enable or disable AES mandatory enable feature ")
                    #             sys.exit(2)
                    #     elif ENCvar == "0":
                    #             AESvar = config['AES_ENC_MANDATORY']['AESENCbit']
                    #             AESvar= AESvar.lower()
                    #             if AESvar == "1" or AESvar == "true":
                    #                 print("To use AES Mandatory encryption bit ")
                    #                 print("Please select the option of ECDH key or ECDH with encryption to make use of AES Mandatory encryption bit")
                    #                 print("Please refer the efuseconfig.ini file for the usage of AESENCbit to be enable or disable ")
                    #                 sys.exit(2)
                    #     else:
                    #         self.ENCvar.set(0)
                    #         self.ecdhkey.set("")
                    #         self.ecdhpass.set("")
                    # except ValueError:
                    #     error_msg = 109
                    #     self.ENCvar.set(0)
                    #     self.ecdhkey.set("")
                    #     self.ecdhpass.set("") 
                    
                    # if((1 ==self.ENCvar.get()) or  (1 ==self.AUTHvar.get())):
                    #     try: 
                    #         exit_code = 210
                    #         _opensslp = config['DEFAULT']['OPENSSLPATH']
                    #         if ("" == _opensslp):
                    #             print("ERROR: Set Openssl Path OPENSSLPATH")
                    #             sys.exit(2)
                    #         self.opensslpath.set(_opensslp)
                    #         cmd = "del /f /q opensslcfg.ini"
                    #         op = os.system(cmd) 
                    #         with open("opensslcfg.ini","wt+") as conf_f:  
                    #             conf_f.write(_opensslp)
                    #         conf_f.close()

                    #     except:
                    #         error_msg = 110
                    #         print("ERROR: Set Openssl Path OPENSSLPATH")
                    #         sys.exit(2)
                                  
                    # try:
                    #     exit_code = 211
                    #     ENCvar = config['ECDH']['ENCRYPTION']  
                    #     ENCvar= ENCvar.lower()
                    #     ECDHENCvar = config['ECDH_KEY_ENC']['ECDHENCvar'] 
                    #     ECDHENCvar= ECDHENCvar.lower()  
                    #     if ENCvar == "1" and ECDHENCvar =="1":    
                    #         if "true" == ECDHENCvar or ECDHENCvar == "1":                
                    #             self.ECDHENCvar.set(1)
                    #         else:
                    #             if "false" == ECDHENCvar or ECDHENCvar == "0":  
                    #                 self.ECDHENCvar.set(0)
                    #             else:
                    #                 self.ECDHENCvar.set(0)
                    #                 print("ECDHENCvar  is not valid")
                    #                 print("Please refer the efuseconfig.ini file for the usage of ECDHENCvar to be enable or disable encryption feature")
                    #                 sys.exit(2)
                    #     else:
                    #         if ENCvar == "0" and ECDHENCvar =="0":
                    #             self.ECDHENCvar.set(0)
                    #         else:
                    #             self.ECDHENCvar.set(0)
                    #             print("ECDH ENCRYPTION is not set,then set ECDHENCvar=1")
                    #             print("ECDH ENCRYPTION is to be set and to ecrypt the keys use ECDHENCvar=1")
                    #             print("Please refer the efuseconfig.ini file for the usage of ECDHENCvar to be enable or disable encryption feature")
                    #             sys.exit(2)
                    # except ValueError:
                    #     error_msg = 111    
                    #     self.ECDHENCvar.set(0)
                    #     sys.exit(2)        
                    try:
                        exit_code = 212
                        TAGvar0 = config['TAGX_FLASH']['TAGvar0']  
                        TAGvar0= TAGvar0.lower()    
                        if "true" == TAGvar0 or TAGvar0 == "1":
                            self.TAGvar.set(1)
                            try:
                                exit_code = 213
                                tagAddr = config['TAGX_FLASH']['TAGAddr0']  
                                try: 
                                    exit_code = 214
                                    val = int(tagAddr,16)
                                    #if len(tagAddr) >= 5:
                                    #    print("Errot invalid Tag0 Addess") 
                                    #    sys.exit(2)                        
                                    self.tagAddr.set(tagAddr)
                                except:
                                    error_msg = 112
                                    print("Error invalid Tag Addess")
                                    sys.exit(2)    
                            except:
                                error_msg = 113
                                self.TAGvar.set(0)
                                print("Tag0 Address not provided")
                                sys.exit(2)
                            try:
                                exit_code = 213
                                tagAddr = config['TAGX_FLASH']['TAG0flashcomp']  
                                try: 
                                    exit_code = 214
                                    val = int(tagAddr,16)               
                                    self.Tagflashvar_0.set(val)
                                except:
                                    error_msg = 112
                                    print("Error invalid TAG0flashcomp value")
                                    sys.exit(2)    
                            except:
                                error_msg = 113
                                self.TAGvar.set(0)
                                print("TAG0flashcomp not provided")
                                sys.exit(2)
                        else:
                            if "false" == TAGvar0 or TAGvar0 == "0":
                                self.TAGvar.set(0)
                                self.tagAddr.set("")
                                self.Tagflashvar_0.set(0)
                            else:
                                self.TAGvar.set(0)
                                self.tagAddr.set("")
                                self.Tagflashvar_0.set(0)
                                print("Tagvar is not valid")
                                print("Please refer the efuseconfig.ini file for the usage of Tagvar to be enable or disable ")
                                sys.exit(2)
                    except:
                        error_msg = 114
                        self.TAGvar.set(0)
                        self.tagAddr.set("")
                        sys.exit(2)
                    try:
                        exit_code = 212
                        TAGvar1 = config['TAGX_FLASH']['TAGvar1']  
                        TAGvar1= TAGvar1.lower()    
                        if "true" == TAGvar1 or TAGvar1 == "1":
                            #self.TAGvar.set(1)
                            self.TAGvar_1.set(1)
                            try:
                                exit_code = 213
                                tagAddr1 = config['TAGX_FLASH']['TAGAddr1']  
                                try: 
                                    exit_code = 214
                                    val = int(tagAddr1,16)
                                    #if len(tagAddr1) >= 5:
                                    #    print("Errot invalid Tag1 Addess") 
                                    #    sys.exit(2)                        
                                    self.tagAddr1.set(tagAddr1)
                                except:
                                    error_msg = 112
                                    print("Error invalid Tag1 Addess")
                                    sys.exit(2)    
                            except:
                                error_msg = 113
                                self.TAGvar.set(0)
                                print("Tag1 Address not provided")
                                sys.exit(2)
                            try:
                                exit_code = 213
                                tagAddr1 = config['TAGX_FLASH']['TAG1flashcomp']  
                                try: 
                                    exit_code = 214
                                    val = int(tagAddr1,16)               
                                    self.Tagflashvar_1.set(val)
                                except:
                                    error_msg = 112
                                    print("Error invalid TAG0flashcomp value")
                                    sys.exit(2)    
                            except:
                                error_msg = 113
                                self.TAGvar.set(0)
                                print("TAG1flashcomp not provided")
                                sys.exit(2)
                        else:
                            if "false" == TAGvar1 or TAGvar1 == "0":
                                #self.TAGvar.set(0)
                                self.tagAddr1.set("")
                                self.Tagflashvar_1.set(0)
                            else:
                                self.TAGvar.set(0)
                                self.tagAddr1.set("")
                                self.Tagflashvar_1.set(0)
                                print("Tagvar is not valid")
                                print("Please refer the efuseconfig.ini file for the usage of Tagvar to be enable or disable ")
                                sys.exit(2)
                    except:
                        error_msg = 114
                        self.TAGvar.set(0)
                        self.tagAddr.set("")
                        sys.exit(2)   
                    try:
                        exit_code = 203
                        Flashcomp1var = config['TAGX_FLASH']['Flashcomp1'] 
                        #print("Flashcomp1 ",Flashcomp1)
                        #val = int(Flashcomp1,16)  
                        #tag = int(self.flashcomp1.get(),16)
                        #self.flashcomp1.set(val)   
                        try: 
                            exit_code = 214
                            #val = int(Flashcomp1var,16) 
                            val = val & 0XFFFFFF00
                            self.flashcomp1.set(Flashcomp1var)
                            #  tag = int(self.flashcomp1.get(),16)
                             # value = tag & 0XFFFFFF00
                        except:
                            error_msg = 112
                            print("Error invalid Flashcomp1 value")
                            sys.exit(2)           
                    except:
                        error_msg = 102
                        print("Flashcomp1 is not valid ")
                        print("Please refer the efuseconfig.ini file for the usage of Flashcomp1 t")
                        self.flashcomp1.set(0)             
                    try:    
                        exit_code = 215
                        CUSvar = config['CUSTOM_DATA']['CUSvar']
                        CUSvar= CUSvar.lower()    
                        if "true" == CUSvar or CUSvar == "1":                
                            self.CUSvar.set(1)
                            try:
                                exit_code = 216
                                custIDX = config['CUSTOM_DATA']['custIDX']
                                try: 
                                    exit_code = 217
                                    idx = int(custIDX,16)
                                    if idx not in range(576,863+1):#(192, 415+1):#if idx not in range(480,991+1):#(192, 415+1):
                                        print("Errot Custom IDX  custIDX") 
                                        sys.exit(2) 
                                    else:
                                        self.custIDX.set(custIDX)                   
                                except:
                                    error_msg = 115
                                    print("custIDX is out of range")
                                    sys.exit(2)
                            except:
                                error_msg = 116
                                self.custIDX.set("1E0")
                                idx = 672#192#idx = 480#192
                                sys.exit(2)
                            try:    
                                try:
                                    exit_code = 218
                                    CustFilekeyname = config['CUSTOM_DATA']['CustFilekey']
                                    if not os.path.exists(CustFilekeyname):
                                        sys.exit(2)
                                    cmd = "del /f /q CustFilekey.ini"    
                                    op = os.system(cmd) 
                                    with open("CustFilekey.ini","wt+") as conf_f:  
                                        conf_f.write(CustFilekeyname)
                                    conf_f.close()
                                    CustFilekeysplt = CustFilekeyname.split("\\")
                                    self.CustFilekey.set(CustFilekeysplt[-1])
                                    try:
                                        exit_code = 219
                                        CustFilekeyopen = open(CustFilekeyname,"rt+")
                                        # otp_write_lock_var = config['CUSTOM_DATA']['otp_write_lock_en']
                                        # otp_write_lock_var = otp_write_lock_var.lower()
                                        # if "true" == otp_write_lock_var or otp_write_lock_var == "1":
                                        #     otp_write_lock_en = 1
                                        # cust_write_lock_var = config['CUSTOM_DATA']['cust_write_lock_region']
                                        # custom_lock = int(cust_write_lock_var,16)
                                        for line in CustFilekeyopen:
                                            CUSTMDAT = list(line)
                                            CUSTMDAT = CUSTMDAT[0:]
                                            endoff = len(CUSTMDAT)
                                            key = []
                                            for j in range(0,endoff-1,2):
                                                key.append(CUSTMDAT[j]+CUSTMDAT[j+1])
                                            endoff = 991+1 #479+1
                                            #if 1 == self.ECDHENCvar.get():
                                            #    endoff = 415 + 1
                                            for item in key:
                                                if (idx < endoff):
                                                    item = int(item,16)
                                                    temp= ((item<<16) & 0x00FF0000)| idx & 0xFFFF;#0x1FF;
                                                    temp = struct.pack('I',temp)
                                                    once = True
                                                    # if((idx >480 and idx < 511) and (custom_lock & (1<<0))):
                                                    #     otp_lock_15 = 1
                                                    #     write_lock_flag_15 =1
                                                    # if((idx > 511 and idx < 544) and (custom_lock & (1<<1))):
                                                    #     otp_lock_16 = 1
                                                    #     write_lock_flag_16 =1                                                    
                                                    # if((idx >544 and idx < 576) and (custom_lock & (1<<2))):
                                                    #     otp_lock_17 = 1
                                                    #     write_lock_flag_17 =1
                                                    # if((idx >576 and idx < 608) and (custom_lock & (1<<3))):
                                                    #     otp_lock_18 = 1
                                                    #     write_lock_flag_18 =1
                                                    # if((idx > 608 and idx <640) and (custom_lock & (1<<4))):
                                                    #     otp_lock_19 = 1
                                                    #     write_lock_flag_19 =1
                                                    # if((idx >640 and idx < 672) and (custom_lock & (1<<5))):
                                                    #     otp_lock_20 = 1
                                                    #     write_lock_flag_20 =1
                                                    # if((idx >672 and idx < 704) and (custom_lock & (1<<6))):
                                                    #     otp_lock_21 = 1
                                                    #     write_lock_flag_21 =1
                                                    # if((idx >704 and idx < 736) and (custom_lock & (1<<7))):
                                                    #     otp_lock_22 = 1
                                                    #     write_lock_flag_22 =1
                                                    # if((idx >736 and idx < 768) and (custom_lock & (1<<8))):
                                                    #     otp_lock_23 = 1
                                                    #     write_lock_flag_23 =1
                                                    # if((idx >768 and idx < 800) and (custom_lock & (1<<9))):
                                                    #     otp_lock_24 = 1
                                                    #     write_lock_flag_24 =1
                                                    # if((idx >800 and idx < 832) and (custom_lock & (1<<10))):
                                                    #     otp_lock_25 = 1
                                                    #     write_lock_flag_25 =1
                                                    # if((idx >832 and idx < 864) and (custom_lock & (1<<11))):
                                                    #     otp_lock_26 = 1
                                                    #     write_lock_flag_26 =1
                                                    # if((idx >864 and idx < 896) and (custom_lock & (1<<12))):
                                                    #     otp_lock_27 = 1
                                                    #     write_lock_flag_27=1
                                                    # if((idx >896 and idx < 928) and (custom_lock & (1<<13))):
                                                    #     otp_lock_28 = 1
                                                    #     write_lock_flag_28 =1
                                                    # if((idx >928 and idx < 960) and (custom_lock & (1<<14))):
                                                    #     otp_lock_29 = 1
                                                    #     write_lock_flag_29 =1
                                                    # if((idx >960 and idx < 991) and (custom_lock & (1<<15))):
                                                    #     otp_lock_30 = 1
                                                    #     write_lock_flag_30= 1
                                                    for items in custom_data:
                                                        val = (int(binascii.hexlify(items), 16)) & 0xFFFF0000#0xFF010000
                                                        cntval = (int(binascii.hexlify(temp), 16)) & 0xFFFF0000#0xFF010000
                                                        if val == cntval:
                                                            inst = custom_data.index(items)
                                                            custom_data.remove(items )
                                                            custom_data.insert(inst,temp )
                                                            once = False
                                                    if True == once:
                                                        if idx > 991:
                                                            custdatexd = custdatexd + 1
                                                        custom_data.append(temp)
                                                idx = idx + 1
                                            if (idx > 991+1):#479+1): 
                                                custdatexd = True
                                                idx = 991 #479
                                            self.custIDX.set(hex(idx).upper().split('X')[1])
                                    except:
                                        error_msg = 117
                                        sys.exit(2) 
                                except:
                                    error_msg = 118
                                    print("Custom input file not present")
                                    sys.exit(2)
                            except:
                                error_msg = 119
                                print("Custom input file not provided in Config file 'CustFilekey'")
                                sys.exit(2)
                        else:     
                            self.CUSvar.set(0)    
                            self.custIDX.set("")       
                    except ValueError:  
                        error_msg = 120
                        self.CUSvar.set(0)    
                        self.custIDX.set("")     
                    try: 
                        exit_code = 222
                        sqtp_en = config['SQTP_CFG']['SQTPen']
                        sqtp_en = sqtp_en.lower()    
                        if "true" == sqtp_en or "1" == sqtp_en:
                            sqtpflag = 1
                            try:
                                exit_code = 223
                                MaskVal = config['SQTP_CFG']['Mask']     
                            except:
                                error_msg = 122
                                MaskVal =""
                            try:    
                                exit_code = 224
                                PatternVal = config['SQTP_CFG']['Pattern'] 
                            except:
                                error_msg = 123
                                PatternVal = ""
                            try:
                                exit_code = 225
                                TypeVal = config['SQTP_CFG']['Type'] 
                            except:
                                error_msg = 124
                                TypeVal ='s'
                        try:    
                            exit_code = 226
                            MultipleDevices = config['SQTP_CFG']['MultipleDevices']
                            MultipleDevices = MultipleDevices.lower()    
                            if "true" == MultipleDevices or "1" == MultipleDevices:
                                try: 
                                    exit_code = 227
                                    CustomDataDirPath = config['SQTP_CFG']['CustomDataDirPath']
                                    if not os.path.exists(CustomDataDirPath):
                                        print("CustomDataDirPath File Missing!!")
                                        sys.exit(2)
                                    cmd = "del /f /q CustomDataDirPath.ini"    
                                    op = os.system(cmd)
                                    filename = "\\".join(CustomDataDirPath.split('/'))                    
                                    self.CustmDatDirPath.set(filename)                    
                                    with open("CustomDataDirPath.ini","wt+") as conf_f:  
                                        conf_f.write(filename)
                                    conf_f.close()
                                    MultipleDev = 1
                                except:
                                    error_msg = 125
                                    MultipleDev = 0
                                    print("'CustomDataDirPath' Key File missing in config")
                                    sys.exit(2)
                                try:
                                    exit_code = 228
                                    custOFF = config['SQTP_CFG']['custOFF']
                                    try: 
                                        exit_code = 229
                                        idx = int(custOFF,16)
                                        if idx not in range(576,863+1):#(192, 415+1):if idx not in range(480,991+1):#(192, 415+1):
                                            print("Errot Custom Offset  custOFF") 
                                            sys.exit(2) 
                                        else:
                                            self.custOFF.set(custOFF)                   
                                    except:
                                        error_msg = 126
                                        print("Need a hex value for Custom IDX") 
                                except:
                                    error_msg = 127
                                    self.custOFF.set("240")
                        except ValueError:
                            error_msg = 128
                            MultipleDev = 0
                    except:
                        sqtpflag = 0
                        sys.exit(2)
                    if True == MOB_flag:
                        error_msg = 132 
                        try:
                            exit_code = 234
                            MOB = config['MOBILE']['MOBen']
                            MOB = MOB.lower()
                            if "true" == MOB or "1" == MOB:
                                self.DSWvar.set(1)#Enable DSW 
                                try: # dswgpiosel = 0
                                    exit_code = 235
                                    DSWgpio = config['MOBILE']['DPWROKgpio']
                                    self.DSWgpio.set(DSWgpio)
                                    DSWpin = self.DSWgpio.get()
                                    try:
                                        val = int(DSWpin,8)
                                    except:
                                        exit_code = 236
                                        print("GPIO sel is not a valid value")
                                        dswgpiosel = 0
                                        self.DSWgpio.set("")
                                        sys.exit(2)  
                                            
                                    if "000" == DSWpin or len(DSWpin) >= 4 or val > 0o257:
                                        exit_code = 237
                                        print("GPIO sel is not a valid value")
                                        self.DSWgpio.set("")
                                        sys.exit(2)  
                                    dswgpiosel = hex(val<<2) 
                                except:
                                    sys.exit(2)  
                                    self.DSWgpio.set(0)  #Strap Enable default
                                try:
                                    exit_code = 238
                                    WDTdelay = config['MOBILE']['DPWDTdelay']
                                    if WDTdelay == "":
                                       print("DSWWDTdelay is not valid one")
                                       print("Please refer the efuseconfig.ini file for the usage of DPWDTdelay for Mobile feature")
                                       sys.exit(2) 
                                    WDTDelayg = (int(WDTdelay))
                                    self.WDTENvar.set(1)
                                    self.WDTDelay.set(WDTDelayg)
                                    WDTDelayg =  self.WDTDelay.get()
                                    if WDTDelayg > 3:
                                        print("DPWDTdelay  is not valid")
                                        print("Please refer the efuseconfig.ini file for the usage of Mobile features for the DPWDTdelay variable")
                                        sys.exit(2)
                                except:
                                    if WDTDelayg > 3 or WDTdelay == "":
                                       sys.exit(2)  
                                    self.WDTDelay.set(0) 
                                    WDTDelayg =  self.WDTDelay.get()
                                    sys.exit(2)    
                            else:
                                if "false" == MOB or "0" == MOB:
                                    self.DSWvar.set(0)#Disable DSW
                                else:
                                    print("MOB enable feature variable  is not valid")
                                    print("Please refer the efuseconfig.ini file for the usage of Mobile to be enable or disable for MOBILE feature")
                                    sys.exit(2)
                        except ValueError:
                            error_msg = 132
                            print("DSW_PWROK enable option error")
                            sys.exit(2)
                        
                    if True == DSW_flag:
                        error_msg = 132 
                        try:
                            exit_code = 234
                            DSW = config['DESKTOP']['DESen']
                            DSW = DSW.lower()
                            if "true" == DSW or "1" == DSW:
                                self.DESWvar.set(1)#Enable DSW 
                                try:
                                    exit_code = 238
                                    WDTdelay = config['DESKTOP']['DSWWDTdelay']
                                    if WDTdelay == "":
                                       print("DSWWDTdelay is not valid one")
                                       print("Please refer the efuseconfig.ini file for the usage of DSWWDTdelay for desktop feature")
                                       sys.exit(2) 
                                    WDTDelayg = (int(WDTdelay))
                                    if WDTDelayg > 3:
                                        print("DSWWDTdelay is not valid one")
                                        print("Please refer the efuseconfig.ini file for the usage of DSWWDTdelay for desktop feature")
                                        sys.exit(2)
                                    self.WDTENvar.set(1)
                                    self.WDTDelay.set(WDTDelayg)
                                    WDTDelayg =  self.WDTDelay.get()
                                except:
                                    if WDTDelayg > 3 or WDTdelay == "":
                                       sys.exit(2)  
                                    self.WDTDelay.set(0) 
                                    WDTDelayg =  self.WDTDelay.get()
                            
                                try:
                                    exit_code = 238
                                    SUSvar = config['DESKTOP']['SUS_5ven']
                                    SUSvar= SUSvar.lower()
                                    if "true" == SUSvar or "1" == SUSvar:                
                                        self.SUSvar.set(1)
                                    else:
                                        if "false" == SUSvar or "0" == SUSvar:
                                             self.SUSvar.set(0)
                                        else:
                                             print("SUS_5ven is not valid one")
                                             print("Please refer the efuseconfig.ini file for the usage of SUS_5ven for the avilable value to be set")
                                             sys.exit(2)
                                except:
                                    self.SUSvar.set(0) 
                                    SUSvar =  self.SUSvar.get()
                                    sys.exit(2)
                            else:
                                if "false" == DSW or "0" ==DSW:
                                    self.DESWvar.set(0)
                                else:
                                    print("DESKTOP variable  is not valid")
                                    print("Please refer the efuseconfig.ini file for the usage of DESKTOP to be enable or disable ")
                                    sys.exit(2)       
                        except ValueError:
                            error_msg = 132
                            print("DSW_PWROK enable option error")
                            sys.exit(2)
                    if( True == COMP_flag):
                        try:
                            exit_code = 211            
                            COMPvar = config['COMP_STRAP']['COMPEn'] 
                            COMPvar= COMPvar.lower()    
                            if "true" == COMPvar or COMPvar == "1":                
                                self.COMPvar.set(1)
                            else:
                                if "false" == COMPvar or COMPvar == "0":     
                                    self.COMPvar.set(0)
                                else:
                                    print("COMPEn  is not valid ")
                                    print("Please refer the efuseconfig.ini file for the usage of COMPEn to be enable or disable feature")
                                    sys.exit(2)
                        except ValueError:
                            error_msg = 111    
                            self.COMPvar.set(0)

                    if ((True == DSW_flag) and  (True == MOB_flag)):
                         print("CAUTION: Feature may not be available in all packages")
                         print("Please refer the datasheet for the features available for the given package")
                         print("Desktop & Mobile is not to be enable at same time ")
                         print("Please refer the efuseconfig.ini file for the usage of Desktop & Mobile to be enable which is based on the package available")
                         sys.exit(2)

                    if ((True == DSW_flag) and  (True == COMP_flag)):
                         print("CAUTION: Feature may not be available in all packages")
                         print("Please refer the datasheet for the features available for the given package")
                         print("Desktop & Comparator strap  is not to be enable at same time ")
                         print("Please refer the efuseconfig.ini file for the usage of Desktop & Comparator to be enable which is based on the package available")
                         sys.exit(2)
                         
                except:
                    print("Error Message =", error_msg,"Exit Code =", exit_code)
                    print("Error!! EFuse file not Generated!!")
                    sys.exit(2)    

            def generate_sqtp_W_multiple_custom_data(self):
                global MaskVal
                global PatternVal
                global TypeVal  
                global dummy_buffer
                once = True
                CustmDatDirPath = self.CustmDatDirPath.get()
                Custfilesdir = open(CustmDatDirPath,"rt+")
          
                fldloc = self.outdir.get()
                fldloc = "/".join(fldloc.split('\\')) 
                self.dummy_file_generate()
                sqtppath1=fldloc+"/out_binaries/sqptfile_multiple_devices.txt"
                sqtppath2=fldloc+"/out_binaries/sqptfile_multiple_devices.tmp"

                dat = incnt = outcnt = 0
                with open(sqtppath1,"wt+") as out_file:
                    out_file.write("<header>\n")
                    out_file.write("mask,"+MaskVal+"\n")
                    out_file.write("pattern,"+PatternVal+"\n")
                    out_file.write("type,"+TypeVal+"\n")
                    out_file.write("</header>\n")
                    out_file.write("<data>\n")
                    out_file.close
                for Custfiles in Custfilesdir:
                    filename = "/".join(Custfiles.split('\\'))   
                    filename = filename.split("\n")[0]
                    try:
                        in_file = open(filename,"rt+")
                        offset = 576#480#192
                        if "" == self.custOFF.get():
                            offset = 576#480#192
                        else:    
                            offset = self.custOFF.get()
                            offset = int(offset,16)
                        for cnt in in_file:
                            CUSTMDAT = list(cnt)
                            CUSTMDAT = CUSTMDAT[0:]
                            endoff = len(CUSTMDAT)
                            entry = 0
                            key = []
                            for j in range(0,endoff-1,2):
                                key.append(CUSTMDAT[j]+CUSTMDAT[j+1])
                                entry = entry + 1
                            entry = entry + offset #starting offset
                            endoff = 863#415
                            if entry > endoff:
                                entry = endoff
                            data_idx = 0
                            for idx in range(offset,entry):
                                dat = key[data_idx].upper()
                                del dummy_buffer[idx]
                                dummy_buffer.insert(idx,dat ) 
                                data_idx = data_idx + 1
                        in_file.close()
                        dat = ""
                        incnt = outcnt = 0
                        sqptfile = open(sqtppath1,"rt+")
                        with open(sqtppath2,"wt+") as out_file:
                            for cnt in sqptfile:
                                out_file.write(cnt)
                            for items in dummy_buffer:
                                dat = dat + str(items).zfill(2)
                                if 28 == outcnt:
                                    if (15 == incnt):
                                        dat =dat+"\n"
                                        out_file.write(dat)
                                        dat = ""
                                        incnt = 0
                                        outcnt = outcnt +1
                                    else:
                                        incnt = incnt +1
            
                                else:
                                    if (35 == incnt):
                                        dat =dat+"\\"+"\n"
                                        out_file.write(dat)
                                        dat = ""
                                        incnt = 0
                                        outcnt = outcnt +1
                                    else:
                                        incnt = incnt +1
                                        
                                if 30 == outcnt:
                                    out_file.write(dat)
                                    break        
                                    
                        sqptfile.close()
                        out_file.close()
                        cmd = sqtppath1
                        cmd = "\\".join(cmd.split('/'))
                        cmd = "del /f /q "+cmd
                        op = os.system(cmd) 
                        cmd = sqtppath2
                        cmd = "\\".join(cmd.split('/'))
                        cmd = "rename "+cmd+" sqptfile_multiple_devices.txt"
                        op = os.system(cmd) 
                    
                    except:
                        print("File Doesnt exist:",filename)
                sqptfile = open(sqtppath1,"rt+")
                with open(sqtppath2,"wt+") as out_file:
                    for cnt in sqptfile:
                        out_file.write(cnt)
                    out_file.write("</data>\n")    
                sqptfile.close()
                cmd = sqtppath1
                cmd = "\\".join(cmd.split('/'))
                cmd = "del /f /q "+cmd
                op = os.system(cmd) 
                cmd = sqtppath2
                cmd = "\\".join(cmd.split('/'))
                cmd = "rename "+cmd+" sqptfile_multiple_devices.txt"
                op = os.system(cmd) 

            def dummy_file_generate(self):
                global dummy_buffer
                fldloc = self.outdir.get()
                fldloc = "/".join(fldloc.split('\\')) 
                dirpath=fldloc+"/out_binaries/efuse.bin" 
                efuse_file = open(dirpath,"rb")
                efuse_file.seek(0)
                efuse_data =efuse_file.read()
                cnt = idx = dat = incnt = outcnt = 0
                dummy_buffer = []
                for indx in range(0, 1024):
                    dat = 0
                    dat = hex(dat).zfill(2).split("x")[1].upper()
                    dummy_buffer.append(dat)
                    
                for items in efuse_data:
                    if 0 == cnt:
                        idx = items 
                    if 1 == cnt:    
                        idx = idx + (items << 8)
                    if 2 == cnt:  
                        dat = items
                        dat = hex(dat).zfill(2).split("x")[1].upper()
                    #if 3 == cnt:  
                        if 57005 == idx:#DEAD
                            break
                        else:
                            if idx >= 0 and idx <= 1024:#512
                                del dummy_buffer[idx]
                                dummy_buffer.insert(idx,dat ) 
                        cnt = 0
                    else:
                        cnt = cnt + 1
                        
            def help_menu(self):
                global help_active
                if 0 ==help_active:
                    help_windox()
            def view_menu(self):
                    view_windox()            
            def callback1(self, *dummy):
                tagadd1 = self.tagAddr1.get()
                try:
                    val = int(tagadd1,16)
                except ValueError:
                 #   print ("err")
                    self.tagAddr1.set("")
                if "0000" == tagadd1 or len(tagadd1) >= 9 :
                    self.tagAddr1.set("")
            def callback(self, *dummy):
                tagadd = self.tagAddr.get()
                try:
                    val = int(tagadd,16)
                except ValueError:
                 #   print ("err")
                    self.tagAddr.set("")
                if "0000" == tagadd or len(tagadd) >= 9 :
                    self.tagAddr.set("")     

            def otp_crc_var_callback(self, *dummy):
                otp_crc_var = self.otp_crc_var.get()
                if len(otp_crc_var) >= 9 :
                    self.otp_crc_var.set("00000000")      

            def otp_rollback_var_0_callback(self, *dummy):
                otp_rollback_var_0 = self.otp_rollback_var_0.get()
                if len(otp_rollback_var_0) >= 9 :
                    self.otp_rollback_var_0.set("00000000")    

            def otp_rollback_var_1_callback(self, *dummy):
                otp_rollback_var_1 = self.otp_rollback_var_1.get()
                if len(otp_rollback_var_1) >= 9 :
                    self.otp_rollback_var_1.set("00000000")     

            def otp_rollback_var_2_callback(self, *dummy):
                otp_rollback_var_2 = self.otp_rollback_var_2.get()
                if len(otp_rollback_var_2) >= 9 :
                    self.otp_rollback_var_2.set("00000000")     

            def otp_rollback_var_3_callback(self, *dummy):
                otp_rollback_var_3 = self.otp_rollback_var_3.get()
                if len(otp_rollback_var_3) >= 9 :
                    self.otp_rollback_var_3.set("00000000")     

            def ecdsa_rollback_var_0_callback(self, *dummy):
                ecdsa_rollback_var_0 = self.ecdsa_rollback_var_0.get()
                if len(ecdsa_rollback_var_0) >= 9 :
                    self.ecdsa_rollback_var_0.set("00000000")    
            def otp_read_256_var_callback(self, *dummy):
                otp_read_256_var = self.otp_read_256_var.get()
                if len(otp_read_256_var) >= 9 :
                    self.otp_read_256_var.set("00000000")    

            def security_features_var_callback(self, *dummy):
                security_features_var = self.security_features_var.get()
                if len(security_features_var) >= 3 :
                    self.security_features_var.set("00")      

            def otp_region_read_lock_var_0_callback(self, *dummy):
                otp_region_read_lock_var_0 = self.otp_region_read_lock_var_0.get()
                if len(otp_region_read_lock_var_0) >= 3 :
                    self.otp_region_read_lock_var_0.set("00")      

            def otp_region_read_lock_var_1_callback(self, *dummy):
                otp_region_read_lock_var_1 = self.otp_region_read_lock_var_1.get()
                if len(otp_region_read_lock_var_1) >= 3 :
                    self.otp_region_read_lock_var_1.set("00")      

            def otp_region_read_lock_var_2_callback(self, *dummy):
                otp_region_read_lock_var_2 = self.otp_region_read_lock_var_2.get()
                if len(otp_region_read_lock_var_2) >= 3 :
                    self.otp_region_read_lock_var_2.set("00")     

            def otp_region_read_lock_var_3_callback(self, *dummy):
                otp_region_read_lock_var_3 = self.otp_region_read_lock_var_3.get()
                if len(otp_region_read_lock_var_3) >= 3 :
                    self.otp_region_read_lock_var_3.set("00")     

            def otp_region_write_lock_var_0_callback(self, *dummy):
                otp_region_write_lock_var_0 = self.otp_region_write_lock_var_0.get()
                if len(otp_region_write_lock_var_0) >= 3 :
                    self.otp_region_write_lock_var_0.set("00")     

            def otp_region_write_lock_var_1_callback(self, *dummy):
                otp_region_write_lock_var_1 = self.otp_region_write_lock_var_1.get()
                if len(otp_region_write_lock_var_1) >= 3 :
                    self.otp_region_write_lock_var_1.set("00")      

            def otp_region_write_lock_var_2_callback(self, *dummy):
                otp_region_write_lock_var_2 = self.otp_region_write_lock_var_2.get()
                if len(otp_region_write_lock_var_2) >= 3 :
                    self.otp_region_write_lock_var_2.set("00")      

            def otp_region_write_lock_var_3_callback(self, *dummy):
                otp_region_write_lock_var_3 = self.otp_region_write_lock_var_3.get()
                if len(otp_region_write_lock_var_3) >= 3 :
                    self.otp_region_write_lock_var_3.set("00")       

            def DPWREN_GPIO_sel_var_callback(self, *dummy):
                DPWREN_GPIO_sel_var = self.DPWREN_GPIO_sel_var.get()
                if len(DPWREN_GPIO_sel_var) >= 3:
                    self.DPWREN_GPIO_sel_var.set("0")     

            def PRIM_PWRGD_GPIO_sel_var_callback(self, *dummy):
                PRIM_PWRGD_GPIO_sel_var = self.PRIM_PWRGD_GPIO_sel_var.get()
                if len(PRIM_PWRGD_GPIO_sel_var) >= 3:
                    self.PRIM_PWRGD_GPIO_sel_var.set("0") 

            def RSMRST_GPIO_sel_var_callback(self, *dummy):
                RSMRST_GPIO_sel_var = self.RSMRST_GPIO_sel_var.get()
                if len(RSMRST_GPIO_sel_var) >= 3:
                    self.RSMRST_GPIO_sel_var.set("0")     

            def DSW_PWRGD_GPIO_sel_var_callback(self, *dummy):
                DSW_PWRGD_GPIO_sel_var = self.DSW_PWRGD_GPIO_sel_var.get()
                if len(DSW_PWRGD_GPIO_sel_var) >= 3:
                    self.DSW_PWRGD_GPIO_sel_var.set("0")     

            def SUS_PWR_EN_GPIO_sel_var_callback(self, *dummy):
                SUS_PWR_EN_GPIO_sel_var = self.SUS_PWR_EN_GPIO_sel_var.get()
                if len(SUS_PWR_EN_GPIO_sel_var) >= 3:
                    self.SUS_PWR_EN_GPIO_sel_var.set("0")     

            def SLP_SUS_GPIO_sel_var_callback(self, *dummy):
                SLP_SUS_GPIO_sel_var = self.SLP_SUS_GPIO_sel_var.get()
                if len(SLP_SUS_GPIO_sel_var) >= 3:
                    self.SLP_SUS_GPIO_sel_var.set("0") 

            def otp_crc_var_callback(self, *dummy):
                otp_crc_var = self.otp_crc_var.get()
                if len(otp_crc_var) >= 9 :
                    self.otp_crc_var.set("00000000")      

            def otp_rollback_var_0_callback(self, *dummy):
                otp_rollback_var_0 = self.otp_rollback_var_0.get()
                if len(otp_rollback_var_0) >= 9 :
                    self.otp_rollback_var_0.set("00000000")    

            def otp_rollback_var_1_callback(self, *dummy):
                otp_rollback_var_1 = self.otp_rollback_var_1.get()
                if len(otp_rollback_var_1) >= 9 :
                    self.otp_rollback_var_1.set("00000000")     

            def otp_rollback_var_2_callback(self, *dummy):
                otp_rollback_var_2 = self.otp_rollback_var_2.get()
                if len(otp_rollback_var_2) >= 9 :
                    self.otp_rollback_var_2.set("00000000")     

            def otp_rollback_var_3_callback(self, *dummy):
                otp_rollback_var_3 = self.otp_rollback_var_3.get()
                if len(otp_rollback_var_3) >= 9 :
                    self.otp_rollback_var_3.set("00000000")     

            def ecdsa_rollback_var_0_callback(self, *dummy):
                ecdsa_rollback_var_0 = self.ecdsa_rollback_var_0.get()
                if len(ecdsa_rollback_var_0) >= 9 :
                    self.ecdsa_rollback_var_0.set("00000000")    

            def power_sequence_var_callback(self, *dummy):
                power_sequence_var = self.power_sequence_var.get()
                if len(power_sequence_var) >= 3 :
                    self.power_sequence_var.set("0")            

            def otp_write_260_var_callback(self, *dummy):
                otp_write_260_var = self.otp_write_260_var.get()
                if len(otp_write_260_var) >= 9 :
                    self.otp_write_260_var.set("00000000")        

            def progflashvar_2_callback(self, *dummy):
                progflashvar_2 = self.progflashvar_2.get()
                if len(progflashvar_2) >= 3 :
                    self.progflashvar_2.set("0")    

            def progflashvar_1_callback(self, *dummy):
                progflashvar_1 = self.progflashvar_1.get()
                if len(progflashvar_1) >= 3 :
                    self.progflashvar_1.set("0")
                    
            def update2(self, *dummy):
                pass

            def update1(self, *dummy):

                global primgpiosel_0
                DSWpin = self.PRIMvar0.get()
                try:
                    val = int(DSWpin,8)
                except ValueError:
                    val = 0
                    self.PRIMvar0.set("")
                if "000" == DSWpin or len(DSWpin) >= 4 or val > 0o257:
                    self.PRIMvar0.set("")
                primgpiosel_0 = hex(val<<2) 

            def update(self, *dummy):
                DSWgpio = self.DSWgpio.get()
                if len(DSWgpio) >= 3:
                    self.DSWgpio.set("")
                # global dswgpiosel
                # DSWpin = self.DSWgpio.get()
                # try:
                #     val = int(DSWpin,8)
                # except ValueError:
                #     val = 0
                #     self.DSWgpio.set("")
                # if "000" == DSWpin or len(DSWpin) >= 4 or val > 0o257:
                #     self.DSWgpio.set("")
                # dswgpiosel = hex(val<<2)  

            def quit_window(self):
                global general_win_flag_active
                global mobile_win_flag_active
                global desktop_win_flag_active
                global mobile_com_win_flag_active
                global gen_com_win_flag_active
                global first_win_flag
                global cust_enter_var
                global setting_win_flag
                global headerflag
                global sqtpflag
                global warningMSG
                global pathfilename
                global cust_idx_enter_flag
                global cust_data_enter_flag
                
                if 0 == general_win_flag_active:
                    general_win_flag_active =1

                if 0 == mobile_win_flag_active:
                    mobile_win_flag_active =1

                if 0 == desktop_win_flag_active:
                   desktop_win_flag_active =1

                if 0 == mobile_com_win_flag_active:
                    mobile_com_win_flag_active =1
                    
                if 0 == gen_com_win_flag_active:
                    gen_com_win_flag_active =1

                setting_win_flag = 0
                headerflag = 0
                pathfilename =[]
                sqtpflag = 0
                warningMSG = 0
                
                custom_data = []
                log_file_cnt = []
                setting_win_flag = 0
                self.ATEvar.set(1)
                self.JTAGvar.set(0)
                self.AUTHvar.set(0)
                # self.JTAGvar1.set(0)
                self.ENCvar.set(0)
                self.TAGvar.set(0)
                self.tagAddr.set("00000000")
                self.CUSvar.set(0)
                #self.ecdsabar.config(state="disabled")
                #self.ecdsapassbar.config(state="disabled")  
                if False == soteria_flag: 
                    self.ecdhbar.config(state="disabled")
                    self.ecdhpassbar.config(state="disabled")
                    self.ecdhbar_button.config(state="disabled")

                self.CUSvar.set(0)
                self.custIDX.set("240")#("1E0")#("C0")
                self.custDAT.set("00")


                self.custIDXbar.config(state="disabled")
                self.custDATbar.config(state="disabled")
                self.hex.config(state="disabled")
                self.dec.config(state="disabled")
                self.Ebutton.config(state="disabled")
                self.CUSTfilebar.config(state="disabled")
                self.bbutton2.config(state="disabled")
                self.ViewCusDButton.config(state="disabled")
                custdatexd = 0
                if False == soteria_flag:
                    self.ECDHENCvar.set(0)
                    self.ECDHENC_CB.config(state="disabled")
                if True ==  COMP_flag:
                   self.COMPvar.set(0)

                if(True == DSW_flag ):
                   self.DESWvar.set(0)
                   self.WDTDelay.set(0)
                   self.WDTENvar.set(0)
                   primgpiosel_0 =0

                if(True == MOB_flag):
                   self.DSWvar.set(0)
                   self.WDTDelay.set(0)
                   self.WDTENvar.set(0)
                   self.DSWgpio.set("")
                   self.DSWlbl3.config(state="disabled")
                   dswgpiosel = 0 
                   primgpiosel_0 =0
                otp_write_lock_en =0
                write_lock_flag_15 = 0
                write_lock_flag_16 = 0
                write_lock_flag_17 = 0
                write_lock_flag_18 = 0
                write_lock_flag_19 = 0
                write_lock_flag_20 = 0
                write_lock_flag_21 = 0
                write_lock_flag_22 = 0
                write_lock_flag_23 = 0
                write_lock_flag_24 = 0
                write_lock_flag_25 = 0
                write_lock_flag_26 = 0
                write_lock_flag_27 = 0
                write_lock_flag_28 = 0
                write_lock_flag_29 = 0
                write_lock_flag_30 = 0

                otp_lock_15 = 0
                otp_lock_16 = 0
                otp_lock_17 = 0
                otp_lock_18 = 0
                otp_lock_19 = 0
                otp_lock_20 = 0
                otp_lock_21 = 0
                otp_lock_22 = 0
                otp_lock_23 = 0
                otp_lock_24 = 0
                otp_lock_25 = 0 
                otp_lock_26 = 0
                otp_lock_27 = 0
                otp_lock_28 = 0
                otp_lock_29 = 0
                otp_lock_30 = 0
                self.AEMvar.set(0)
                #self.ECDSALCKvar.set(0)
                #self.ECDSALCK_CB.config(state ="disabled")
                if False == soteria_flag:
                    self.ECDHENC_CB.config(state="disabled")
                '''
                    self.ECDHLCK_CB.config(state="disabled")
                    '''
                if False == soteria_flag:
                    #self.ECDHPrivLCK_CB.config(state="disabled")
                    #self.ECDHPubLCK_CB.config(state="disabled")
                    ##self.ECDHENCvar.set(0)
                    s#elf.ECDHPrivLCKvar.set(0)
                    s#elf.ECDHPubLCKvar.set(0)
                self.tagbar.config(state="disabled")

                self.Hex2Dec.set(1)
                global generate_efuse_data
                generate_efuse_data =0
                global warning_main_wind_flag
                if 1 == warning_main_wind_flag:
                     selected = messagebox.showerror("Glacier Efuse Generator Tool Ver: 3.09 Close Window",' Close the "Warning window" which is opened before, then click "ok" to proceed,if you are not close that window , it will be opened ')
                     if selected =="ok":
                          warning_main_wind_flag =0

                if 1 == cust_idx_enter_flag:
                     selected = messagebox.showerror("Glacier Efuse Generator Tool Ver: 3.09 Close Window",' Close the "Custome IDX error window" which is opened before, then click "ok" to proceed,if you are not close that window , it will be opened ')
                     if selected =="ok":
                        cust_idx_enter_flag = 0

                if 1 == cust_data_enter_flag:
                     selected_1 = messagebox.showerror("Glacier Efuse Generator Tool Ver: 3.09 Close Window",' Close the "Custome Data error window" which is opened before, then click "ok" to proceed,if you are not close that window , it will be opened ')
                     if selected_1 =="ok":
                        cust_data_enter_flag = 0

                self.master.destroy()

                if 1 == first_win_flag:
                     messagebox.showinfo('Glacier Efuse Generator Tool Ver: 3.09 Close Window', 'Click the "OK" button to proceed & Please click the "Refresh" button in the Main window to enable "Select the Device Package available:" option to generate the efuse files for the given package')

                 
            def on_closing_main(self):
                global general_win_flag_active
                global mobile_win_flag_active
                global desktop_win_flag_active
                global mobile_com_win_flag_active
                global gen_com_win_flag_active
                global first_win_flag
                global cust_enter_var
                global setting_win_flag
                global headerflag
                global sqtpflag
                global warningMSG
                global pathfilename
                global cust_idx_enter_flag
                global cust_data_enter_flag
                

                        
                if 0 == general_win_flag_active:
                    general_win_flag_active =1

                if 0 == mobile_win_flag_active:
                    mobile_win_flag_active =1

                if 0 == desktop_win_flag_active:
                   desktop_win_flag_active =1

                if 0 == mobile_com_win_flag_active:
                    mobile_com_win_flag_active =1
                    
                if 0 == gen_com_win_flag_active:
                    gen_com_win_flag_active =1

                setting_win_flag = 0
                pathfilename =[]
                headerflag = 0
                sqtpflag = 0
                warningMSG = 0
                custom_data = []
                log_file_cnt = []
                #pathfilename = []
                self.ATEvar.set(1)
                self.JTAGvar.set(0)
                self.AUTHvar.set(0)
                # self.JTAGvar1.set(0)
                self.ENCvar.set(0)
                self.TAGvar.set(0)
                self.tagAddr.set("00000000")
                self.CUSvar.set(0)
                #self.ecdsabar.config(state="disabled")
                #self.ecdsapassbar.config(state="disabled")  
                if False == soteria_flag:
                    self.ecdhbar.config(state="disabled")
                    self.ecdhpassbar.config(state="disabled")
                    self.ecdhbar_button.config(state="disabled")

                self.CUSvar.set(0)
                self.custIDX.set("240")#("1E0")#("C0")
                self.custDAT.set("00")


                self.custIDXbar.config(state="disabled")
                self.custDATbar.config(state="disabled")
                self.hex.config(state="disabled")
                self.dec.config(state="disabled")
                self.Ebutton.config(state="disabled")
                self.CUSTfilebar.config(state="disabled")
                self.bbutton2.config(state="disabled")
                self.ViewCusDButton.config(state="disabled")
                custdatexd = 0
                self.ECDHENCvar.set(0)
                if False == soteria_flag:
                    self.ECDHENC_CB.config(state="disabled")
                if True ==  COMP_flag:
                   self.COMPvar.set(0)

                if(True == DSW_flag ):
                   self.DESWvar.set(0)
                   self.WDTDelay.set(0)
                   self.WDTENvar.set(0)
                   primgpiosel_0 =0

                if(True == MOB_flag):
                   self.DSWvar.set(0)
                   self.WDTDelay.set(0)
                   self.WDTENvar.set(0)
                   self.DSWgpio.set("")
                   self.DSWlbl3.config(state="disabled")
                   dswgpiosel = 0 
                   primgpiosel_0 =0
                otp_write_lock_en =0
                write_lock_flag_15 = 0
                write_lock_flag_16 = 0
                write_lock_flag_17 = 0
                write_lock_flag_18 = 0
                write_lock_flag_19 = 0
                write_lock_flag_20 = 0
                write_lock_flag_21 = 0
                write_lock_flag_22 = 0
                write_lock_flag_23 = 0
                write_lock_flag_24 = 0
                write_lock_flag_25 = 0
                write_lock_flag_26 = 0
                write_lock_flag_27 = 0
                write_lock_flag_28 = 0
                write_lock_flag_29 = 0
                write_lock_flag_30 = 0

                otp_lock_15 = 0
                otp_lock_16 = 0
                otp_lock_17 = 0
                otp_lock_18 = 0
                otp_lock_19 = 0
                otp_lock_20 = 0
                otp_lock_21 = 0
                otp_lock_22 = 0
                otp_lock_23 = 0
                otp_lock_24 = 0
                otp_lock_25 = 0 
                otp_lock_26 = 0
                otp_lock_27 = 0
                otp_lock_28 = 0
                otp_lock_29 = 0
                otp_lock_30 = 0
                self.AEMvar.set(0)
                #self.ECDSALCKvar.set(0)
                #self.ECDSALCK_CB.config(state ="disabled")
                if (False == soteria_flag):
                    self.ECDHENC_CB.config(state="disabled")
                    '''
                        self.ECDHLCK_CB.config(state="disabled")
                        '''
                    #self.ECDHPrivLCK_CB.config(state="disabled")
                    #self.ECDHPubLCK_CB.config(state="disabled")
                    #self.ECDHENCvar.set(0)
                    #self.ECDHPrivLCKvar.set(0)
                    #self.ECDHPubLCKvar.set(0)
                self.tagbar.config(state="disabled")

                self.Hex2Dec.set(1)
                global generate_efuse_data
                generate_efuse_data =0
                global warning_main_wind_flag
                if 1 == warning_main_wind_flag:
                     selected = messagebox.showerror("Glacier Efuse Generator Tool Ver: 3.09 Close Window",' Close the "Warning window" which is opened before, then click "ok" to proceed,if you are not close that window , it will be opened ')
                     if selected =="ok":
                          warning_main_wind_flag =0

                if 1 == cust_idx_enter_flag:
                     selected = messagebox.showerror("Glacier Efuse Generator Tool Ver: 3.09 Close Window",' Close the "Custome IDX error window" which is opened before, then click "ok" to proceed,if you are not close that window , it will be opened ')
                     if selected =="ok":
                        cust_idx_enter_flag = 0

                if 1 == cust_data_enter_flag:
                     selected_1 = messagebox.showerror("Glacier Efuse Generator Tool Ver: 3.09 Close Window",' Close the "Custome Data error window" which is opened before, then click "ok" to proceed,if you are not close that window , it will be opened ')
                     if selected_1 =="ok":
                        cust_data_enter_flag = 0

                self.master.destroy()
                if 1 == first_win_flag:
                     messagebox.showinfo('Glacier Efuse Generator Tool Ver: 3.09 Close Window', 'Click the "OK" button to proceed & Please click the "Refresh" button in the Main window to enable "Select the Device Package available:" option to generate the efuse files for the given package')

                
            def CUSsel(self):
                global custom_data
                global custdatexd
                global ref_active
                global otp_write_lock_en
                global cust_enter_var

                write_lock_flag_15 = 0
                write_lock_flag_16 = 0
                write_lock_flag_17 = 0
                write_lock_flag_18 = 0
                write_lock_flag_19 = 0
                write_lock_flag_20 = 0
                write_lock_flag_21 = 0
                write_lock_flag_22 = 0
                write_lock_flag_23 = 0
                write_lock_flag_24 = 0
                write_lock_flag_25 = 0
                write_lock_flag_26 = 0
                write_lock_flag_27 = 0
                write_lock_flag_28 = 0
                write_lock_flag_29 = 0
                write_lock_flag_30 = 0

                otp_lock_15 = 0
                otp_lock_16 = 0
                otp_lock_17 = 0
                otp_lock_18 = 0
                otp_lock_19 = 0
                otp_lock_20 = 0
                otp_lock_21 = 0
                otp_lock_22 = 0
                otp_lock_23 = 0
                otp_lock_24 = 0
                otp_lock_25 = 0 
                otp_lock_26 = 0
                otp_lock_27 = 0
                otp_lock_28 = 0
                otp_lock_29 = 0
                otp_lock_30 = 0
                otp_write_lock_en = 0
                cust_enter_var = 0
                opt = self.CUSvar.get()
                if 1== opt:
                    for idx in range(576,863+1):#(192, 479+1):for idx in range(480,991+1):#(192, 479+1):
                        dat = int('00',16)
                        temp= ((dat<<16) & 0x00FF0000)| idx & 0xFFFF;#0x1FF;
                        temp = struct.pack('I',temp)
                        custom_data.append(temp)
                    self.custIDXbar.config(state="normal")
                    self.custDATbar.config(state="normal")
                    self.hex.config(state="normal")
                    self.dec.config(state="normal")
                    self.Ebutton.config(state="normal")
                    self.CUSTfilebar.config(state="normal")
                    self.bbutton2.config(state="normal")
                    self.ViewCusDButton.config(state="normal")
                if 0== opt:
                    ref_active = 0
                    custdatexd = False
                    custom_data = []
                    self.Hex2Dec.set(1)
                    self.custIDX.set("240")#("1E0")#("C0")
                    self.custDAT.set("00")
                    self.CustFilekey.set("")
                    self.custIDXbar.config(state="disabled")
                    self.custDATbar.config(state="disabled")
                    self.hex.config(state="disabled")
                    self.dec.config(state="disabled")
                    self.Ebutton.config(state="disabled")
                    self.CUSTfilebar.config(state="disabled")
                    self.bbutton2.config(state="disabled")
                    self.ViewCusDButton.config(state="disabled")
                    
            def ECDHENCsel(self):
                global custdatexd
                global msgidx
                global custom_data
                global rom_aes_flag
                global ecdhkeyenc_en_flag
                global rom_ecdh_flag
                opt = self.ECDHENCvar.get()
                if 1== opt:
                    ecdhkeyenc_en_flag = 1
                    selection = "Encryption Enabled"
                    rom_ecdh_flag = 1
                    self.ecdhkey_R11.config(state="normal")
                    self.ecdhkey_R12.config(state="normal")
                    self.ecdhkeyvar.set(0)
                    self.ecdhkey_lbl.config(state="normal")  
                    self.ecdhkey_R12.config(state="normal") 
                    #self.ECDHPubLCK_CB.config(state="normal")
                    if(custdatexd):
                            custdatexd = False
                            msgidx = 10
                            for items in custom_data:    
                                val = ((int(binascii.hexlify(items), 16)) & 0xFFFFFFFF )#0xFF0100FF)
                                idx  = ((val >> 24 | ((val >> 8) & 0x100)) & 0xFFFF)#0x1FF)
                                if idx > 192:#415:
                                    temp= ((0<<16) & 0x00FF0000)| idx & 0xFFFF;#0x1FF;
                                    temp = struct.pack('I',temp)
                                    inst = custom_data.index(items)
                                    custom_data.remove(items )
                                    custom_data.insert(inst,temp )
                            self.custIDX.set("240")#("1E0")#("C0")
                            self.custDAT.set("00")
                            self.CustFilekey.set("")
                            error_windox()      # self.AESMlbl.config(text = selection) 
                            self.view_menu()            
                if 0== opt: 
                    ecdhkeyenc_en_flag = 0
                    selection = "Encryption Disabled"
                    self.ecdhkey_R11.config(state="disabled")
                    self.ecdhkey_R12.config(state="disabled")
                    self.ecdhkeyvar.set(0)
                    self.ecdhkey_lbl.config(state="disabled")  
                    self.ecdhkey_R12.config(state="disabled") 
                    #self.ECDHPubLCK_CB.config(state="disabled")
                    #self.ECDHPubLCKvar.set(0)
                #self.ECDHENClbl.config(text = selection)   
            '''    
            def ECDHLCKsel(self):
                opt = self.ECDHLCKvar.get()
                if 1== opt:
                    selection = "Lock ECC Key"
                if 0== opt: 
                    selection = "Don't Lock ECC Key"
                self.ECDHLCKlbl.config(text = selection)
            '''
            #def sel_ecdhkeysel(self):
            #	pass
            def ecdhkeysel(self):
            	opt = self.ecdhkeyvar.get()
            	if 1==opt:
            		#self.ecdh_key_lbl.config(state="normal")
            		self.custom_ecdh_key_outdirbar.config(state="normal")
            		self.custom_ecdh_key_hash_button.config(state="normal")
            		#self.custom_ecdh_pass_key_lbl.config(state="normal")
            		self.custom_ecdh_pass_key_outdirbar.config(state="normal")
            	if 0==opt:
            		#self.ecdh_key_lbl.config(state="disabled")
            		self.custom_ecdh_key_outdirbar.config(state="disabled")
            		self.custom_ecdh_key_hash_button.config(state="disabled") 
            		self.custom_ecdh_pass_key_outdirbar.config(state="disabled")
                    #self.custom_ecdh_pass_key_lbl.config(state="disabled")   
                    #self.custom_ecdh_key_bin.set("")			
            def ecdh_key_browsefldr_1(self):
                pathdir = os.getcwd()
                pathdir = pathdir+"\\"
                path = askopenfilename(initialdir=pathdir,
                                   filetypes =(("key file in PEM", "*.pem"),("All Files","*.*"))
                                   #title = "set path Openssl.exe"
                                   )
                path = "\\".join(path.split('/'))                   
                path = path.replace(pathdir,'')
                self.ecdhkey.set(path)    	
            def custom_ecdh_key_browsefldr(self):
                pathdir = os.getcwd()
                pathdir = pathdir+"\\"
                path = askopenfilename(initialdir=pathdir,
                                   filetypes =(("key file in PEM", "*.pem"),("All Files","*.*"))
                                   #title = "set path Openssl.exe"
                                   )
                path = "\\".join(path.split('/'))                   
                path = path.replace(pathdir,'')
                self.custom_ecdh_key_bin.set(path)
            def ecdh_key_var_sel(self):
            	opt = self.ecdh_key_var.get()
            	if 1==opt:
            		#self.ecdh_key_lbl.config(state="normal")
            		self.ecdh_key_outdirbar.config(state="normal")
            		self.ecdh_key_hash_button.config(state="normal")
            	if 0==opt:
            		#self.ecdh_key_lbl.config(state="disabled")
            		self.ecdh_key_outdirbar.config(state="disabled")
            		self.ecdh_key_hash_button.config(state="disabled")  
            		self.ecdh_key_bin.set(" ")  		
            def ecdh_key_browsefldr(self):
                pathdir = os.getcwd()
                pathdir = pathdir+"\\"
                path = askopenfilename(initialdir=pathdir,
                                   filetypes =(("RAW BIN File", "*.bin"),("All Files","*.*"))
                                   #title = "set path Openssl.exe"
                                   )
                path = "\\".join(path.split('/'))                   
                path = path.replace(pathdir,'')
                self.ecdh_key_bin.set(path)
            def ecdh_en_key_var_sel(self):
            	opt = self.ecdh_en_key_var.get()
            	if 1==opt:
            		#self.ecdh_key_lbl.config(state="normal")
            		self.ecdh_en_key_outdirbar.config(state="normal")
            		self.ecdh_en_key_hash_button.config(state="normal")
            	if 0==opt:
            		#self.ecdh_key_lbl.config(state="disabled")
            		self.ecdh_en_key_outdirbar.config(state="disabled")
            		self.ecdh_en_key_hash_button.config(state="disabled") 
            		self.ecdh_en_key_bin.set("")          		    	
            def ecdh_en_key_browsefldr(self):
                pathdir = os.getcwd()
                pathdir = pathdir+"\\"
                path = askopenfilename(initialdir=pathdir,
                                   filetypes =(("RAW BIN File", "*.bin"),("All Files","*.*"))
                                   #title = "set path Openssl.exe"
                                   )
                path = "\\".join(path.split('/'))                   
                path = path.replace(pathdir,'')
                self.ecdh_en_key_bin.set(path)
            def ecdsa_key_hash_check_sel(self):
                opt = self.ecdsa_key_hash_check_var.get()
                if 1 ==opt:
                    selection = " "
                    #self.ecdsa_key_lbl.config(state="normal")
                    self.ecdsa_key_outdirbar.config(state="normal")
                    self.ecdsa_key_hash_button.config(state="normal")
                    #self.DSWlbl.config(state="disabled")
                    #self.DSWbar0.config(state="disabled")
                    #self.ecdsaaddresslbl.config(state="normal")
                    #self.ecdsaaddressbar0.config(state="normal")
                    #self.ecdsaaddress_1_lbl.config(state="normal")
                    #self.ecdsaaddressbar_1.config(state="normal")
                    self.ECCP384lbl.config(state="disabled")
                    self.ECCR11.config(state="disabled")
                    self.ECCR12.config(state="disabled")
                if 0 ==opt:
                    selection = " "
                    #self.ecdsa_key_lbl.config(state="disabled")
                    self.ecdsa_key_outdirbar.config(state="disabled")
                    self.ecdsa_key_hash_button.config(state="disabled")
                    #self.DSWlbl.config(state="normal")
                    #self.DSWbar0.config(state="normal")
                    #self.ecdsaaddresslbl.config(state="normal")
                    #self.ecdsaaddressbar0.config(state="normal")
                    #self.ecdsaaddress_1_lbl.config(state="normal")
                    #self.ecdsaaddressbar_1.config(state="normal")
                    self.ECCP384lbl.config(state="normal")
                    self.ECCR11.config(state="normal")
                    self.ECCR12.config(state="normal")
                    self.eckeycount.set(0)
                    self.ECCP384var.set(0)
                    self.ecdsa_key_hash_bin.set("")
                self.ecdsa_key_hash_lbl.config(text =selection)

            def ECDSALCKsel(self):
                opt = self.ECDSALCKvar.get()
            def otpwritelcksel(self):
                opt = self.otp_write_lock_var_0.get()
                if 1 ==opt :
                    self.otp_write_lock_byte_0.config(state="normal")
                    self.otp_write_lock_byte_0_bar.config(state="normal")
                if 0 ==opt :
                    self.otp_write_lock_byte_0.config(state="disabled")
                    self.otp_write_lock_byte_0_bar.config(state="disabled")        
            def otpreadlcksel(self):
                opt = self.otp_read_lock_var_0.get()
                if 1 ==opt :
                    self.otp_read_lock_byte_0.config(state="normal")
                    self.otp_read_lock_byte_0_bar.config(state="normal")
                if 0 ==opt :
                    self.otp_read_lock_byte_0.config(state="disabled")
                    self.otp_read_lock_byte_0_bar.config(state="disabled")     

            def otp_write_secure_lock_sel(self):
                opt = self.otp_write_secure_lock.get()
                if 1 ==opt :
                    self.otp_write_secure_lock_byte_lb_0.config(state="normal")
                    self.otp_write_secure_lock_byte_bar.config(state="normal")
                if 0 ==opt :
                    self.otp_write_secure_lock_byte_lb_0.config(state="disabled")
                    self.otp_write_secure_lock_byte_bar.config(state="disabled")     

            def otp_read_secure_lock_sel(self):
                opt = self.otp_read_secure_lock.get()
                if 1 ==opt :
                    self.otp_read_secure_lock_byte_lb_0.config(state="normal")
                    self.otp_read_secure_lock_byte_bar.config(state="normal")
                if 0 ==opt :
                    self.otp_read_secure_lock_byte_lb_0.config(state="disabled")
                    self.otp_read_secure_lock_byte_bar.config(state="disabled")     

            def cfg_lock_byte_0_sel(self):
                opt = self.cfg_lock_byte_0.get()
                if 1 ==opt :
                    self.cfg_lock_byte_0_val_lb_0.config(state="normal")
                    self.cfg_lock_byte_0_val_bar.config(state="normal")
                if 0 ==opt :
                    self.cfg_lock_byte_0_val_lb_0.config(state="disabled")
                    self.cfg_lock_byte_0_val_bar.config(state="disabled")     

            def cfg_lock_byte_1_sel(self):
                opt = self.cfg_lock_byte_1.get()
                if 1 ==opt :
                    self.cfg_lock_byte_1_val_lb_0.config(state="normal")
                    self.cfg_lock_byte_1_val_bar.config(state="normal")
                if 0 ==opt :
                    self.cfg_lock_byte_1_val_lb_0.config(state="disabled")
                    self.cfg_lock_byte_1_val_bar.config(state="disabled")     

            def cfg_lock_byte_2_sel(self):
                opt = self.cfg_lock_byte_2.get()
                if 1 ==opt :
                    self.cfg_lock_byte_2_val_lb_0.config(state="normal")
                    self.cfg_lock_byte_2_val_bar.config(state="normal")
                if 0 ==opt :
                    self.cfg_lock_byte_2_val_lb_0.config(state="disabled")
                    self.cfg_lock_byte_2_val_bar.config(state="disabled") 
            
            def cfg_lock_byte_3_sel(self):
                opt = self.cfg_lock_byte_3.get()
                if 1 ==opt :
                    self.cfg_lock_byte_3_val_lb_0.config(state="normal")
                    self.cfg_lock_byte_3_val_bar.config(state="normal")
                if 0 ==opt :
                    self.cfg_lock_byte_3_val_lb_0.config(state="disabled")
                    self.cfg_lock_byte_3_val_bar.config(state="disabled")     

            def cfg_lock_byte_4_sel(self):
                opt = self.cfg_lock_byte_4.get()
                if 1 ==opt :
                    self.cfg_lock_byte_4_val_lb_0.config(state="normal")
                    self.cfg_lock_byte_4_val_bar.config(state="normal")
                if 0 ==opt :
                    self.cfg_lock_byte_4_val_lb_0.config(state="disabled")
                    self.cfg_lock_byte_4_val_bar.config(state="disabled") 

            def ECDHPrivLCKsel(self):
                opt = self.ECDHPrivLCKvar.get()

            def ECDHPubLCKsel(self):
                opt = self.ECDHPubLCKvar.get()

            def TAG1sel(self):
            	opt = self.TAGvar_1.get()
            	if 1 ==opt:
            		self.TAGlbl23.config(state = "normal")
            		self.tagbar1.config(state = "normal")
            		self.tagAddr1.set("")
            		self.Tagflashvar_1bl.config(state="normal")
            		self.Tagflashvar_1_R1.config(state="normal")
            		self.Tagflashvar_1_R2.config(state="normal")   
            		self.Tagflashvar_1.set(0) 		
            	if 0 ==opt:
            		self.TAGlbl23.config(state = "disabled")
            		self.tagbar1.config(state = "disabled")
            		self.tagAddr1.set("")
            		self.Tagflashvar_1bl.config(state="disabled")
            		self.Tagflashvar_1_R1.config(state="disabled")
            		self.Tagflashvar_1_R2.config(state="disabled")
            		self.Tagflashvar_1.set(0)
            def TAG0sel(self):
                opt = self.TAGvar.get()
                if 1== opt:
                    self.tagbar.config(state="normal")
                    #self.tagbar1.config(state="normal")
                    self.TAGlbl2.config(state="normal")
                    #self.TAGlbl23.config(state="normal")
                    self.tagAddr.set("")
                    #self.tagAddr1.set("")
                    self.Tagflashvar_0bl.config(state="normal")
                    self.Tagflashvar_0_R1.config(state="normal")
                    self.Tagflashvar_0_R2.config(state="normal")
                    #self.tagflash0l1.config(state="normal")
                    #self.tag_flash_0_cb_0.config(state="normal")
                    #self.tag_flash_0_cb_1.config(state="normal")
                    #self.tag_flash_0_cb_2.config(state="disabled")
                    #self.tag_flash_0_cb_3.config(state="disabled")
                    #self.TAGlbl23.config(state="disabled")
                    #self.tagbar1.config(state="disabled")
                    #self.Tagflashvar_1bl.config(state="disabled")
                    #self.Tagflashvar_1_R1.config(state="disabled")
                    #self.Tagflashvar_1_R2.config(state="disabled")
                    #self.tagflash1l1.config(state="disabled")
                    self.Tagflashvar_0.set(0)
                    #self.Tagflashvar_1.set(0)
                    self.Tagflashvar_2.set(0)
                    self.Tagflashvar_3.set(0)
                    #self.tag_flash_1_cb.config(state="disabled")
                if 0== opt:    
                    self.tagbar.config(state="disabled")
                    #self.tagbar1.config(state="disabled")
                    self.TAGlbl2.config(state="disabled")
                    #self.TAGlbl23.config(state="disabled")
                    self.tagAddr.set("")
                    #self.tagAddr1.set("")
                    self.Tagflashvar_0bl.config(state="disabled")
                    self.Tagflashvar_0_R1.config(state="disabled")
                    self.Tagflashvar_0_R2.config(state="disabled")
                    #self.tagflash0l1.config(state="disabled")
                    #self.tag_flash_0_cb_0.config(state="disabled")
                    #self.tag_flash_0_cb_1.config(state="disabled")
                    #self.tag_flash_0_cb_2.config(state="disabled")
                    #self.tag_flash_0_cb_3.config(state="disabled")
                    #self.TAGlbl23.config(state="disabled")
                    #self.tagbar1.config(state="disabled")
                    #self.Tagflashvar_1bl.config(state="disabled")
                    #self.Tagflashvar_1_R1.config(state="disabled")
                    #self.Tagflashvar_1_R2.config(state="disabled")
                    #self.tagflash1l1.config(state="disabled")
                    self.Tagflashvar_0.set(0)
                    #self.Tagflashvar_1.set(0)
                    self.Tagflashvar_2.set(0)
                    self.Tagflashvar_3.set(0)
                    #self.tag_flash_1_cb.config(state="disabled")

            def sel_ecdhkeysel(self):  
            	opt = self.sel_ecdhkeyvar.get()
            	if 1 ==opt:
            		#self.ecdh_key_var_lbl.config(state="disabled")
            		#self.sel_ecdhkey_R11.config(state="disabled")
            		#self.sel_ecdhkey_R12.config(state="disabled")
                    self.ecdhkey.set("")
                    self.ecdhpass.set("")
                    self.custom_ecdh_key_bin.set("")
                    self.custom_ecdh_pass_key_bin.set("")
                    self.ecdh_key_bin.set("")
                    self.ecdh_en_key_bin.set("")
                    self.ECDHENC_CB.config(state="disabled")
                    self.ecdhkey_R12.config(state="disabled")
                    self.ecdh_key_var_check.config(state="disabled")
                    self.ecdh_en_key_var_check.config(state="disabled")
            		#self.ecdh_key_var_check.config(state="disabled")
                    self.ecdhbar.config(state="disabled")
                    self.ecdhbar_button.config(state="disabled")
                    self.ecdhpassbar.config(state="disabled")  
                    self.ecdh_key_outdirbar.config(state="disabled")  
                    self.ecdh_key_hash_button.config(state="disabled")  
                    self.ecdh_en_key_outdirbar.config(state="disabled")  
                    self.ecdh_en_key_hash_button.config(state="disabled")  
                    self.custom_ecdh_key_outdirbar.config(state="disabled")  
                    self.custom_ecdh_key_hash_button.config(state="disabled")  
                    self.custom_ecdh_pass_key_outdirbar.config(state="disabled")  
                    #self.ecdh_key_outdirbar.config(state="disabled")
                    #self.ecdh_key_hash_button.config(state="disabled")
                    self.ecdh_key_var_check.config(state="normal")
                    self.ecdh_en_key_var_check.config(state="normal")
                    self.custom_ecdh_key_bin.set("")
                    self.custom_ecdh_pass_key_bin.set("")
                    self.ecdh_key_bin.set("")
                    self.ecdh_en_key_bin.set("")
                    self.ECDHENCvar.set(0)  
                    self.ecdhkeyvar.set(0)  
                    self.ecdh_key_var.set(0)
                    self.ecdh_en_key_var.set(0)
                    self.ecdhkey_lbl.config(state="disabled")  
                    self.ecdhkey_R12.config(state="disabled")
                    #self.ecdhkey.set("")
                    #self.ecdh_en_key_var.set("")
                    #self.ecdh_key_var.set("")
            		#self.ecdh_en_key_outdirbar.config(state="disabled")
            		#self.ecdh_en_key_hash_button.config(state="disabled")
            	if 0==opt:
            		#self.sel_ecdhkey_R11.config(state="normal")
            		#self.sel_ecdhkey_R12.config(state="normal")
                    self.ecdhkey.set("")
                    self.ecdhpass.set("")
                    self.custom_ecdh_key_bin.set("")
                    self.custom_ecdh_pass_key_bin.set("")
                    self.ecdh_key_bin.set("")
                    self.ecdh_en_key_bin.set("")
                    self.ECDHENC_CB.config(state="normal")
                    self.ecdhkey_R12.config(state="normal")
                    self.ecdh_key_var_check.config(state="normal")
                    self.ecdh_en_key_var_check.config(state="normal")
                    #self.ecdh_key_var_check.config(state="normal")
                    self.ecdhbar.config(state="normal")
                    self.ecdhbar_button.config(state="normal")
                    self.ecdhpassbar.config(state="normal")  
            		#self.ecdh_key_outdirbar.config(state="normal")
            		#self.ecdh_key_hash_button.config(state="normal")
                    self.ecdh_key_var_check.config(state="disabled")
                    self.ecdh_en_key_var_check.config(state="disabled")    
                    self.custom_ecdh_key_bin.set("")
                    self.custom_ecdh_pass_key_bin.set("")
                    self.ecdh_key_bin.set("")
                    self.ecdh_en_key_bin.set("")   
                    self.ECDHENCvar.set(0)  
                    self.ecdhkeyvar.set(0) 
                    self.ecdh_key_var.set(0)
                    self.ecdh_en_key_var.set(0)
                    self.ecdh_key_outdirbar.config(state="disabled")  
                    self.ecdh_key_hash_button.config(state="disabled")  
                    self.ecdh_en_key_outdirbar.config(state="disabled")  
                    self.ecdh_en_key_hash_button.config(state="disabled")  
                    self.ecdhkey_lbl.config(state="disabled")  
                    self.ecdhkey_R12.config(state="disabled")                 		
            def ENCsel(self):
            	opt = self.ENCvar.get()
            	if 1 ==opt:
            		#self.ecdh_key_var_lbl.config(state="disabled")
            		self.sel_ecdhkey_R11.config(state="normal")
            		self.sel_ecdhkey_R12.config(state="normal")
            		self.ECDHENC_CB.config(state="normal")
            		self.ecdhkey_R12.config(state="normal")
            		self.ecdh_key_var_check.config(state="normal")
            		self.ecdh_en_key_var_check.config(state="normal")
            		#self.ecdh_key_var_check.config(state="normal")
            		self.ecdhbar.config(state="normal")
            		self.ecdhbar_button.config(state="normal")
            		self.ecdhpassbar.config(state="normal") 
            		self.sel_ecdhkeyvar.set(0) 
            		self.custom_ecdh_key_bin.set("")
            		self.custom_ecdh_pass_key_bin.set("")
            		self.ecdh_key_bin.set("")
            		self.ecdh_en_key_bin.set("")
            		self.ECDHENCvar.set(0)  
            		self.ecdhkeyvar.set(0)
            		self.ecdh_key_var.set(0)
            		self.ecdh_en_key_var.set(0)
            		self.ecdh_key_outdirbar.config(state="disabled")  
            		self.ecdh_key_hash_button.config(state="disabled")  
            		self.ecdh_en_key_outdirbar.config(state="disabled")  
            		self.ecdh_en_key_hash_button.config(state="disabled")  
            		self.ecdhkey_lbl.config(state="disabled")  
            		self.ecdhkey_R12.config(state="disabled")  
            		#self.ecdh_key_outdirbar.config(state="normal")
            		#self.ecdh_key_hash_button.config(state="normal")
            		if 0 == self.sel_ecdhkeyvar.get():
        	    		self.ecdh_key_var_check.config(state="disabled")
        	    		self.ecdh_en_key_var_check.config(state="disabled") 
            		# self.ECDHENC_CB.config(state="disabled")
            		# self.ecdhkey_R12.config(state="disabled")
            		# self.ecdh_key_var_check.config(state="disabled")
            		# self.ecdh_en_key_var_check.config(state="disabled")
            		# #self.ecdh_key_var_check.config(state="disabled")
            		# self.ecdhbar.config(state="normal")
            		# self.ecdhpassbar.config(state="normal")  
            		# #self.ecdh_key_outdirbar.config(state="disabled")
            		# #self.ecdh_key_hash_button.config(state="disabled")
            		# self.ecdh_en_key_var_check.config(state="disabled")
                    #self.ecdh_en_key_var.set("")
                    #self.ecdh_key_var.set("")
            		#self.ecdh_en_key_outdirbar.config(state="disabled")
            		#self.ecdh_en_key_hash_button.config(state="disabled")
            	if 0==opt:
            		self.sel_ecdhkey_R11.config(state="disabled")
            		self.sel_ecdhkey_R12.config(state="disabled")
            		self.ECDHENC_CB.config(state="disabled")
            		self.ecdhkey_R12.config(state="disabled")
            		self.ecdh_key_var_check.config(state="disabled")
            		self.ecdh_en_key_var_check.config(state="disabled")
            		#self.ecdh_key_var_check.config(state="disabled")
            		self.ecdhbar.config(state="disabled")
            		self.ecdhbar_button.config(state="disabled")
            		self.ecdhpassbar.config(state="disabled")  
            		self.sel_ecdhkeyvar.set(0) 
            		self.custom_ecdh_key_bin.set("")
            		self.custom_ecdh_pass_key_bin.set("")
            		self.ecdh_key_bin.set("")
            		self.ecdh_en_key_bin.set("")
            		self.ECDHENCvar.set(0)  
            		self.ecdhkeyvar.set(0)
            		self.ecdh_key_var.set(0)
            		self.ecdh_en_key_var.set(0)
            		self.ecdh_key_outdirbar.config(state="disabled")  
            		self.ecdh_key_hash_button.config(state="disabled")  
            		self.ecdh_en_key_outdirbar.config(state="disabled")  
            		self.ecdh_en_key_hash_button.config(state="disabled")  
            		#self.ecdh_key_outdirbar.config(state="disabled")
            		#self.ecdh_key_hash_button.config(state="disabled")
            		if 1 == self.sel_ecdhkeyvar.get():
        	    		self.ecdh_key_var_check.config(state="disabled")
        	    		self.ecdh_en_key_var_check.config(state="disabled")
            		# self.ECDHENC_CB.config(state="normal")
            		# self.ecdhkey_R12.config(state="normal")
            		# self.ecdh_key_var_check.config(state="normal")
            		# self.ecdh_en_key_var_check.config(state="disabled")
            		# #self.ecdh_key_var_check.config(state="normal")
            		# self.ecdhbar.config(state="disabled")
            		# self.ecdhpassbar.config(state="disabled")  
            		# #self.ecdh_key_outdirbar.config(state="normal")
            		# #self.ecdh_key_hash_button.config(state="normal")
            		# self.ecdh_en_key_var_check.config(state="normal")
            		#self.ecdh_en_key_outdirbar.config(state="normal")
            		#self.ecdh_en_key_hash_button.config(state="normal")
                # opt = self.ENCvar.get()
                # if 1== opt:
                #     selection = "Enter below Fields"
                #     self.ecdhbar.config(state="normal")
                #     self.ecdhpassbar.config(state="normal")  
                #     self.ECDHENC_CB.config(state="normal")
                #     '''
                #     self.ECDHLCK_CB.config(state="normal")
                #     '''
                #     self.ECDHPrivLCK_CB.config(state="normal")
                #     #self.ECDHPubLCK_CB.config(state="normal")
                #     #AK
                #     self.ecdhkey.set("Please enter Filename")
                #     self.ecdhpass.set("Please enter Password")
                #     self.ECDHENClbl.config(text = " ")
                # if 0== opt:    
                #     selection = "Ignore below Fields"
                #     self.ecdhbar.config(state="disabled")
                #     self.ecdhpassbar.config(state="disabled")  
                #     self.ECDHENC_CB.config(state="disabled")
                #     '''
                #     self.ECDHLCK_CB.config(state="disabled")
                #     '''
                #     self.ECDHPrivLCK_CB.config(state="disabled")
                #     self.ECDHPubLCK_CB.config(state="disabled")
                #     self.ECDHPubLCKvar.set(0)
                #     '''
                #     self.ECDHENCvar.set(0)
                #     self.ECDHENClbl.config(text = " ")
                #     self.ECDHLCKvar.set(0)
                #     self.ECDHLCKlbl.config(text = " ")
                #     '''
                #     self.ecdhkey.set("")
                #     self.ecdhpass.set("")
                #     self.ECDHENCvar.set(0)
                #     self.ECDHPrivLCKvar.set(0)
                #     self.AEMvar.set(0)
                #     self.ECDHENClbl.config(text = " ")
                #     #self.ECDHPubLCKvar.set(0)
                # self.ENClbl.config(text = selection)  

                
            def ATEsel(self):
                opt = self.ATEvar.get()
                if 1== opt:
                    selection = "ATE Mode Enabled "
                if 0== opt:    
                    selection = "ATE Mode Disabled "
                self.ATElbl.config(text = selection)

            def tagflashkeysel0(self):
               opt = self.Tagflashvar_2.get()
               if 1==opt:
                    #self.tag_flash_0_cb_2.config(state="normal")
                    #self.tag_flash_0_cb_3.config(state="normal")
                    self.TAGlbl23.config(state="normal")
                    self.tagbar1.config(state="normal")
                    self.Tagflashvar_1bl.config(state="normal")
                    self.Tagflashvar_1_R1.config(state="normal")
                    self.Tagflashvar_1_R2.config(state="normal")
                    #self.tagflash1l1.config(state="normal")
               if 0 ==opt:
                    #self.tag_flash_0_cb_2.config(state="disabled")
                    #self.tag_flash_0_cb_3.config(state="disabled")
                    self.TAGlbl23.config(state="disabled")
                    self.tagbar1.config(state="disabled")
                    self.Tagflashvar_1bl.config(state="disabled")
                    self.Tagflashvar_1_R1.config(state="disabled")
                    self.Tagflashvar_1_R2.config(state="disabled")
                    #self.tagflash1l1.config(state="disabled")

            def RollProtsel(self):
                pass
            def Rollsel(self):
                opt = self.Rollvar.get()
                if 1 ==opt:
                    self.MRollR1.config(state="normal")
                    self.MRollR2.config(state="normal")
                if 0 ==opt:
                    self.MRollR1.config(state="disabled")
                    self.MRollR2.config(state="disabled")    
                    self.MRollvar.set(0)
            def MRollsel(self):
                pass
            def ecdsakeyrevsel(self):
                pass
            def ecdsakeysel(self):
                opt = self.ecdsakeyvar.get()
                if 1 ==opt:
                    self.MecdsakeyR1.config(state="normal")
                    self.MecdsakeyR2.config(state="normal")
                if 0 ==opt:
                    self.MecdsakeyR1.config(state="disabled")
                    self.MecdsakeyR2.config(state="disabled")    
                    self.Mecdsakeyvar.set(0)
            def combokeysel(self):
                pass
            def dumm(self):
                pass
            def Mecdsakeysel(self):
                pass
            def dicesel(self):
                pass
            def AEMsel(self):
            	pass    

            def fullysel(self):
                pass
                # global AEMvar_flag
                # print("Enter AEMsel ")
                # if 0 == AEMvar_flag:
                #      AEMvar_flag = 1
                #      opt = self.AEMvar.get()
                #      print("Enter AEMsel 1")
                #      if 1== opt:
                #          val = self.ENCvar.get()
                #          print("Enter AEMsel 2")
                #          if 0 == val:
                #              messagebox.showinfo('AES Mandatory encryption', 'Please select the option in the GUI to make use of "AES Encryption Mandatory" bit : "Use Code Encryption Keys" for the plain ECDH key or select the "Encrypt ECDH Key" , if not selected , it will be in "Disabled" state')
                #              AEMvar_flag = 0
                #              print("Enter AEMsel 3")
                #              self.AEMvar.set(0)
                    
            def hashbrowsefldr_1(self):
                pathdir = os.getcwd()
                pathdir = pathdir+"\\"
                path = askopenfilename(initialdir=pathdir,
                                   filetypes =(("PEM File", "*.pem"),("All Files","*.*"))
                                   #title = "set path Openssl.exe"
                                   )
                path = "\\".join(path.split('/'))                   
                path = path.replace(pathdir,'')
                self.ecdsa_sha384_key_hash_bin.set(path)       

            def plat_hashbrowsefldr_1(self):
                pathdir = os.getcwd()
                pathdir = pathdir+"\\"
                path = askopenfilename(initialdir=pathdir,
                                   filetypes =(("PEM File", "*.pem"),("All Files","*.*"))
                                   #title = "set path Openssl.exe"
                                   )
                path = "\\".join(path.split('/'))                   
                path = path.replace(pathdir,'')
                self.plat_ecdsa_sha384_key_hash_bin.set(path)   
                
            def hashbrowsefldr(self):
                pathdir = os.getcwd()
                pathdir = pathdir+"\\"
                path = askopenfilename(initialdir=pathdir,
                                   filetypes =(("BIN File", "*.bin"),("All Files","*.*"))
                                   #title = "set path Openssl.exe"
                                   )
                path = "\\".join(path.split('/'))                   
                path = path.replace(pathdir,'')
                self.ecdsa_key_hash_bin.set(path)     

            def AUTHselen(self):
                opt = self.AUTHEnvar.get()
                if 1== opt:
                    selection = "Authentication Enabled "
                    #self.ecdsa_key_lbl.config(state="normal")
                    self.ecdsa_key_hash_check.config(state="normal")
                    #self.ecdsa_key_outdirbar.config(state="normal")
                    #self.self.ecdsa_key_hash_button.config(state="normal")
                    #self.DSWlbl.config(state="normal")
                    #self.DSWbar0.config(state="normal")
                    #self.ecdsaaddresslbl.config(state="normal")
                    #self.ecdsaaddressbar0.config(state="normal")
                    #self.ecdsaaddress_1_lbl.config(state="normal")
                    #self.ecdsaaddressbar_1.config(state="normal")
                    self.ECCP384lbl.config(state="normal")
                    self.ECCR11.config(state="normal")
                    self.ECCR12.config(state="normal")
                    self.ECCP384var.set(0)
                    #self.ecdsa_key_hash_check_var.set(1)
                    #self.ecdsabar.config(state="normal")
                    #self.ecdsapassbar.config(state="normal")   
                    #AK
                    #self.ecdsakey.set("Please enter Filename")
                    #self.ecdsapass.set("Please enter Password")
                    #self.ECDSALCK_CB.config(state ="normal")
                    self.ecdsa_key_hash_lbl.config(text =" ")
                    self.ecdsa_key_hash_lbl.config(text =" ")
                    self.ecdsa_sha384_key_hash_bin.set("")
                    self.ecdsa_key_hash_bin.set("")
                    self.ecdsa_sha384_key_outdirbar.config(state="disabled")
                    self.ecdsa_sha384_key_hash_button.config(state="disabled")
                if 0== opt:    
                    selection = "Authentication Disabled "
                    #self.ecdsa_key_lbl.config(state="disabled")
                    self.ecdsa_key_hash_check.config(state="disabled")
                    self.ecdsa_key_outdirbar.config(state="disabled")
                    #self.self.ecdsa_key_hash_button.config(state="disabled")
                    self.ecdsa_key_hash_check_var.set(0)
                    #self.DSWlbl.config(state="disabled")
                    #self.DSWbar0.config(state="disabled")
                    #self.ecdsaaddresslbl.config(state="disabled")
                    #self.ecdsaaddressbar0.config(state="disabled")
                    #self.ecdsaaddress_1_lbl.config(state="disabled")
                    #self.ecdsaaddressbar_1.config(state="disabled")
                    self.ECCP384lbl.config(state="disabled")
                    self.ECCR11.config(state="disabled")
                    self.ECCR12.config(state="disabled")
                    self.ECCP384var.set(0)
                    #self.ECDSALCK_CB.config(state ="disabled")
                    #self.ECDSALCKvar.set(0)
                    self.ecdsa_key_hash_lbl.config(text =" ")
                    self.ecdsa_sha384_key_hash_bin.set("")
                    self.ecdsa_key_hash_bin.set("")
                    self.ecdsa_sha384_key_outdirbar.config(state="disabled")
                    self.ecdsa_sha384_key_hash_button.config(state="disabled")

            def AUTHsel(self):
                opt = self.AUTHvar.get()
                if 1== opt:
                    selection = "Authentication Enabled "
                    #self.ecdsabar.config(state="normal")
                    #self.ecdsapassbar.config(state="normal")   
                    #AK
                    #self.ecdsakey.set("Please enter Filename")
                    #self.ecdsapass.set("Please enter Password")
                    #self.ECDSALCK_CB.config(state ="normal")
                if 0== opt:    
                    selection = "Authentication Disabled "
                    #self.ecdsabar.config(state="disabled")
                    #self.ecdsapassbar.config(state="disabled")  
                    #self.ecdsakey.set("")
                    #self.ecdsapass.set("")
                    #self.ECDSALCK_CB.config(state ="disabled")
                    #self.ECDSALCKvar.set(0)
                #self.AUTHlbl.config(text = selection)     
                


            def DESWsel(self):
                global dswgpiosel
                opt = self.DESWvar.get()
                if 1== opt:
                    self.WDTbl2.config(state="normal")
                    self.WDTEN_CB.config(state="normal")
                if 0== opt:      
                    # self.R18.config(state="disabled")
                    # self.R19.config(state="disabled")
                    # self.R20.config(state="disabled")            
                    # self.R21.config(state="disabled")
                    self.WDTbl2.config(state="disabled")    
                    self.WDTEN_CB.config(state="disabled")
                    self.WDTDelay.set(0) 
                    self.WDTENvar.set(0)  

            def PRIMsel1(self):
                opt = self.PRIMvar1.get()
                if 1== opt:
                    #self.WDTbl2.config(state="normal")
                    #self.WDTEN_CB.config(state="normal")
                    self.PRIMbar1.config(state="normal")
                    self.PRIM1.config(state="normal")
                if 0== opt:      
                    self.PR2.config(state="disabled")
                    self.PR3.config(state="disabled")
                    self.PRIMbar1.config(state="disabled")
                    self.PRIMgpio_1.set("")
                    self.PRIMbar1.config(state="disabled")

            def PRIMsel(self):
                global primgpiosel_0
                opt = self.PRIMvar0.get()
                if 1== opt:
                    #self.WDTbl2.config(state="normal")
                    #self.WDTEN_CB.config(state="normal")
                    self.PRIMbar.config(state="normal")
                    self.PRIMlbl3.config(state="normal")
                if 0== opt:      
                    self.PR0.config(state="disabled")
                    self.PR1.config(state="disabled")
                    self.PRIMbar.config(state="disabled")
                    self.PRIMgpio_0.set("")
                    self.PRIMlbl3.config(state="disabled")
                    primgpiosel_0 = 0 

            def DSWsel(self):
                global dswgpiosel
                opt = self.DSWvar.get()
                if 1== opt:
                    self.WDTbl2.config(state="normal")
                    self.WDTEN_CB.config(state="normal")
                    self.DSWbar.config(state="normal")
                    self.DSWlbl3.config(state="normal")
                if 0== opt:      
                    self.R18.config(state="disabled")
                    self.R19.config(state="disabled")
                    self.R20.config(state="disabled")            
                    self.R21.config(state="disabled")
                    self.WDTbl2.config(state="disabled")    
                    self.WDTEN_CB.config(state="disabled")
                    self.DSWbar.config(state="disabled")
                    self.WDTDelay.set(0) 
                    self.WDTENvar.set(0)  
                    self.DSWgpio.set("")
                    self.DSWlbl3.config(state="disabled")
                    dswgpiosel = 0 
                    
            def WDTdelayset(self):
                pass
            
            def WDTENsel(self):  
                opt = self.WDTENvar.get()
                if 1== opt:
                    self.WDTbl2.config(state="normal")
                    #self.R18.config(state="normal")
                    #self.R19.config(state="normal")
                    #self.R20.config(state="normal")
                    #self.R21.config(state="normal")
                    #self.WDTDelay.set(0)
                if 0== opt: 
                    self.WDTbl2.config(state="disabled") 
                    #self.R18.config(state="disabled")
                    #self.R19.config(state="disabled")
                    #self.R20.config(state="disabled")            
                    #self.R21.config(state="disabled")
                    #self.WDTDelay.set(0)
                    
            def JTAGsel(self):
                global jtag_disbale_flag
                opt = self.JTAGvar.get()
                if 0== opt:
                    selection = "JTAG Debug Disable is Enabled "
                    jtag_disbale_flag = 0
                if 1== opt:    
                    selection = "JTAG Debug Disable is Disabled "
                    jtag_disbale_flag = 1
                #self.JTAGlbl.config(text = selection)          

            def COMPsel(self):
                opt = self.COMPvar.get()
                if 1== opt:
                    selection = "CMP_STRAP "
                if 0== opt:    
                    selection = "CMP_STRAP"
                self.COMPlbl.config(text = selection)   

            def SUSsel(self):
                opt = self.SUSvar.get()
                if 1== opt:
                    selection = "SUS_5V"
                if 0== opt:    
                    selection = "SUS_5V"
                self.SUSlbl.config(text = selection)
                
                        
            def chk_aeskey_ini(self):
                try:
                    aesk_f = open("aeskey.ini","rt")   
                    for lines in aesk_f:
                        if lines == "":
                            self.aeskey.set("Path for AES Key")
                            return            
                        self.aeskey.set(str(lines))
                except:
                    self.aeskey.set("Path for AES Key")       
            def browsecsv(self):
                filename = askopenfilename(initialdir="C:\\",
                                   filetypes =(("All Files","*.*"),("exe File", "*.exe")),
                                   title = "Choose a file"
                                   )
                filename = "\\".join(filename.split('/'))                    
                self.aeskey.set(filename)
                with open("aeskey.ini","wt+") as aesk_f:  
                    aesk_f.write(filename)
                aesk_f.close()
                        
            def browse_custom_file(self):
                global custom_data
                global ref_active
                global msgidx
                global custdatexd
                global otp_lock_15
                global otp_lock_16
                global otp_lock_17
                global otp_lock_18
                global otp_lock_19
                global otp_lock_20
                global otp_lock_21
                global otp_lock_22
                global otp_lock_23
                global otp_lock_24
                global otp_lock_25
                global otp_lock_26
                global otp_lock_27
                global otp_lock_28
                global otp_lock_29
                global otp_lock_30
                global otp_write_lock_en
                global cust_enter_var
                global browse_custom_file_val

                if 0 == browse_custom_file_val:
                     idx = self.custIDX.get()
                     hexordec = self.Hex2Dec.get()
                     if 1==hexordec:
                         try:
                             idx = int(idx,16)
                         except:
                             idx = 0
                     if 0 == hexordec:
                         try:
                             idx = int(idx,10)
                         except:
                             idx = 0
                     if 0 == idx:
                          idx = 672#480#192
                     

                     if idx > 863:
                          msgidx = 9
                          error_windox()
                          return

                     browse_custom_file_val = 1    
                     pathdir = os.getcwd()
                     pathdir = pathdir+"\\"
                     filename = askopenfilename(initialdir=pathdir,
                                        filetypes =(("All Files","*.*"),("txt File", "*.txt")),
                                        title = "Choose a file"
                                        )
                     fldname = "\\".join(filename.split('/'))                    
                     filename = fldname.replace(pathdir,'')  
                     filename1 = filename.split("\\")    
                     self.CustFilekey.set(filename1[-1])
                     with open("CustFilekey.ini","wt+") as custom_f:  
                         custom_f.write(filename)
                     custom_f.close()
                     try:
                         CustFilekey = open(fldname,"rt+")
                     except:
                         return
                 
                     for line in CustFilekey:
                         CUSTMDAT = list(line)
                         CUSTMDAT = CUSTMDAT[0:]
                         
                         endoff = len(CUSTMDAT)
                         cust_enter_var =1
                         key = []
                         for j in range(0,endoff-1,2):
                             key.append(CUSTMDAT[j]+CUSTMDAT[j+1])
                         endoff = 863+1#479+1
                         for item in key:
                             if (idx < endoff):
                                 item = int(item,16)
                                 temp= ((item<<16) & 0x00FF0000)| idx & 0xFFFF;#0x1FF;
                                 temp = struct.pack('I',temp)
                                 once = True
                                 # if(idx >480 and idx < 511):
                                 #     otp_lock_15 = 1
                                 #     otp_write_lock_en = 1
                                 # if(idx > 511 and idx < 544):
                                 #     otp_lock_16 = 1
                                 #     otp_write_lock_en = 1
                                 # if(idx >544 and idx < 576):
                                 #     otp_lock_17 = 1
                                 #     otp_write_lock_en = 1
                                 # if(idx >576 and idx < 608):
                                 #     otp_lock_18 = 1
                                 #     otp_write_lock_en = 1
                                 # if(idx > 608 and idx <640):
                                 #     otp_lock_19 = 1
                                 #     otp_write_lock_en = 1
                                 # if(idx >640 and idx < 672):
                                 #     otp_lock_20 = 1
                                 #     otp_write_lock_en = 1
                                 if(idx >672 and idx < 704):
                                     otp_lock_21 = 1
                                     otp_write_lock_en = 1
                                 if(idx >704 and idx < 736):
                                     otp_lock_22 = 1
                                     otp_write_lock_en = 1
                                 if(idx >736 and idx < 768):
                                     otp_lock_23 = 1
                                     otp_write_lock_en = 1
                                 if(idx >768 and idx < 800):
                                     otp_lock_24 = 1
                                     otp_write_lock_en = 1
                                 if(idx >800 and idx < 832):
                                     otp_lock_25 = 1
                                     otp_write_lock_en = 1
                                 if(idx >832 and idx < 864):
                                     otp_lock_26 = 1
                                     otp_write_lock_en = 1
                                 if(idx >864 and idx < 896):
                                     otp_lock_27 = 1
                                     otp_write_lock_en = 1
                                 if(idx >896 and idx < 928):
                                     otp_lock_28 = 1
                                     otp_write_lock_en = 1
                                 if(idx >928 and idx < 960):
                                     otp_lock_29 = 1
                                     otp_write_lock_en = 1
                                 if(idx >960 and idx < 991):
                                     otp_lock_30 = 1
                                     otp_write_lock_en = 1
                                 for items in custom_data:
                                     val = (int(binascii.hexlify(items), 16)) & 0xFFFF0000 #0xFF010000
                                     cntval = (int(binascii.hexlify(temp), 16)) & 0xFFFF0000 #0xFF010000
                                     if val == cntval:
                                         inst = custom_data.index(items)
                                         custom_data.remove(items )
                                         custom_data.insert(inst,temp )
                                         once = False
                                 if True == once:
                                     if idx > 863:
                                         custdatexd = custdatexd + 1
                                     custom_data.append(temp)
                             idx = idx + 1
                         if (idx > 863+1):#479+1): 
                             custdatexd = True
                             idx = 863#479
                         self.custIDX.set(hex(idx).upper().split('X')[1])   
                                     
                     CustFilekey.close()

                     #if(idx >= 480):
                     #    custom_window()
                     if (0 == ref_active):
                         self.view_menu()
                     browse_custom_file_val = 0

            def CusDATEntryVald(self, *dummy):
                #global error_windox3_flag
                dat = self.custDAT.get()
                hexordec = self.Hex2Dec.get()
                global cust_data_enter_flag
             
                if 1==hexordec:
                    if len(dat) >= 3:
                         #error_windox3()
                         self.custDAT.set("")
                         return
                        #self.custDAT.set(0)    
                if 0 == hexordec:
                    try:
                        dat1 = int(dat,10)
                        if len(dat) >= 4 or dat1 >=256 :
                            #error_windox2()
                            self.custDAT.set("")
                            return
                    except ValueError:
                        self.custDAT.set("00")
                  
                #if 1 == error_windox3_flag:
                #     print("its opened")
                #     error_windox3().show_window()

            def CusIDXEntryVald(self, *dummy):
                dat = self.custIDX.get()
                hexordec = self.Hex2Dec.get()
                global cust_idx_enter_flag
                if 1==hexordec:
                    val = 16
                if 0 == hexordec:
                    val = 10
                    
                try:
                    dat1 = int(dat,val)
                    if 992 == dat1:
                        #error_windox1()
                        return
                except ValueError:
                    self.custIDX.set("")
                    
                if "00" == dat or len(dat) >= 4: 
                    self.custIDX.set("")
                    
            def Custenter(self):
                global cust_enter_var
                global otp_lock_15
                global otp_lock_16
                global otp_lock_17
                global otp_lock_18
                global otp_lock_19
                global otp_lock_20
                global otp_lock_21
                global otp_lock_22
                global otp_lock_23
                global otp_lock_24
                global otp_lock_25
                global otp_lock_26
                global otp_lock_27
                global otp_lock_28
                global otp_lock_29
                global otp_lock_30
                global otp_write_lock_en
                global write_lock_flag_15
                global write_lock_flag_16
                global write_lock_flag_17
                global write_lock_flag_18
                global write_lock_flag_19
                global write_lock_flag_20
                global write_lock_flag_21
                global write_lock_flag_22
                global write_lock_flag_23
                global write_lock_flag_24
                global write_lock_flag_25
                global write_lock_flag_26
                global write_lock_flag_27
                global write_lock_flag_28
                global write_lock_flag_29
                global write_lock_flag_30

                global cust_idx_enter_flag
                global cust_data_enter_flag
                self.CustFilekey.set("")
                idx = self.custIDX.get()
                dat = self.custDAT.get()

                if 0 == cust_idx_enter_flag:
                     try:
                          if idx == "":
                               cust_idx_enter_flag = 1
                               selected = messagebox.showerror("Custome IDX error window", "Index is not empty : Provide Index (Dec - 576 - 863) ,(Hex -  240 - 35F)")#selected = messagebox.showerror("Custome IDX error window", "Index is not empty : Provide Index (Dec - 480 - 991) ,(Hex -  1E0 - 3DF)")
                               if "ok" == selected:
                                    cust_idx_enter_flag = 0
                                    return
                               else:
                                    cust_idx_enter_flag = 0
                     except:
                          cust_idx_enter_flag = 0
                          return

                
                     
                hexordec = self.Hex2Dec.get()
                if 1==hexordec:
                    if len(dat) >= 3:
                        #self.custDAT.set(0)
                        #error_windox3()
                        self.custDAT.set("")
                        return
                if 0 == hexordec:
                    try:
                        dat1 = int(dat,10)
                        if len(dat) >= 4 or dat1 >=256 :
                            #error_windox1()
                            self.custDAT.set("")
                            return
                    except ValueError:
                        self.custDAT.set("")
                        
                        
                global custom_data
                global ref_active
                once = True
                hexordec = self.Hex2Dec.get()
                if 1==hexordec:
                    try:
                        idx = int(idx,16)
                    except:
                        idx = 0
                    try:
                        dat = int(dat,16)
                    except:
                        dat = 0
                if 0 == hexordec:
                    try:
                        idx = int(idx,10)
                    except:
                        idx = 0
                    try:
                        dat = int(dat,10)
                    except:
                        dat = 0

                dat1 =dat
                if idx not in range(576,863+1):#(480,991+1):#(192, 415+1):
                     if 0 == cust_idx_enter_flag:
                        cust_idx_enter_flag = 1
                        #self.hex.config(state="disabled")
                        #self.dec.config(state="disabled")
                        selected = messagebox.showerror("Custome IDX error window", "Index (Dec - 576 - 863) ,(Hex -  240 - 35F)  is out of range ")
                        #selected = messagebox.showerror("Custome IDX error window", "Index (Dec - 480 - 991) ,(Hex -  1E0 - 3DF)  is out of range ")
                        if "ok" == selected:
                           cust_idx_enter_flag = 0
                           #self.hex.config(state="normal")
                           #self.dec.config(state="normal")
                     return
                temp= ((dat<<16) & 0x00FF0000)| idx & 0xFFFF;#0x1FF;
                temp = struct.pack('I',temp)       
                for items in custom_data:
                    val = (int(binascii.hexlify(items), 16)) & 0xFFFF0000 #0xFF010000
                    cntval = (int(binascii.hexlify(temp), 16)) & 0xFFFF0000 #0xFF010000
                    if val == cntval:
                        inst = custom_data.index(items)
                        custom_data.remove(items )
                        custom_data.insert(inst,temp )
                        once = False
                if True == once:       
                    custom_data.append(temp)
            
                idx = self.custIDX.get()  
                if 1==hexordec:
                    idx = int(idx,16)
                    if idx > 863:
                        error_windox1()
                        return
                    else:
                        idx = idx + 1
                        if idx == 864:
                            idx = 863
                        self.custIDX.set(hex(idx).upper().split('X')[1])
                else:
                    idx = int(idx,10)
                    if idx > 863:
                        error_windox1()
                        return
                    else:
                        idx = idx + 1
                        if idx == 864:
                            idx = 863
                        self.custIDX.set(idx)
                dat = int(0)    
                self.custDAT.set(dat)
                cust_enter_var = 1
                # if(idx >480 and idx <= 512):
                #    otp_lock_15 = 1
                #    otp_write_lock_en = 1

                # if(idx > 512 and idx <= 544):
                #    otp_lock_16 = 1
                #    otp_write_lock_en = 1

                # if(idx >544 and idx <= 576):
                #    otp_lock_17 = 1
                #    otp_write_lock_en = 1

                # if(idx >576 and idx <= 608):
                #    otp_lock_18 = 1
                #    otp_write_lock_en = 1

                # if(idx > 608 and idx <= 640):
                #    otp_lock_19 = 1
                #    otp_write_lock_en = 1

                # if(idx >640 and idx <= 672):
                #    otp_lock_20 = 1
                #    otp_write_lock_en = 1

                if(idx >672 and idx <= 704):
                   otp_lock_21 = 1
                   otp_write_lock_en = 1

                if(idx >704 and idx <= 736):
                   otp_lock_22 = 1
                   otp_write_lock_en = 1
                if(idx >736 and idx <= 768):
                   otp_lock_23 = 1
                   otp_write_lock_en = 1

                if(idx >768 and idx <= 800):
                   otp_lock_24 = 1
                   otp_write_lock_en = 1

                if(idx >800 and idx <= 832):
                   otp_lock_25 = 1
                   otp_write_lock_en = 1

                if(idx >832 and idx <= 864):
                   otp_lock_26 = 1
                   otp_write_lock_en = 1

                if(idx >864 and idx <= 896):
                   otp_lock_27 = 1
                   otp_write_lock_en = 1

                if(idx >896 and idx <= 928):
                   otp_lock_28 = 1
                   otp_write_lock_en = 1

                if(idx >928 and idx <= 960):
                   otp_lock_29 = 1
                   otp_write_lock_en = 1

                if(idx >960 and idx <= 991):
                   otp_lock_30 = 1
                   otp_write_lock_en = 1

                if (0 == ref_active):
                    self.view_menu()
                #if 1 ==otp_write_lock_en and 1 == cust_enter_var:
                #    custom_window()
                    
            def hex2dec(self): 
                hexordec = self.Hex2Dec.get()
                idx = self.custIDX.get()
                dat = self.custDAT.get()
                if "" ==idx or " " ==idx:
                    #self.custIDX.set("1E0")
                    self.custIDX.set("240")
                if "" ==dat or " " ==dat:
                    self.custDAT.set("00")   
                if 0==hexordec:
                    try:
                        idx = int(idx,16)
                        dat = int(dat,16)
                        self.custIDX.set(idx)
                        self.custDAT.set(dat)
                    except ValueError:
                        self.custIDX.set("576")#self.custIDX.set("480")
                        self.custDAT.set(0)
                if 1==hexordec:
                    try:
                        idx = (int(idx,10))
                        idx = hex(idx).upper().split('X')[1]
                        dat = (int(dat,10))
                        dat = hex(dat).upper().split('X')[1]
                        self.custIDX.set(idx)
                        self.custDAT.set(dat)
                    except ValueError:
                        self.custIDX.set("240")#self.custIDX.set("1E0")
                        self.custDAT.set(0)
                
            def browsefldr(self):
                global browsefldr_flag
                if 0 == browsefldr_flag:
                     try:
                          browsefldr_flag =1
                          pathdir = os.getcwd()
                          pathdir = pathdir+"\\"
                          fldname = askdirectory(initialdir=pathdir,
                                             title = "Choose a folder"
                                             )
                                             
                          fldname = "\\".join(fldname.split('/'))                    
                          fldname = fldname.replace(pathdir,'')   
                          self.outdir.set(fldname)
                          browsefldr_flag = 0
                     except:
                           browsefldr_flag = 1

            def efuse_key_gen_(self): 
                global KeyRFlagsCrnt
                keyRFlags_ = KeyRFlagsCrnt
                fldloc = self.outdir.get()
                fldloc =fldloc+"/keys/"
                fldloc = "\\".join(fldloc.split('/'))
                cmd = "if exist "+fldloc+"+key_file.bin del /q /f "+fldloc+"key_file.bin"
                op = os.system(cmd) 
                rtn = 0
                if "" == self.ecdhpass.get() or "Please enter Password" == self.ecdhpass.get():
                    self.ecdhpass.set("") 
                global msgidx
                if 0 == keyRFlags_: 
                  #  lbl = Label(self, text="Parsing error").grid(column = 0,sticky=W, pady=0, padx=1)
                 #   msgidx = 3
                  #  error_windox()
                    return 1
                ret = self.gene_conf_file(keyRFlags_,0, self.ecdhkey.get(), self.ecdhpass.get(), self.ecdsakey.get(),self.ecdsapass.get())
                if ret:
                     return 3

                 
                # key_extractor_file = os.path.normpath("tools\CEC1712_key_extractor_and_enc.exe")
                # if not os.path.exists(key_extractor_file):
                #      messagebox.showinfo('CEC1712_key_extractor_and_enc.exe file Warning window', 'Under tools folder "CEC1712_key_extractor_and_enc.exe" file is not available, please copy CEC1712_key_extractor_and_enc.exe to "tools" folder')
                #      return 3

                  
                cmd = "tools\Glacier_sha384_ecdhkey.exe -o "+fldloc+"key_file.bin -i "+fldloc+"key_file.txt >>dummy.txt"
                op = os.system(cmd) 
                cmd = "copy /y Ecdh2PubKey.bin  "+fldloc+"\\"
                op = os.system(cmd)    
                key_fileloc = fldloc+"\\"+"Ecdh2PubKey.bin"     
                hash_key = fldloc+"\\"+"hash_of_ecdh2_pubkey.bin"
                if os.path.exists(key_fileloc):
                   _opensslp = self.opensslpath.get()
                   cmd = _opensslp+" dgst -sha384 -binary -out "+hash_key +" "+ key_fileloc
                   os.system(cmd)
                cmd = "del /f /q Ecdh2PubKey.bin  "
                op = os.system(cmd) 
                cmd = "del /f /q "+fldloc+"key_file.txt"
                op = os.system(cmd) 
                cmd = "del /f /q dummy.txt"
                op = os.system(cmd) 
                cmd = "rename "+fldloc+"key_file1.txt key_file.txt"
                op = os.system(cmd)
                #key_file_1 = fldloc+"key_file.bin"
                #key_file_path = os.path.normpath(key_file_1)
                #if not os.path.exists(key_file_path):
                #     messagebox.showinfo('key_file.bin file Warning window', 'Under tools folder "key_file.bin" file is not generated under "keys" folder')
                #     return 3

                return rtn
                
            def folder_create(self):
                fldname = self.outdir.get();
                if fldname == "":
                    cnt_time=datetime.datetime.now()
                    upd_time ='{0:%Y}{0:%m}{0:%d}_{0:%w}{0:%H%M%S}'.format(cnt_time)
                    fldname = "efuse\efuse_"+upd_time
                    cmd = "IF NOT EXIST "+fldname+" MD "+fldname  
                    op = os.system(cmd) 
                    self.outdir.set(fldname)
                outkeydir=fldname+"\keys"
                cmd = "IF NOT EXIST "+outkeydir+" MD "+outkeydir  
                op = os.system(cmd) 
                buildbindir=fldname+"\out_binaries"
                cmd = "IF NOT EXIST "+buildbindir+" MD "+buildbindir  
                op = os.system(cmd) 
                
            def dummy_function(self,keyname):
                #print("dummy functions ")
                return 0

            def browse_ecdsa_public_key(self,keyname,key_pass,ecdsa_key_bin,full_ecdsa_key,hash_key,each_hash_bin):
                #print("browse_ecdsa_public_key ")
                ret =0
                fldloc = self.outdir.get()
                fldloc =fldloc+"/keys/"
                fldloc = "\\".join(fldloc.split('/'))
                ecdsa_key = keyname
                #print("browse ecdsa_public_key browse_flag %s ",ecdsa_key)
                crypto_be = cryptography.hazmat.backends.default_backend()
                key_fileloc=fldloc+ecdsa_key_bin
                hash_key = fldloc+hash_key
                #print("ecdsa_key function ",ecdsa_key)
                #print("ecdsa_key function ",ecdsa_key_bin)
                #print("hash_key function ",hash_key)
                #print("Not called key_fileloc ",key_fileloc)
                #full_ecdsa_key_name = fldloc+"\\"+full_ecdsa_key
                #full_ecdsa = open(full_ecdsa_key_name,"wb")
                # if os.path.exists(ecdsa_key):
                #   print("ecdsa key exist ")
                # else:
                #   print("Not exist")
                if os.path.exists(ecdsa_key):
                    #print("Exist")
                    with open (ecdsa_key, "r") as ecdata:
                        data = ecdata.readlines()
                        str1 = ''.join(data)
                        h3 = str1.splitlines()
                        cert_file = h3[0]
                        encrypt_file =h3[1]
                    if cert_file =="-----BEGIN CERTIFICATE-----":
                        with open(ecdsa_key, 'rb') as f:
                            cert = x509.load_pem_x509_certificate(f.read(), crypto_be) 
                            #print("Exist1")
                            #print("Exist1")
                            #key_fileloc=fldloc+"key_file.bin"
                            if cert.issuer !='':
                                #print("Exist2")
                                pub_nums = cert.public_key().public_numbers()
                                #print(pub_nums)
                                pubkey_1 =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                                pubkey_2 = pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                                #print("pubkey_2 ",pubkey_2 )
                                #key_fileloc_1=fldloc+"key_file_2.bin"
                            with open(key_fileloc,"wb+") as key_file:
                                #file_data = key_file.read()
                                key_file.seek(0)
                                #print(file_data)
                                #dat = binascii.hexlify(pubkey)
                                #dat = dat.decode("utf-8")
                                key_file.write(pubkey_1)
                                key_file.write(pubkey_2)
                                full_ecdsa_key.write(pubkey_1)
                                full_ecdsa_key.write(pubkey_2)
                                #print("cer")
                                key_file.close()
                            f.close()
                            #key_file.close()
                    if cert_file== "-----BEGIN EC PRIVATE KEY-----":
                        try:
                            pattern = re.compile("ENCRYPTED")
                            encrypt_file = re.findall(pattern,encrypt_file)
                            encrypt_file =encrypt_file[0]
                            if encrypt_file =="ENCRYPTED":
                                aes_key = h3[2]
                                pattern = re.compile("DEK-Info: AES-256-CBC")
                                aes_key = re.findall(pattern,aes_key) 
                                aes_key =aes_key[0]
                                if aes_key =="DEK-Info: AES-256-CBC":
                                    with open(ecdsa_key, 'rb') as encypt_key:
                                        pass_phrase = key_pass.encode("ascii")
                                        try:
                                            root_ca_priv_key = serialization.load_pem_private_key(
                                            data=encypt_key.read(),
                                            password=pass_phrase,
                                            backend=crypto_be)
                                        except:
                                            #print("ECDSA Password is incorrect or not provided the valid password\n")
                                            #print("Efuse binary of OTP files is not generated \n")
                                            #if "" == self.ecdsapass.get():
                                            messagebox.showinfo('ECDSA Key is given without password', 'Provide the passowrd for the keys')
                                            #error_windox()
                                            ret =1
                                            return ret 
                                            #return rtn
                                        pub_nums = root_ca_priv_key.public_key().public_numbers()
                                        pubkey =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                                        pubkey += pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                                        #print(binascii.hexlify(pubkey))
                                        with open(key_fileloc,"wb+") as key_file:
                                            key_file.seek(0)
                                            key_file.write(pubkey)
                                            full_ecdsa_key.write(pubkey)
                                            #key_file.write(pubkey_2)
                                            key_file.close() 
                        except:
                            with open(ecdsa_key, 'rb') as plain_priv_key:
                                root_ca_priv_key = serialization.load_pem_private_key(
                                data=plain_priv_key.read(),
                                password=None,
                                backend=crypto_be)
                                # Get the public key as X and Y integers concatenated
                                #print("root_ca_priv_key ",root_ca_priv_key.version)
                                pub_nums = root_ca_priv_key.public_key().public_numbers()
                                pubkey =  pub_nums.x.to_bytes(32, byteorder='big', signed=False)
                                pubkey += pub_nums.y.to_bytes(32, byteorder='big', signed=False)
                                #print(binascii.hexlify(pubkey))   
                                with open(key_fileloc,"wb+") as key_file:
                                    key_file.seek(0)
                                    key_file.write(pubkey)
                                    full_ecdsa_key.write(pubkey)
                                        #key_file.write(pubkey_2)
                                    key_file.close()  
                    if cert_file== "-----BEGIN PUBLIC KEY-----":
                        with open(ecdsa_key, 'rb') as plain_pub_key:
                            public_key = serialization.load_pem_public_key(data=plain_pub_key.read(),backend=crypto_be) 
                            pub_nums = public_key.public_numbers()
                            pubkey =  pub_nums.x.to_bytes(32, byteorder='big', signed=False)
                            pubkey += pub_nums.y.to_bytes(32, byteorder='big', signed=False)
                            #print(binascii.hexlify(pubkey)) 
                            with open(key_fileloc,"wb+") as key_file:
                                key_file.seek(0)
                                key_file.write(pubkey)
                                full_ecdsa_key.write(pubkey)
                                        #key_file.write(pubkey_2)
                                key_file.close()    

                if os.path.exists(key_fileloc):
                   _opensslp = self.opensslpath.get()
                   #print("Hash384 is generated ")
                   #print("_opensslp ",_opensslp)
                   cmd = _opensslp+" dgst -sha384 -binary -out "+hash_key +" "+ key_fileloc
                   os.system(cmd)

                if os.path.exists(hash_key):
                    f = open(hash_key, mode='rb')
                    image = f.read()
                    each_hash_bin.write(image)
                    f.close()
                return ret

            def ecdsa_public_key(self,keyname,key_pass,ecdsa_key_bin,full_ecdsa_key,hash_key,each_hash_bin):
                fldloc = self.outdir.get()
                ret =0
                global browse_flag
                #print("ecdsa_public_key browse_flag %x ",browse_flag)
                fldloc =fldloc+"/keys/"
                fldloc = "\\".join(fldloc.split('/'))
                if browse_flag ==0:
                    ecdsa_key = keyname
                    #print("keyname ",keyname)
                    ecdsa_key = "/".join(ecdsa_key.split('\\')) 
                    ecdsa_key = fldloc+keyname
                else:
                    ecdsa_key = keyname
                    #print("ecdsa_public_key browse_flag %x ",browse_flag)
                crypto_be = cryptography.hazmat.backends.default_backend()
                key_fileloc=fldloc+ecdsa_key_bin
                hash_key = fldloc+hash_key
                #print("ecdsa_key function ",ecdsa_key)
                #print("ecdsa_key function ",ecdsa_key_bin)
                #print("hash_key function ",hash_key)
                #print("Not called key_fileloc ",key_fileloc)
                #full_ecdsa_key_name = fldloc+"\\"+full_ecdsa_key
                #full_ecdsa = open(full_ecdsa_key_name,"wb")
                # if os.path.exists(ecdsa_key):
                #   print("ecdsa key exist ")
                # else:
                #   print("Not exist")
                if os.path.exists(ecdsa_key):
                    #print("Exist")
                    with open (ecdsa_key, "r") as ecdata:
                        data = ecdata.readlines()
                        str1 = ''.join(data)
                        h3 = str1.splitlines()
                        cert_file = h3[0]
                        encrypt_file =h3[1]
                    if cert_file =="-----BEGIN CERTIFICATE-----":
                        with open(ecdsa_key, 'rb') as f:
                            cert = x509.load_pem_x509_certificate(f.read(), crypto_be) 
                            #print("Exist1")
                            #print("Exist1")
                            #key_fileloc=fldloc+"key_file.bin"
                            if cert.issuer !='':
                                #print("Exist2")
                                pub_nums = cert.public_key().public_numbers()
                                #print(pub_nums)
                                pubkey_1 =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                                pubkey_2 = pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                                #print("pubkey_2 ",pubkey_2 )
                                #key_fileloc_1=fldloc+"key_file_2.bin"
                            with open(key_fileloc,"wb+") as key_file:
                                #file_data = key_file.read()
                                key_file.seek(0)
                                #print(file_data)
                                #dat = binascii.hexlify(pubkey)
                                #dat = dat.decode("utf-8")
                                key_file.write(pubkey_1)
                                key_file.write(pubkey_2)
                                full_ecdsa_key.write(pubkey_1)
                                full_ecdsa_key.write(pubkey_2)
                                #print("cer")
                                key_file.close()
                            f.close()
                            #key_file.close()
                    if cert_file== "-----BEGIN EC PRIVATE KEY-----":
                        try:
                            pattern = re.compile("ENCRYPTED")
                            encrypt_file = re.findall(pattern,encrypt_file)
                            encrypt_file =encrypt_file[0]
                            if encrypt_file =="ENCRYPTED":
                                aes_key = h3[2]
                                pattern = re.compile("DEK-Info: AES-256-CBC")
                                aes_key = re.findall(pattern,aes_key) 
                                aes_key =aes_key[0]
                                if aes_key =="DEK-Info: AES-256-CBC":
                                    with open(ecdsa_key, 'rb') as encypt_key:
                                        pass_phrase = key_pass.encode("ascii")
                                        try:
                                            root_ca_priv_key = serialization.load_pem_private_key(
                                            data=encypt_key.read(),
                                            password=pass_phrase,
                                            backend=crypto_be)
                                        except:
                                            #print("ECDSA Password is incorrect or not provided the valid password\n")
                                            #print("Efuse binary of OTP files is not generated \n")
                                            #if "" == self.ecdsapass.get():
                                            messagebox.showinfo('ECDSA Key is given without password', 'Provide the passowrd for the keys')
                                            #error_windox()
                                            ret =0
                                            return ret
                                            #return rtn
                                        pub_nums = root_ca_priv_key.public_key().public_numbers()
                                        pubkey =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                                        pubkey += pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                                        #print(binascii.hexlify(pubkey))
                                        with open(key_fileloc,"wb+") as key_file:
                                            key_file.seek(0)
                                            key_file.write(pubkey)
                                            full_ecdsa_key.write(pubkey)
                                            #key_file.write(pubkey_2)
                                            key_file.close() 
                        except:
                            with open(ecdsa_key, 'rb') as plain_priv_key:
                                root_ca_priv_key = serialization.load_pem_private_key(
                                data=plain_priv_key.read(),
                                password=None,
                                backend=crypto_be)
                                # Get the public key as X and Y integers concatenated
                                #print("root_ca_priv_key ",root_ca_priv_key.version)
                                pub_nums = root_ca_priv_key.public_key().public_numbers()
                                pubkey =  pub_nums.x.to_bytes(32, byteorder='big', signed=False)
                                pubkey += pub_nums.y.to_bytes(32, byteorder='big', signed=False)
                                #print(binascii.hexlify(pubkey))   
                                with open(key_fileloc,"wb+") as key_file:
                                    key_file.seek(0)
                                    key_file.write(pubkey)
                                    full_ecdsa_key.write(pubkey)
                                        #key_file.write(pubkey_2)
                                    key_file.close()  
                    if cert_file== "-----BEGIN PUBLIC KEY-----":
                        with open(ecdsa_key, 'rb') as plain_pub_key:
                            public_key = serialization.load_pem_public_key(data=plain_pub_key.read(),backend=crypto_be) 
                            pub_nums = public_key.public_numbers()
                            pubkey =  pub_nums.x.to_bytes(32, byteorder='big', signed=False)
                            pubkey += pub_nums.y.to_bytes(32, byteorder='big', signed=False)
                            #print(binascii.hexlify(pubkey)) 
                            with open(key_fileloc,"wb+") as key_file:
                                key_file.seek(0)
                                key_file.write(pubkey)
                                full_ecdsa_key.write(pubkey)
                                        #key_file.write(pubkey_2)
                                key_file.close()    

                if os.path.exists(key_fileloc):
                   _opensslp = self.opensslpath.get()
                   #print("Hash384 is generated ")
                   #print("_opensslp ",_opensslp)
                   cmd = _opensslp+" dgst -sha384 -binary -out "+hash_key +" "+ key_fileloc
                   os.system(cmd)

                if os.path.exists(hash_key):
                    f = open(hash_key, mode='rb')
                    image = f.read()
                    each_hash_bin.write(image)
                    f.close()
                return ret
            def sha384_ecdsa_public_key(self,keyname):#,key_pass,ecdsa_key_bin,full_ecdsa_key,hash_key,each_hash_bin):
                fldloc = self.outdir.get()
                ret =0
                global browse_flag
                #print("ecdsa_public_key browse_flag %x ",browse_flag)
                fldloc = fldloc+"\\keys"

                ecdsa_key = keyname
                crypto_be = cryptography.hazmat.backends.default_backend()
                key_fileloc=fldloc+"\\"+"owner_1_ecdsa_384.bin"#fldloc+"\\"+"ecdsa_384.bin"
                hash_key =fldloc+"\\"+ "owner_1_hash384.bin"#fldloc+"\\"+"hash384.bin"
                print("1" , key_fileloc)
                print("fldloc " , fldloc)
                if os.path.exists(ecdsa_key):
                    with open (ecdsa_key, "r") as ecdata:
                        data = ecdata.readlines()
                        str1 = ''.join(data)
                        h3 = str1.splitlines()
                        cert_file = h3[0]
                        encrypt_file =h3[1]
                    if cert_file =="-----BEGIN CERTIFICATE-----":
                        with open(ecdsa_key, 'rb') as f:
                            cert = x509.load_pem_x509_certificate(f.read(), crypto_be) 
                            if cert.issuer !='':
                                pub_nums = cert.public_key().public_numbers()
                                pubkey_1 =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                                pubkey_2 = pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                            with open(key_fileloc,"wb+") as key_file:
                                key_file.seek(0)
                                key_file.write(pubkey_1)
                                key_file.write(pubkey_2)
                                key_file.close()
                            f.close()
                    if cert_file== "-----BEGIN EC PRIVATE KEY-----":
                        try:
                            pattern = re.compile("ENCRYPTED")
                            encrypt_file = re.findall(pattern,encrypt_file)
                            encrypt_file =encrypt_file[0]
                            if encrypt_file =="ENCRYPTED":
                                aes_key = h3[2]
                                pattern = re.compile("DEK-Info: AES-256-CBC")
                                aes_key = re.findall(pattern,aes_key) 
                                aes_key =aes_key[0]
                                if aes_key =="DEK-Info: AES-256-CBC":
                                    with open(ecdsa_key, 'rb') as encypt_key:
                                        pass_phrase = key_pass.encode("ascii")
                                        try:
                                            root_ca_priv_key = serialization.load_pem_private_key(
                                            data=encypt_key.read(),
                                            password=pass_phrase,
                                            backend=crypto_be)
                                        except:
                                            messagebox.showinfo('ECDSA Key is given without password', 'Provide the passowrd for the keys')
                                            ret =0
                                            return ret
                                        pub_nums = root_ca_priv_key.public_key().public_numbers()
                                        pubkey =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                                        pubkey += pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                                        #print(binascii.hexlify(pubkey))
                                        with open(key_fileloc,"wb+") as key_file:
                                            key_file.seek(0)
                                            key_file.write(pubkey)
                                            key_file.close() 
                        except:
                            with open(ecdsa_key, 'rb') as plain_priv_key:
                                root_ca_priv_key = serialization.load_pem_private_key(
                                data=plain_priv_key.read(),
                                password=None,
                                backend=crypto_be)
                                # Get the public key as X and Y integers concatenated
                                #print("root_ca_priv_key ",root_ca_priv_key.version)
                                pub_nums = root_ca_priv_key.public_key().public_numbers()
                                pubkey =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                                pubkey += pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                                #print(binascii.hexlify(pubkey))   
                                with open(key_fileloc,"wb+") as key_file:
                                    key_file.seek(0)
                                    key_file.write(pubkey)
                                    #full_ecdsa_key.write(pubkey)
                                        #key_file.write(pubkey_2)
                                    key_file.close()  
                    if cert_file== "-----BEGIN PUBLIC KEY-----":
                        with open(ecdsa_key, 'rb') as plain_pub_key:
                            public_key = serialization.load_pem_public_key(data=plain_pub_key.read(),backend=crypto_be) 
                            pub_nums = public_key.public_numbers()
                            pubkey =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                            pubkey += pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                            #print(binascii.hexlify(pubkey)) 
                            with open(key_fileloc,"wb+") as key_file:
                                key_file.seek(0)
                                key_file.write(pubkey)
                                #full_ecdsa_key.write(pubkey)
                                        #key_file.write(pubkey_2)
                                key_file.close()    

                if os.path.exists(key_fileloc):
                   _opensslp = self.opensslpath.get()
                   cmd = _opensslp+" dgst -sha384 -binary -out "+hash_key +" "+ key_fileloc
                   os.system(cmd)

                # if os.path.exists(hash_key):
                #     f = open(hash_key, mode='rb')
                #     image = f.read()
                #     each_hash_bin.write(image)
                #     f.close()
                return ret
            def plat_sha384_ecdsa_public_key(self,keyname):#,key_pass,ecdsa_key_bin,full_ecdsa_key,hash_key,each_hash_bin):
                fldloc = self.outdir.get()
                ret =0
                global browse_flag
                #print("ecdsa_public_key browse_flag %x ",browse_flag)
                fldloc = fldloc+"\\keys"
                #fldloc = "\\".join(fldloc.split('/'))
                # if browse_flag ==0:
                #     ecdsa_key = keyname
                #     #print("keyname ",keyname)
                #     ecdsa_key = "/".join(ecdsa_key.split('\\')) 
                #     ecdsa_key = fldloc+keyname
                # else:
                ecdsa_key = keyname
                    #print("ecdsa_public_key browse_flag %x ",browse_flag)
                crypto_be = cryptography.hazmat.backends.default_backend()
                key_fileloc=fldloc+"\\"+"plat_ecdsa_384.bin"#fldloc+"\\"+"ecdsa_384.bin"
                hash_key =fldloc+"\\"+ "plat_hash384.bin"#fldloc+"\\"+"hash384.bin"
                #print("1" , key_fileloc)
                #print("fldloc " , fldloc)
                if os.path.exists(ecdsa_key):
                    #print("Exist")
                    with open (ecdsa_key, "r") as ecdata:
                        data = ecdata.readlines()
                        str1 = ''.join(data)
                        h3 = str1.splitlines()
                        cert_file = h3[0]
                        encrypt_file =h3[1]
                    if cert_file =="-----BEGIN CERTIFICATE-----":
                        with open(ecdsa_key, 'rb') as f:
                            cert = x509.load_pem_x509_certificate(f.read(), crypto_be) 
                            #print("Exist1")
                            #print("Exist1")
                            #key_fileloc=fldloc+"key_file.bin"
                            if cert.issuer !='':
                                #print("Exist2")
                                pub_nums = cert.public_key().public_numbers()
                                #print(pub_nums)
                                pubkey_1 =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                                pubkey_2 = pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                                #print("pubkey_2 ",pubkey_2 )
                                #key_fileloc_1=fldloc+"key_file_2.bin"
                            with open(key_fileloc,"wb+") as key_file:
                                #file_data = key_file.read()
                                key_file.seek(0)
                                #print(file_data)
                                #dat = binascii.hexlify(pubkey)
                                #dat = dat.decode("utf-8")
                                key_file.write(pubkey_1)
                                key_file.write(pubkey_2)
                                #full_ecdsa_key.write(pubkey_1)
                                #full_ecdsa_key.write(pubkey_2)
                                #print("cer")
                                key_file.close()
                            f.close()
                            #key_file.close()
                    if cert_file== "-----BEGIN EC PRIVATE KEY-----":
                        try:
                            pattern = re.compile("ENCRYPTED")
                            encrypt_file = re.findall(pattern,encrypt_file)
                            encrypt_file =encrypt_file[0]
                            if encrypt_file =="ENCRYPTED":
                                aes_key = h3[2]
                                pattern = re.compile("DEK-Info: AES-256-CBC")
                                aes_key = re.findall(pattern,aes_key) 
                                aes_key =aes_key[0]
                                if aes_key =="DEK-Info: AES-256-CBC":
                                    with open(ecdsa_key, 'rb') as encypt_key:
                                        pass_phrase = key_pass.encode("ascii")
                                        try:
                                            root_ca_priv_key = serialization.load_pem_private_key(
                                            data=encypt_key.read(),
                                            password=pass_phrase,
                                            backend=crypto_be)
                                        except:
                                            #print("ECDSA Password is incorrect or not provided the valid password\n")
                                            #print("Efuse binary of OTP files is not generated \n")
                                            #if "" == self.ecdsapass.get():
                                            messagebox.showinfo('ECDSA Key is given without password', 'Provide the passowrd for the keys')
                                            #error_windox()
                                            ret =0
                                            return ret
                                            #return rtn
                                        pub_nums = root_ca_priv_key.public_key().public_numbers()
                                        pubkey =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                                        pubkey += pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                                        #print(binascii.hexlify(pubkey))
                                        with open(key_fileloc,"wb+") as key_file:
                                            key_file.seek(0)
                                            key_file.write(pubkey)
                                            #full_ecdsa_key.write(pubkey)
                                            #key_file.write(pubkey_2)
                                            key_file.close() 
                        except:
                            with open(ecdsa_key, 'rb') as plain_priv_key:
                                root_ca_priv_key = serialization.load_pem_private_key(
                                data=plain_priv_key.read(),
                                password=None,
                                backend=crypto_be)
                                # Get the public key as X and Y integers concatenated
                                #print("root_ca_priv_key ",root_ca_priv_key.version)
                                pub_nums = root_ca_priv_key.public_key().public_numbers()
                                pubkey =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                                pubkey += pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                                #print(binascii.hexlify(pubkey))   
                                with open(key_fileloc,"wb+") as key_file:
                                    key_file.seek(0)
                                    key_file.write(pubkey)
                                    #full_ecdsa_key.write(pubkey)
                                        #key_file.write(pubkey_2)
                                    key_file.close()  
                    if cert_file== "-----BEGIN PUBLIC KEY-----":
                        with open(ecdsa_key, 'rb') as plain_pub_key:
                            public_key = serialization.load_pem_public_key(data=plain_pub_key.read(),backend=crypto_be) 
                            pub_nums = public_key.public_numbers()
                            pubkey =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                            pubkey += pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                            #print(binascii.hexlify(pubkey)) 
                            with open(key_fileloc,"wb+") as key_file:
                                key_file.seek(0)
                                key_file.write(pubkey)
                                #full_ecdsa_key.write(pubkey)
                                        #key_file.write(pubkey_2)
                                key_file.close()    

                if os.path.exists(key_fileloc):
                   #print("3")
                   _opensslp = self.opensslpath.get()
                   #print("_opensslp ",_opensslp)
                   #print("Hash384 is generated ")
                   #print("_opensslp ",_opensslp)
                   cmd = _opensslp+" dgst -sha384 -binary -out "+hash_key +" "+ key_fileloc
                   os.system(cmd)
                   #print("2")

                # if os.path.exists(hash_key):
                #     f = open(hash_key, mode='rb')
                #     image = f.read()
                #     each_hash_bin.write(image)
                #     f.close()
                return ret
            def parse_content(self):
                keyRFlags_  = 0 #required Key Flags b'0 = ECDH Key True, b'1 ECDH password True, b'2 ECDSA Key True, b'3 ECDSA password True
                ecdhk_ = self.ecdhkey.get()
                if "No ECDH" == ecdhk_ or  "" == ecdhk_ or "Please enter Filename" == ecdhk_ or "Enter ECDH Key filename to generate" == ecdhk_ :
                    keyRFlags_ |= (1<<0)#return
                ecdhp_ = self.ecdhpass.get()
                if "No ECDH" == ecdhp_ or "" == ecdhp_ or "Please enter Password" == ecdhp_ or "Enter ECDH Password" == ecdhp_ :
                    keyRFlags_ |= (1<<1)#return
                ecdsak_ = self.ecdsakey.get()
                if "" == ecdsak_ or "NO ECDSA" == ecdsak_ or "Please enter Filename" == ecdsak_ or "Enter ECDSA Key filename to generate" == ecdsak_ :
                    keyRFlags_ |= (1<<2)#return
                ecdsap_ = self.ecdsapass.get()
                if "" == ecdsap_ or "NO ECDSA" == ecdsap_ or "Please enter Password" == ecdsap_ or "Enter ECDSA Password" == ecdsap_ :
                    keyRFlags_ |= (1<<3)#return
                if 0x0C == keyRFlags_ or 0x03 == keyRFlags_ or 0x00 == keyRFlags_:
                    if 0 == keyRFlags_:
                        keyRFlags_ = 0x30
                    if (0x0C & keyRFlags_) == 0x0C:  
                        self.ecdsakey.set("NO ECDSA")
                        self.ecdsapass.set("NO ECDSA")
                        keyRFlags_ = 0x10
                    if (0x03 & keyRFlags_) == 0x03:
                        self.ecdhkey.set("No ECDH")
                        self.ecdhpass.set("No ECDH") 
                        keyRFlags_ = 0x20
                else:
                    if 0x0b == keyRFlags_:
                       keyRFlags_ = 0x20 
                    if 0x08 == keyRFlags_:
                       keyRFlags_ = 0x30 
                    if 0x02 == keyRFlags_ or 0x01 == keyRFlags_:
                       return 0 
                    if 0x0F == keyRFlags_:
                        if 1 == self.ENCvar.get():
                            self.ecdhkey.set("Please enter Filename")
                            self.ecdhpass.set("Please enter Password")
                        if 1 == self.AUTHvar.get():
                            self.ecdsakey.set("Please enter Filename")
                            self.ecdsapass.set("Please enter Password")
                        return 0
                    if (0x03 & keyRFlags_):
                        if (0x03 & keyRFlags_) == 0x03:
                            self.ecdhkey.set("No ECDH")
                            self.ecdhpass.set("No ECDH")
                            if 0x04 == (0x04 & keyRFlags_):  
                                self.ecdsakey.set("Please enter Filename")
                                return 0
                            if 0x08 == (0x08 & keyRFlags_):      
                                self.ecdsapass.set("Please enter Password")
                                return 0
                        else:
                            if (0x03 & keyRFlags_) == 0x01:
                                self.ecdhkey.set("Please enter Filename")
                            else:
                                self.ecdhpass.set("Please enter Password")
                             
                    if (0x0C & keyRFlags_):
                        if (0x0C & keyRFlags_) == 0x0C:  
                            self.ecdsakey.set("NO ECDSA")
                            self.ecdsapass.set("NO ECDSA")   
                            if 0x01 == (0x01 & keyRFlags_):
                                self.ecdhkey.set("Please enter Filename")
                                return 0
                            if 0x02 == (0x02 & keyRFlags_):   
                                self.ecdhpass.set("Please enter Password")
                                return 0    
                        else:
                            if (0x0C & keyRFlags_) == 0x08: 
                                self.ecdsapass.set("Please enter Password")    
                            else:
                                self.ecdsakey.set("Please enter Filename")
                        return 0
              
                return keyRFlags_

            def otp_dump_function(self):    
                    #global MaskVal
                    #global PatternVal
                    #global TypeVal    
                    fldloc = self.outdir.get()
                    fldloc = "/".join(fldloc.split('\\')) 
                    cnt = idx = dat = incnt = outcnt = 0
                    dirpath=fldloc+"/out_binaries/efuse.bin" 
                    sqtppath=fldloc+"/out_binaries/otp_dump.log" 
                    efuse_file = open(dirpath,"rb")
                    efuse_file.seek(0)
                    efuse_data =efuse_file.read()
                    #print("efuse_data ",efuse_data)
                    in_file = open(sqtppath,"wt+")
                    in_file.write("******** OTP  DUMPT value and is available in the otp_dump.log ************\n")
                    #in_file.write("******** OTP  DUMPT value ************")
                    in_file.write("\n")    
                    for items in efuse_data:
                        if 0 == cnt:
                            idx = items 
                        if 1 == cnt:    
                            idx = idx + (items << 8)
                        if 2 == cnt:  
                            dat = items
                            if 57005 == idx:#DEAD
                                break
                            incnt = incnt +1
                            if idx <= 0x2F:
                                if idx ==0:
                                    in_file.write("ECDH Private key 0-47 offset ************\n")
                                cnt = "  OTP Value  ="+hex(dat)
                                in_file.write(cnt)    
                            #if (idx ) 
                            #print("OTP Offset  =0x",idx,"OTP Value  =0x",hex(dat))   
                            cnt = "OTP Offset(dec)  = "+ str(idx) +" Offset(hex) =" +hex(idx)
                            in_file.write(cnt)    
                            cnt = "  OTP Value  ="+hex(dat)
                            in_file.write(cnt)    
                            in_file.write(" \n")
                            cnt =0 
                            if ( 8== incnt):
                                outcnt = outcnt + incnt
                                incnt = 0
                        else:
                            cnt = cnt + 1            
                    outcnt = outcnt + incnt 
                       
                    
                    #in_file.write("</data>\n")
                    in_file.close    
                    efuse_file.close
                     
            def generate_efuse(self):
                global efuse_data_table
                global custom_data
                global headerflag
                global warningMSG
                global sqtpflag
                global pathfilename
                global ecdhkeyenc_en_flag
                global rom_ecdh_flag
                global custdatexd
                global cust_content
                global msgidx
                global jtag_disbale_flag
                global display_done
                global WDTDelayg
                global otp_lock_15
                global otp_lock_16
                global otp_lock_17
                global otp_lock_18
                global otp_lock_19
                global otp_lock_20
                global otp_lock_21
                global otp_lock_22
                global otp_lock_23
                global otp_lock_24
                global otp_lock_25
                global otp_lock_26
                global otp_lock_27
                global otp_lock_28
                global otp_lock_29
                global otp_lock_30
                global otp_write_lock_en
                global write_lock_flag_15
                global write_lock_flag_16
                global write_lock_flag_17
                global write_lock_flag_18
                global write_lock_flag_19
                global write_lock_flag_20
                global write_lock_flag_21
                global write_lock_flag_22
                global write_lock_flag_23
                global write_lock_flag_24
                global write_lock_flag_25
                global write_lock_flag_26
                global write_lock_flag_27
                global write_lock_flag_28
                global write_lock_flag_29
                global write_lock_flag_30
                global cust_enter_var

                global cust_data_enter_flag
                global cust_idx_enter_flag
                global generate_efuse_data
                global warning_main_wind_flag
                #print(" self.ecdsa_key_hash_bin ",self.ecdsa_key_hash_bin.get())
                
                #if 0 == generate_efuse_data: can be enabled for the future purpose
                if 1:
                     try:
                          generate_efuse_data = 1
                          if 1 == cust_data_enter_flag or 1 == cust_idx_enter_flag:
                               return
                          
                          pathfilename = []
                          log_file_cnt = []
                          efuse_data_table = []
                          # opensslpath = self.opensslpath.get()
                          # cmd = opensslpath + " version "
                          # cmd ='"%s"'%cmd
                          # ret = os.system(cmd)
                          # if ret:
                          #      messagebox.showinfo('Opensll path  Warning window', 'openssl path is missing ')
                          #      return 1

                          self.folder_create()
                          fldloc = self.outdir.get()
                          fldloc = "/".join(fldloc.split('\\')) 
                          log_file_cnt.append("Log Details for Efuse data Generated under folder = "+ fldloc)

                          update_efuse483 = False
                          update_efuse483_lock = False
                          update_efuse_ecdsa_lock = False
                          update_efuse_ecdh_priv_lock = False
                          update_efuse_ecdh_pub_lock = False
                          keyfileflags = 0


                          efuse_orig_file_name_1 = "efuse\original_binary"
                          if os.path.exists(efuse_orig_file_name_1) and os.path.isdir(efuse_orig_file_name_1):
                              if not os.listdir(efuse_orig_file_name_1):
                                   messagebox.showinfo('original_binary folder Warning window', 'Under tools folder "otp_prog_original.hex/.bin" file are not available, please copy otp_prog_original.hex/.bin to "efuse/original_binary" folder')
                                   return 3
                                 
                          efuse_orig_file_name = "efuse\original_binary\otp_prog_original.hex"
                          efuse_orig_name_path = os.path.normpath("efuse\original_binary\otp_prog_original.hex")
                          if not os.path.exists(efuse_orig_name_path):
                              messagebox.showinfo('otp_prog_original.hex file Warning window', 'Under tools folder "otp_prog_original.hex" file is not available, please copy otp_prog_original.hex to "efuse/original_binary" folder')
                              return 3

                          efuse_bin_orig_file_name = "efuse\original_binary\otp_prog_original.bin"
                          efuse_bin_orig_name_path = os.path.normpath("efuse\original_binary\otp_prog_original.bin")
                          if not os.path.exists(efuse_bin_orig_name_path):
                              messagebox.showinfo('otp_prog_original.bin file Warning window', 'Under tools folder "otp_prog_original.bin" file is not available, please copy otp_prog_original.bin to "efuse/original_binary" folder')
                              return 3
                                 
                   
                          # key_extractor_file_1 = "tools"
                          # if os.path.exists(key_extractor_file_1) and os.path.isdir(key_extractor_file_1):
                          #      if not os.listdir(key_extractor_file_1):
                          #           messagebox.showinfo('Tools folder Warning window', 'Under tools folder  files are not available, please copy respective files(Everglades_key_extractor_and_enc.exe , EVERGLADES_ECDH_ROM_crt.pem,openssl.exe & srec_cat.exe) to "tools" folder')
                          #           return 3
                            
                          # key_extractor_file = os.path.normpath("tools\Everglades_key_extractor_and_enc.exe")
                          # if not os.path.exists(key_extractor_file):
                          #      messagebox.showinfo('Everglades_key_extractor_and_enc.exe file Warning window', 'Under tools folder "Everglades_key_extractor_and_enc.exe" file is not available, please copy Everglades_key_extractor_and_enc.exe to "tools" folder')
                          #      return 3

                          # ecdh_pub_file_name = "tools/EVERGLADES_ECDH_ROM_crt.pem"
                          # ecdh_pub_file_path = os.path.normpath(ecdh_pub_file_name)
                          # if not os.path.exists(ecdh_pub_file_path):
                          #      messagebox.showinfo('EVERGLADES_ECDH_ROM_crt.pem file Warning window', 'Under tools folder "EVERGLADES_ECDH_ROM_crt.pem" file is not available, please copy EVERGLADES_ECDH_ROM_crt.pem to "tools" folder')
                          #      return 3

                          _opensslp = self.opensslpath.get()
                          openssl_file = os.path.normpath(_opensslp)
                          #if not os.path.exists(openssl_file):
                          #     messagebox.showinfo('OpenSSl.exe file Warning window', 'Under tools folder "openssl.exe" file is not available, please provide the proper path of the openssl.exe or copy openssl.exe to "tools" folder')
                          #     return 3 

                          if 0:
                              if 1 == cust_enter_var:
                                   #select_custom = messagebox.askquestion('Generate Efuse data ', 'You have written the Data into the customer OTP region between (Dec :(480-991) , Hex :(0x1E0-0x3DF)), Do you want to Write Lock this region ? Press "Yes" or "No" ')
                                   #if select_custom =='yes':
                                   self.new_windos = custom_window()
                   
                                    
                          # if 1== self.AUTHEnvar.get():
                          #    ecdsaaddress = int(self.ecdsaaddress.get(),16)
                          #    temp= ((ecdsaaddress<<8) & 0xFF0000)| 0x16C#0x3FC ;#0x1FC;
                          #    temp = struct.pack('I',temp)
                          #    efuse_data_table.append(temp)  
                          #    temp = "ECDSA Key storage Flash Address location used = "+temp
                          #    log_file_cnt.append(temp)
                          #print("Here 1 COMP_flag \n MOB_flag  COMP_flag  DSW_flag  soteria_flag  soteria_cus_flag  \n",COMP_flag,MOB_flag,COMP_flag,DSW_flag,soteria_flag,soteria_cus_flag)
                          if 1== self.ECCP384var.get() and 1== self.AUTHEnvar.get():
                            if self.ecdsa_sha384_key_hash_bin.get()  =="":
                                messagebox.showinfo('SHA384 Owner1 Public key Warning window', 'SHA384 Owner1 Public key path is missing ')
                                return 1
                            self.sha384_bin_gen()
                            opensslpath = self.opensslpath.get()
                            cmd = opensslpath + " version "
                            cmd ='"%s"'%cmd
                            ret = os.system(cmd)
                            if ret:
                              messagebox.showinfo('Opensll path  Warning window', 'openssl path is missing ')
                              return 1
                            key_fileloc_1=fldloc+"/keys/owner_1_hash384.bin"
                            #if file.exists()
                            if True == os.path.isfile(key_fileloc_1):
                                with open (key_fileloc_1,"rb") as key_in_file:
                                    if 1 == self.AUTHEnvar.get():
                                        key_in_file.seek(0)
                                        key_file_data = key_in_file.read()
                                        #print("Authentication enable ")
                                        idx = 0
                                        #keyfileflags =key_in_file[255] 
                                        for i in range(368,416):
                                            temp= key_file_data[idx]<< 16 | (i)
                                            temp = struct.pack('I',temp)       
                                            efuse_data_table.append(temp) 
                                            idx = idx+ 1
                          if 1== self.AUTHEnvar.get() and 1==self.ecdsa_key_hash_check_var.get():
                            try:
                               #print(" File ")
                               if self.ecdsa_key_hash_bin.get() == "":
                                    messagebox.showinfo('SHA384 Owner1 Public key Binary Warning window', 'SHA384 Owner1 Public Binary path is missing ')
                                    return 1
                               key_fileloc_1 = self.ecdsa_key_hash_bin.get()
                               #print("File 1")
                               if os.path.exists(key_fileloc_1):
                                 temp = "ECDSA Key flash binary used = "+key_fileloc_1
                                 log_file_cnt.append(temp)
                               else:
                                 messagebox.showinfo('ECDSA Hash Binary', 'ECDSA hash binary  is not provided , please provide the valid binary')
                                 return 3
                               #print("File 3")
                            except ValueError:
                               messagebox.showinfo('ECDSA Hash Binary', 'ECDSA hash binary  is not provided , please provide the valid binary')
                               return 3 
                            with open (key_fileloc_1,"rb") as key_in_file:
                                if 1 == self.AUTHEnvar.get():
                                    key_in_file.seek(0)
                                    key_file_data = key_in_file.read()
                                    #print("Authentication enable ")
                                    idx = 0
                                    #keyfileflags =key_in_file[255] 
                                    for i in range(368,416):
                                        temp= key_file_data[idx]<< 16 | (i)
                                        temp = struct.pack('I',temp)       
                                        efuse_data_table.append(temp) 
                                        idx = idx+ 1
                                    if (1 == self.ECDSALCKvar.get()):
                                      update_efuse_ecdsa_lock = True
                                      update_efuse483 = True
                          #   try:
                          #       tagadd = self.ecdsaaddress.get()
                          #       tag = int(self.ecdsaaddress.get(),16)
                          #       if (""  ==tag):
                          #          messagebox.showinfo('ECDSA Key Storage Flash Address 0 Warning window', 'ECDSA Key Storage Flash Address 0 is not provided , please provide the valid ecdsaaddress 0 in 16 byte boundary')
                          #          return 3 
                          #       if ( "" != tag) and ("00000000" != tag):
                          #         tag = int(self.ecdsaaddress.get(),16)
                          #       if (tag & 0xF)>0:
                          #          messagebox.showinfo('ECDSA Key Storage Flash Address 0 Warning window', 'ECDSA Key Storage Flash Address 0 is multiple of 16 byte , please provide the valid ecdsaaddress 0 in 16 byte boundary')
                          #          return 3
                          #   except:
                          #       messagebox.showinfo('ECDSA Key Storage Flash Address 0 Warning window', 'ECDSA Key Storage Flash Address 0 is not provided , please provide the valid ecdsaaddress 0 in 16 byte boundary')
                          #       return 3 
                          #   try:
                          #       tagadd = self.ecdsaaddress_1.get()
                          #       tag = int(self.ecdsaaddress_1.get(),16)
                          #       if (""  ==tag):
                          #          messagebox.showinfo('ECDSA Key Storage Flash Address 1 Warning window', 'ECDSA Key Storage Flash Address 1 is not provided , please provide the valid ecdsaaddress 1 in 16 byte boundary')
                          #          return 3 
                          #       if ( "" != tag) and ("00000000" != tag):
                          #         tag = int(self.ecdsaaddress_1.get(),16)
                          #       if (tag & 0xF)>0:
                          #          messagebox.showinfo('ECDSA Key Storage Flash Address 1 Warning window', 'ECDSA Key Storage Flash Address 1 is multiple of 16 byte , please provide the valid ecdsaaddress 1 in 16 byte boundary')
                          #          return 3
                          #   except:
                          #       messagebox.showinfo('ECDSA Key Storage Flash Address 1 Warning window', 'ECDSA Key Storage Flash Address 1 is not provided , please provide the valid ecdsaaddress 1 in 16 byte boundary')
                          #       return 3 
                          # #print("Here 2")
                          # if 1== self.AUTHEnvar.get() and 0==self.ecdsa_key_hash_check_var.get():
                          #    tagadd = self.ecdsaaddress.get()
                          #    ecdsa_addr_1 = self.ecdsaaddress_1.get()
                          #    # if (""  ==tagadd):
                          #    #    messagebox.showinfo('ECDSA Key Storage Flash Address Warning window', 'ECDSA Key Storage Flash Address is not provided , please provide the valid ecdsaaddress in 16 byte boundary')
                          #    #    return 3 
                          #    if ( "" != tagadd) and ("00000000" != tagadd):
                          #      tag = int(self.ecdsaaddress.get(),16)
                          #    if (tag > 0xFFFFFFFF):
                          #       messagebox.showinfo('ECDSA Key Storage Flash Address 0 Warning window', 'ECDSA Key Storage Flash Address 0 is multiple of 16 byte or not to be greater than 4 byte, please provide the valid ecdsaaddress in 16 byte boundary')
                          #       return 3 
                          #    if ( "" != ecdsa_addr_1) and ("00000000" != ecdsa_addr_1):
                          #      tag = int(self.ecdsaaddress_1.get(),16)
                          #    if (tag > 0xFFFFFFFF) :
                          #       messagebox.showinfo('ECDSA Key Storage Flash Address 1 Warning window', 'ECDSA Key Storage Flash Address 1 is multiple of 16 byte or not to be greater than 4 byte, please provide the valid ecdsaaddress in 16 byte boundary')
                          #       return 3 
                          #    val = self.eckeycount.get()
                          #    if val ==0 or val > 32:
                          #       messagebox.showinfo('ECKeyCount Warning window', 'ECKeyCount is not provided or greater than 32, please provide the valid value')
                          #       return
                          #    if val >0:
                          #     #print("value greateer ")
                          #     if 1== self.ECCP384var.get() and 0 == self.ecdsa_key_hash_check_var.get():
                          #         if (self.ec384keygen()):
                          #            return 3
                          #         if (self.ec384keybin()):
                          #            return 3
                          #         #print("ec384keybin end")
                          #         key_fileloc_1=fldloc+"/keys/hash_of_hash.bin"
                          #         try:
                          #             with open (key_fileloc_1,"rb") as key_in_file:
                          #                 if 1 == self.AUTHEnvar.get():
                          #                     key_in_file.seek(0)
                          #                     key_file_data = key_in_file.read()
                          #                     #print("Authentication enable ")
                          #                     idx = 0
                          #                     #keyfileflags =key_in_file[255] 
                          #                     for i in range(368,416):
                          #                         temp= key_file_data[idx]<< 16 | (i)
                          #                         temp = struct.pack('I',temp)       
                          #                         efuse_data_table.append(temp) 
                          #                         idx = idx+ 1
                          #                     if (1 == self.ECDSALCKvar.get()):
                          #                         update_efuse_ecdsa_lock = True
                          #                     update_efuse483 = True
                          #         except:
                          #            messagebox.showinfo('EC Key Hash Generation Warning window', 'EC key filename is not provided to generate HASH or HASH file is not exist, please provide the valid value')
                          #            return
                          # if 1== self.AUTHEnvar.get():     
                          #   tagadd = self.ecdsaaddress.get()
                          #   if ( "" != tagadd) and ("00000000" != tagadd):
                          #     tag = int(self.ecdsaaddress.get(),16)
                          #     if (tag & 0xF)>0:
                          #       messagebox.showinfo('ECDSA Key Storage Flash Address Warning window', 'ECDSA Key Storage Flash Address is multiple of 16 byte , please provide the valid ecdsaaddress in 16 byte boundary')
                          #       return 3 
                          #   if ( "" != tagadd) and ("00000000" != tagadd):
                          #     tag = int(self.ecdsaaddress.get(),16)
                          #     if (tag & 0xF)>0:
                          #       messagebox.showinfo('ECDSA Key Storage Flash Address Warning window', 'ECDSA Key Storage Flash Address is multiple of 16 byte , please provide the valid ecdsaaddress in 16 byte boundary')
                          #       return 3 
                          #print("Here 2")
                          if 1 == self.ecdh_key_var.get():
                          	with open (self.ecdh_key_bin.get(),"rb") as in_file:
                          		file_data = in_file.read()
                          		extension = os.path.splitext(self.ecdh_key_bin.get())[1] 
                          		#print("extension1 ",extension)
                          		idx =0
                          		if extension ==".bin":
        	                  		for i in range(0,48): #efuse Range
        		                  		temp= file_data[idx]<< 16 | (i)
        		                  		temp = struct.pack('I',temp)  
        		                  		efuse_data_table.append(temp) 
        		                  		idx = idx+ 1  
                          		if extension ==".hex":
        	                  		for i in range(0,48): #efuse Range
        	                  			#val = int(binascii.hexlify(file_data[idx]), 16)
        	                  			#val = hex((val >> 8 ) & 0xFF).upper().split('X')[1].zfill(2)
        		                  		temp= file_data[idx]<< 16 | (i)
        		                  		temp = struct.pack('I',temp)  
        		                  		efuse_data_table.append(temp) 
        		                  		idx = idx+ 1  		                	
        	                  	#temp1 = 0x00200000 | 0x31 
        	                  	#temp1 = struct.pack('I',temp1) 
        	                  	#efuse_data_table.append(temp1)          
                          if 1 == self.ecdh_en_key_var.get():
                          	with open (self.ecdh_en_key_bin.get(),"rb") as in_file:
                          		file_data = in_file.read()
                          		extension = os.path.splitext(self.ecdh_en_key_bin.get())[1] 
                          		#print("extension2 ",extension)
                          		idx =0
                          		if extension ==".bin":
        	                  		for i in range(128,176): #efuse Range
        		                  		temp= file_data[idx]<< 16 | (i)
        		                  		temp = struct.pack('I',temp)  
        		                  		efuse_data_table.append(temp) 
        		                  		idx = idx+ 1  
                          		if extension ==".hex":
        	                  		for i in range(128,176): #efuse Range
        		                  		temp= file_data[idx]<< 16 | (i)
        		                  		temp = struct.pack('I',temp)  
        		                  		efuse_data_table.append(temp) 
        		                  		idx = idx+ 1  		                	
        	                  	#temp1 = 0x00200000 | 0x31 
        	                  	#temp1 = struct.pack('I',temp1) 
        	                  	#efuse_data_table.append(temp1)                            	 
                          #print("Here 2")
                          if 1 == self.AUTHvar.get() or (1 == self.ENCvar.get() and 0 == self.sel_ecdhkeyvar.get()):
                              if "" == self.ecdhpass.get() or "Please enter Password" == self.ecdhpass.get():
                                self.ecdhpass.set("") 
                              #filepath=self.ecdhkey.get()
                              if "" ==self.ecdhkey.get():# or "" == self.ecdhpass.get():
                                  messagebox.showinfo('Error in Key Generation', 'Please re-check the ECDH filename/passowrd   is not provided , so Utility is exit')
                                  return
                              if 1 == self.ecdhkeyvar.get():
                                  if "" ==self.custom_ecdh_key_bin.get():
                                    messagebox.showinfo('Error in Key Generation', 'Please re-check the ECDH2 filename   is not provided , so Utility is exit')
                                    return
                              if (self.key_gen_()):
                                  return
                              if(self.efuse_key_gen_()):
                                  return
                              key_fileloc=fldloc+"/keys/key_file.bin"
                              key_fileloc_1=fldloc+"/keys/hash_of_ecdh2_pubkey.bin"
                              try: 
                                  with open (key_fileloc,"rb") as in_file:
                                      in_file.seek(0)
                                      # read file as bytes
                                      file_data = in_file.read()
                                      #keyfileflags =file_data[144] 
                                      #print("Key file opned 0")
                                      if 1 == self.ENCvar.get():
                                          idx = 0
                                          for i in range(0,48): #efuse Range
                                              temp= file_data[idx]<< 16 | (i)
                                              temp = struct.pack('I',temp)       
                                              efuse_data_table.append(temp) 
                                              #print("Key file opned 1")
                                              idx = idx+ 1 
                                          #temp1 = 0x00200000 | 0x31
                                          #log_file_cnt.append("CRC-32 generation")
                                          #temp1 = struct.pack('I',temp1) 
                                          #efuse_data_table.append(temp1)       
                                          if ((1 == self.ECDHENCvar.get())): #and (keyfileflags & ENCT_ENBALE_BIT)):
                                              update_efuse483 = True       
                                              in_file_1 = open (key_fileloc_1,"rb")   
                                              in_file_1.seek(0)    
                                              file_data_1 = in_file_1.read()  
                                              idx = 0        
                                              #if (keyfileflags & ECDH_ENBALE_BIT):        
                                              for i in range(128,176):#(416,480): #efuse Range
                                                temp= file_data_1[idx]<< 16 | (i)
                                                temp = struct.pack('I',temp)       
                                                efuse_data_table.append(temp) 
                                                #print("Key file opned 2")
                                                idx = idx+ 1 
                                          if (1 == self.ECDHLCKvar.get()):
                                              update_efuse483_lock = True      
                                              update_efuse483 = True

                                          if( 1 == self.ECDHPrivLCKvar.get()):
                                              update_efuse_ecdh_priv_lock = True

                                          if(1 == self.ECDHPubLCKvar.get()):
                                              update_efuse_ecdh_pub_lock = True

                                          log_file_cnt.append("Encryption: ECC Private Keys Generated \n Assigned see keys\keys_info.txt for details")
                                  # with open (key_fileloc_1,"rb") as key_in_file:
                                  #     if 1 == self.AUTHEnvar.get():
                                  #         key_in_file.seek(0)
                                  #         print("Authentication enable ")
                                  #         idx = 0
                                  #         for i in range(368,415):
                                  #             temp= key_in_file[idx]<< 16 | (i)
                                  #             temp = struct.pack('I',temp)       
                                  #             efuse_data_table.append(temp) 
                                  #             idx = idx+ 1
                                  #         if (1 == self.ECDSALCKvar.get()):
                                  #             update_efuse_ecdsa_lock = True
                                  #         update_efuse483 = True
                              except:
                                  print ("Error in Key Generation")
                                  log_file_cnt.append("Error in key file generation")
                                  messagebox.showinfo('Error in Key Generation', 'Please re-check the key_file.bin/ECDH filename  is generated in "keys" folder , so Utility is exit')
                                  return
                                  
                          temp=0x00000166
                          if 1 == self.AUTHEnvar.get():#no error
                              temp= temp | 0x00090000 #enabling 1011 of Bit 0 & 3 for authetication 0x00010000
                              log_file_cnt.append("Authentication Keys Generated and \n assigned  see keys\keys_info.txt for details")
                              log_file_cnt.append("Authentication Bit set in Efuse")

                          
                          if (1 == self.ECDHENCvar.get()) or 1 == self.ecdh_en_key_var.get():
                              temp = temp | 0x00020000
                              log_file_cnt.append("OTP Bytes 0-47 Encrypted with Secure AES-256 Encryption key derived from ECDH Public Key 2 (OTP Bytes 128-223)")
                              
                          # if ((1 == self.ENCvar.get()) and (True == update_efuse483_lock)):
                          #     temp= temp | 0x00020000
                          #     log_file_cnt.append("Encryption selected")

                          # temp1 = 0x000003f5 # OTP efuse bytes 1012 
                          # temp2 = 0x000003f8
                          # if 1 == self.ENCvar.get() or 0 == self.ENCvar.get():
                          #     if (( 1 == self.ECDHPrivLCKvar.get())):# #and (True == update_efuse_ecdh_priv_lock)):
                          #         temp1 = temp1 |0x00030000
                          #         #temp2 =temp2 | 0x00030000
                          #         log_file_cnt.append("ECDH Private Key Write Lock bit is set")

                          # if 1 == self.ENCvar.get() or 1 == self.ECDHENCvar.get() or 0 == self.ENCvar.get() or 0 == self.ECDHENCvar.get():
                          #     if (( 1 == self.ECDHPubLCKvar.get())):# and (True == update_efuse_ecdh_pub_lock)):
                          #         temp1 = temp1 |0x00700000
                          #         log_file_cnt.append("ECDH Public II Write Lock bit is set")
                          #     #else:
                          #         #temp1 = temp1 |0x00700000
                          #         #log_file_cnt.append("ECDH Public II Write Lock bit is set ")

                          # if 1==self.AUTHEnvar.get():        
                          #     if (( 1 == self.ECDSALCKvar.get()) ):#and (True == update_efuse_ecdsa_lock)):
                          #         temp1 = temp1 | 0x001B0000 # Efuse byte 1013 Bit 4 &5)
                          #         #temp2 = temp2 | 0x00180000 # Efuse byte 1016 Bit 4 &5)
                          #         log_file_cnt.append("ECDSA Key BA & HASH blob Write Lock bit is set")
                          #     #else:
                          #     #    temp1 = temp1 | 0x00300000 # Efuse byte 1012 Bit 4 &5)
                          #     #    log_file_cnt.append("ECDSA Key Write Lock bit is set &read lock bit is not set")

                          if(self.AEMvar.get()):
                              #temp = 0x000003f3 #  AES mandatory bit of efuse map region 1011[bit 2] 
                              temp= temp | 0x00040000 #Enable Bit2 if AES mandatory encryption bit is enabled in efuse 1011 region
                              log_file_cnt.append("AES Mandatory encryption bit enabled")                  

                          if(self.fullvar.get()):
                              #temp = 0x000003f3 #  AES mandatory bit of efuse map region 1011[bit 2] 
                              temp= temp | 0x00800000 #Enable Bit2 if AES mandatory encryption bit is enabled in efuse 1011 region
                              log_file_cnt.append("Fully Provisioned bit enabled")
                                 
                          if temp & 0xFFFF0000:             
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)

                          # if temp1 & 0xFFFF0000:
                          #     temp1 = struct.pack('I',temp1)
                          #     efuse_data_table.append(temp1)

                          # if temp2 & 0xFFFF0000:
                          #     temp2 = struct.pack('I',temp2)
                          #     efuse_data_table.append(temp2)  


                          # if False == soteria_flag:
                          #     temp1 = 0x00000163  # DICE RIOT 0x163 / 355
                          #     if 1 == self.dice_hash_var.get():
                          #       temp1 |= 0x00000163 | (0x00800163)
                          #       log_file_cnt.append("DICE HASH 384 Feature bit is set")
                          #     if 1 == self.dicevar.get():
                          #        temp1 = temp1 |0x00010000
                          #        log_file_cnt.append("DICE RIOT Feature Enabled bit is set")
                              
                          #     if temp1 & 0xFFFF0000:             
                          #         temp1 = struct.pack('I',temp1)
                          #         efuse_data_table.append(temp1)                          


                          # temp1 = 0x00000162  # Security Feature 0x162 / 354
                          # if 1 == self.Rollvar.get() or 1 == self.ecdsakeyvar.get():
                          #   wbit11 = 0x000803f4
                          #   wbit11 = struct.pack('I',wbit11)
                          #   efuse_data_table.append(wbit11)                                              
                          # if 1 == self.Rollvar.get():
                          #   temp1 = temp1 |0x00010000
                          #   #wbit11 = 0x000803f4
                          #   #wbit11 = struct.pack('I',wbit11)
                          #   #efuse_data_table.append(wbit11)                          
                          #   log_file_cnt.append("Security Feature of Rollback Protection feature Enabled bit is set")
                          #   log_file_cnt.append("Write byte 11 bit is set for rollback ")
                          # if 1 == self.MRollvar.get():
                          #   temp1 = temp1 |0x00020000
                          #   log_file_cnt.append("Security Feature of Manaul Rollback Control feature Enabled bit is set")
                          # if 1 == self.ecdsakeyvar.get():
                          #   temp1 = temp1 |0x00040000
                          #   wbit11 = 0x000803f4
                          #   wbit11 = struct.pack('I',wbit11)
                          #   efuse_data_table.append(wbit11)                          
                          #   log_file_cnt.append("Write byte 11 bit is set for rollback ")
                          #   log_file_cnt.append("Security Feature of ECDSA Key Revocation feature Enabled bit is set")
                          # if 1 == self.Mecdsakeyvar.get():
                          #   temp1 = temp1 |0x00080000
                          #   log_file_cnt.append("Security Feature of Manaul Key Revocation Control Enabled bit is set")

                          # if temp1 & 0xFFFF0000:             
                          #   temp1 = struct.pack('I',temp1)
                          #   efuse_data_table.append(temp1)

                          # temp1 = 0x000003f4  # OTP write lock 1012
                          # if 1 == self.securebootlckvar.get():
                          #   #print("val ",val)
                          #   temp1= temp1 | 0x00840000 
                          #   #temp1 = temp1 |(val < 32)
                          #   #print("temp1 ",temp1)
                          #   log_file_cnt.append("SecurityBoot Write lock bit is updated")
                          #   temp1 = struct.pack('I',temp1)
                          #   #print("generate_efuse 7")
                          #   efuse_data_table.append(temp1)

                          # otp_temp1 = 0x000003f7  # OTP write lock 1015
                          # if 1 == self.sg2lckvar.get():
                          #   #print("val ",val)
                          #   otp_temp1= otp_temp1 | 0x00380000 #0x3FC ;#0x1FC;
                          #   #temp1 = temp1 |(val < 32)
                          #   #print("temp1 ",temp1)
                          #   log_file_cnt.append("SecurityBoot G2  Write lock bit is updated")
                          #   #temp1 = struct.pack('I',temp1)
                          #   #print("generate_efuse 7")
                          #   #efuse_data_table.append(temp1)

                          # #temp1 = 0x000003f7  # OTP write lock 1015
                          # if 1 == self.flashlckvar.get():
                          #   #print("val ",val)
                          #   otp_temp1= otp_temp1 | 0x00800000 #0x3FC ;#0x1FC;
                          #   #temp1 = temp1 |(val < 32)
                          #   #print("temp1 ",temp1)
                          #   log_file_cnt.append(" Write lock bit is updated for TAGX BA & Flash Comp 1 BA ")
                          #   #temp1 = struct.pack('I',temp1)
                          #   #print("generate_efuse 7")
                          #   #efuse_data_table.append(temp1)

                          # if otp_temp1 & 0xFFFF0000:  
                          #   otp_temp1 = struct.pack('I',otp_temp1)
                          #   efuse_data_table.append(otp_temp1) 

                          # temp1 = 0x0000005D  # Security Feature 0x5D / 93
                          # if "" != self.secureboot.get():
                          #   val = int(self.secureboot.get(),16)
                          #   #print("val ",val)
                          #   temp1= ((val<<16) & 0xFF0000)| 0x5D#0x3FC ;#0x1FC;
                          #   #temp1 = temp1 |(val < 32)
                          #   #print("temp1 ",temp1)
                          #   #log_file_cnt.append("SecurityBoot Write lock bit is updated ")
                          #   log_file_cnt.append("Security Boot value is updated  ")
                          #   temp1 = struct.pack('I',temp1)
                          #   #print("generate_efuse 7")
                          #   efuse_data_table.append(temp1)
                          #   #print("generate_efuse 6")


                          # if( 1== otp_write_lock_en):
                          #     temp1 = 0x000003f5
                          #     if((1 == write_lock_flag_15)):
                          #         temp1 = temp1 |0x00800000
                          #         log_name = "Customer region OTP Write Lock 1 : Hex :(0x1E0-0x1FF) is set" 
                          #         log_file_cnt.append(log_name)
                          #         temp1 = struct.pack('I',temp1)
                          #         efuse_data_table.append(temp1)    

                          #     temp2 = 0x000003f6    
                          #     if((1 == otp_lock_16) and (1 == write_lock_flag_16)):
                          #         temp2 = temp2 |0x00010000
                          #         log_name = "Customer region OTP Write Lock 2 : Hex :(0x200-0x21F) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_17) and (1 == write_lock_flag_17)):
                          #         temp2 = temp2 |0x00020000
                          #         log_name = "Customer region OTP Write Lock 3 : Hex :(0x220-0x23F) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_18) and (1 == write_lock_flag_18)):
                          #         temp2 = temp2 |0x00040000
                          #         log_name = "Customer region OTP Write Lock 4 : Hex :(0x240-0x25F) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_19) and (1 == write_lock_flag_19)):
                          #         temp2 = temp2 |0x00080000
                          #         log_name = "Customer region OTP Write Lock 5 : Hex :(0x260-0x27F) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_20) and (1 == write_lock_flag_20)):
                          #         temp2 = temp2 |0x00100000
                          #         log_name = "Customer region OTP Write Lock 6 : Hex :(0x280-0x29F) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_21) and (1 == write_lock_flag_21)):
                          #         temp2 = temp2 |0x00200000
                          #         log_name = "Customer region OTP Write Lock 7 : Hex :(0x2A0-0x2BF) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_22) and (1 == write_lock_flag_22)):
                          #         temp2 = temp2 |0x00400000
                          #         log_name = "Customer region OTP Write Lock 8 : Hex :(0x2C0-0x2DF) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_23) and (1 == write_lock_flag_23)):
                          #         temp2 = temp2 |0x00800000
                          #         log_name = "Customer region OTP Write Lock 9 : Hex :(0x2E0-0x2FF) is set" 
                          #         log_file_cnt.append(log_name)

                          #     if temp2 & 0xFFFF0000:  
                          #         temp2 = struct.pack('I',temp2)
                          #         efuse_data_table.append(temp2)    

                          #     temp3 = 0x000003f7
                          #     if((1 == otp_lock_24) and (1 == write_lock_flag_24)):
                          #         temp3 = temp3 |0x00010000
                          #         log_name = "Customer region OTP Write Lock 10 : Hex :(0x300-0x31F) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_25) and (1 == write_lock_flag_25)):
                          #         temp3 = temp3 |0x00020000
                          #         log_name = "Customer region OTP Write Lock 11 : Hex :(0x320-0x33F) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_26) and (1 == write_lock_flag_26)):
                          #         temp3 = temp3 |0x00040000
                          #         log_name = "Customer region OTP Write Lock 12 : Hex :(0x340-0x35F) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_27) and (1 == write_lock_flag_27)):
                          #         temp3 = temp3 |0x00080000
                          #         log_name = "Customer region OTP Write Lock 13 : Hex :(0x360-0x37F) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_28) and (1 == write_lock_flag_28)):
                          #         temp3 = temp3 |0x00100000
                          #         log_name = "Customer region OTP Write Lock 14 :Hex :(0x380-0x39F) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if((1 == otp_lock_29) and (1 == write_lock_flag_29)):
                          #         log_name = "Customer region OTP Write Lock 15 :Hex :(0x3A0-0x3BF) is set" 
                          #         log_file_cnt.append(log_name)
                          #         temp3 = temp3 |0x00200000
                                  
                          #     if((1 == otp_lock_30) and (1 == write_lock_flag_30)):
                          #         temp3 = temp3 |0x00400000
                          #         log_name = "Customer region OTP Write Lock 16 :Hex :(0x3C0-0x3DF) is set" 
                          #         log_file_cnt.append(log_name)
                                  
                          #     if temp3 & 0xFFFF0000:  
                          #         temp3 = struct.pack('I',temp3)
                          #         efuse_data_table.append(temp3)                     

                          # '''            
                          # if 0 == self.ATEvar.get():
                          #     temp=0x00800023
                          #     temp = struct.pack('I',temp)
                          #     efuse_data_table.append(temp)
                          #     log_file_cnt.append("ATE Mode Disabled in Efuse")
                          # else:
                          #     log_file_cnt.append("ATE Mode Enabled in Efuse")
                      
                          # if 1 == self.JTAGvar.get(): #JTAG Enable
                          #     if 1== self.JTAGvar1.get():
                          #         temp=0x00100022
                          #         temp = struct.pack('I',temp)
                          #         efuse_data_table.append(temp)    
                          #         log_file_cnt.append("JTAG Enabled in Efuse - 2Wire(SWD)")
                          #     else:
                          #         log_file_cnt.append("JTAG Enabled in Efuse - 4Wire")
                          # '''
                                 
                          temp = 0x000003f2
                          if 1 == self.JTAGvar.get(): #JTAG Disable 
                              temp= temp | 0x00800000
                              #temp = 0x00400162 # offset 0x162 of bit[6]
                              #temp = struct.pack('I',temp)     
                              #efuse_data_table.append(temp)      
                              log_file_cnt.append("JTAG Debug Disable is Disabled ")
                              #log_file_cnt.append("Generate CRC-32 of OTP is set")
                          else:
                              #log_file_cnt.append("JTAG Enabled ") 
                              #log_file_cnt.append("ROM JTAG Debug Enabled")    
                              log_file_cnt.append("JTAG Debug Disable is Enabled ")
                          if 1 == self.debug_disable_var.get(): #JTAG Disable 
                              temp= temp | 0x00040000
                              #temp = 0x00400162 # offset 0x162 of bit[6]
                              #temp = struct.pack('I',temp)     
                              #efuse_data_table.append(temp)      
                              log_file_cnt.append("Debug Disable Lock : Debug port disabled and locked is set")
                          else:
                              #log_file_cnt.append("JTAG Enabled ") 
                              #log_file_cnt.append("ROM JTAG Debug Enabled")    
                              log_file_cnt.append("Debug Disable Lock :   Debug capability determined by Bit[7] Debug Disabled is set")
                          if 1 == self.debug_pun_var.get(): #JTAG Disable 
                              temp= temp | 0x00100000
                              #temp = 0x00400162 # offset 0x162 of bit[6]
                              #temp = struct.pack('I',temp)     
                              #efuse_data_table.append(temp)      
                              log_file_cnt.append(" DEBUG_PU_EN:  1 = If JTAG Enabled, DEBUG_PU_EN bit in Debug Enable Register = 1. If JTAG Disabled, DEBUG_PU_EN bit in Debug Enable Register = 0 ")
                          else:
                              #log_file_cnt.append("JTAG Enabled ") 
                              #log_file_cnt.append("ROM JTAG Debug Enabled")    
                              log_file_cnt.append(" DEBUG_PU_EN:  0 = DEBUG_PU_EN bit in Debug Enable Register = 0")
                          
                          if temp & 0xFFFF0000:
                            temp = struct.pack('I',temp)
                            efuse_data_table.append(temp)

                             


                          prod_debug  =self.prod_debug.get()
                          if ( "" != prod_debug):
                              tag = int(self.prod_debug.get(),16)
                              value = tag 
                              if (tag > 0xFF):
                                messagebox.showinfo('Production Debug Owner Warning window', 'Production Debug owner is not provided or greater than 1 byte, please provide the valid value')
                                return 3 
                              v1 = (value  & (0xFF))
                              temp= ((v1<<16) & 0xFF0000)| 0x15B;
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)  
                              log_file_cnt.append("Production Debug owner Byte Updated")

                          otp_rollback_var_0 = int(self.otp_rollback_var_0.get(),16)
                          value = otp_rollback_var_0 
                          if (otp_rollback_var_0 > 0xffffffff):
                            messagebox.showinfo('Rollback Protection Byte 0-3  Warning window', 'Rollback Protection Byte 0-3 value is not provided or greater than 4 byte, please provide the valid value')
                            return 3 
                          value = value & 0xffffffff#<< 4
                          v1 = (value  & (0xFF))
                          v2 =((value>>8 ) & (0xFF))
                          v3 =((value>>16 )  & (0xFF))
                          v4 =((value>>24)  & (0xFF))
                          #print("tag ",tag)
                          temp= ((v1<<16) & 0xFF0000)| 0x140
                          #print("temp 0 = ",temp)
                          temp = struct.pack('I',temp)
                          efuse_data_table.append(temp)   
                          temp= ((v2<<16) & 0xFF0000)| 0x141
                          #print("temp 1 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)  
                          temp= ((v3<<16) & 0xFF0000)| 0x142
                          #print("temp 2 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          temp= ((v4<<(16)) & 0xFF0000)| 0x143
                          #print("temp 3 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          log_file_cnt.append("Rollback Protection Byte 0-3 value Updated")

                          otp_rollback_var_1 = int(self.otp_rollback_var_1.get(),16)
                          value = otp_rollback_var_1 
                          if (otp_rollback_var_1 > 0xffffffff):
                            messagebox.showinfo('Rollback Protection Byte 4-7  Warning window', 'Rollback Protection Byte 4-7 value is not provided or greater than 4 byte, please provide the valid value')
                            return 3 
                          value = value & 0xffffffff#<< 4
                          v1 = (value  & (0xFF))
                          v2 =((value>>8 ) & (0xFF))
                          v3 =((value>>16 )  & (0xFF))
                          v4 =((value>>24)  & (0xFF))
                          #print("tag ",tag)
                          temp= ((v1<<16) & 0xFF0000)| 0x144
                          #print("temp 0 = ",temp)
                          temp = struct.pack('I',temp)
                          efuse_data_table.append(temp)   
                          temp= ((v2<<16) & 0xFF0000)| 0x145
                          #print("temp 1 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)  
                          temp= ((v3<<16) & 0xFF0000)| 0x146
                          #print("temp 2 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          temp= ((v4<<(16)) & 0xFF0000)| 0x147
                          #print("temp 3 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)                 

                          otp_rollback_var_2 = int(self.otp_rollback_var_2.get(),16)
                          value = otp_rollback_var_2 
                          if (otp_rollback_var_2 > 0xffffffff):
                            messagebox.showinfo('Rollback Protection Byte 8-11  Warning window', 'Rollback Protection Byte 8-11 value is not provided or greater than 4 byte, please provide the valid value')
                            return 3 
                          value = value & 0xffffffff#<< 4
                          v1 = (value  & (0xFF))
                          v2 =((value>>8 ) & (0xFF))
                          v3 =((value>>16 )  & (0xFF))
                          v4 =((value>>24)  & (0xFF))
                          #print("tag ",tag)
                          temp= ((v1<<16) & 0xFF0000)| 0x148
                          #print("temp 0 = ",temp)
                          temp = struct.pack('I',temp)
                          efuse_data_table.append(temp)   
                          temp= ((v2<<16) & 0xFF0000)| 0x149
                          #print("temp 1 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)  
                          temp= ((v3<<16) & 0xFF0000)| 0x14A
                          #print("temp 2 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          temp= ((v4<<(16)) & 0xFF0000)| 0x14B
                          #print("temp 3 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          log_file_cnt.append("Rollback Protection Byte 8-11 value Updated")                  

                          otp_rollback_var_3 = int(self.otp_rollback_var_3.get(),16)
                          value = otp_rollback_var_3 
                          if (otp_rollback_var_3 > 0xffffffff):
                            messagebox.showinfo('Rollback Protection Byte 12-15  Warning window', 'Rollback Protection Byte 12-15 value is not provided or greater than 4 byte, please provide the valid value')
                            return 3 
                          value = value & 0xffffffff#<< 4
                          v1 = (value  & (0xFF))
                          v2 =((value>>8 ) & (0xFF))
                          v3 =((value>>16 )  & (0xFF))
                          v4 =((value>>24)  & (0xFF))
                          #print("tag ",tag)
                          temp= ((v1<<16) & 0xFF0000)| 0x14C
                          #print("temp 0 = ",temp)
                          temp = struct.pack('I',temp)
                          efuse_data_table.append(temp)   
                          temp= ((v2<<16) & 0xFF0000)| 0x14D
                          #print("temp 1 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)  
                          temp= ((v3<<16) & 0xFF0000)| 0x14E
                          #print("temp 2 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          temp= ((v4<<(16)) & 0xFF0000)| 0x14F
                          #print("temp 3 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          log_file_cnt.append("Rollback Protection Byte 12-15 value Updated")                  

                          ecdsa_rollback_var_0 = int(self.ecdsa_rollback_var_0.get(),16)
                          value = ecdsa_rollback_var_0 
                          if (ecdsa_rollback_var_0 > 0xffffffff):
                            messagebox.showinfo('ECDSA Key Revocation Byte 0-3  Warning window', 'ECDSA Key Revocation Byte 0-3  value is not provided or greater than 4 byte, please provide the valid value')
                            return 3 
                          value = value & 0xffffffff#<< 4
                          v1 = (value  & (0xFF))
                          v2 =((value>>8 ) & (0xFF))
                          v3 =((value>>16 )  & (0xFF))
                          v4 =((value>>24)  & (0xFF))
                          #print("tag ",tag)
                          temp= ((v1<<16) & 0xFF0000)| 0x150
                          #print("temp 0 = ",temp)
                          temp = struct.pack('I',temp)
                          efuse_data_table.append(temp)   
                          temp= ((v2<<16) & 0xFF0000)| 0x151
                          #print("temp 1 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)  
                          temp= ((v3<<16) & 0xFF0000)| 0x152
                          #print("temp 2 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          temp= ((v4<<(16)) & 0xFF0000)| 0x153
                          #print("temp 3 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          log_file_cnt.append("ECDSA Key Revocation Byte 0-3  value Updated")

                          otp_crc_var = int(self.otp_crc_var.get(),16)
                          value = otp_crc_var 
                          if (otp_crc_var > 0xffffffff):
                            messagebox.showinfo('OTP CRC value  Warning window', 'OTP CRC  value is not provided or greater than 4 byte, please provide the valid value')
                            return 3 
                          value = value & 0xffffffff#<< 4
                          v1 = (value  & (0xFF))
                          v2 =((value>>8 ) & (0xFF))
                          v3 =((value>>16 )  & (0xFF))
                          v4 =((value>>24)  & (0xFF))
                          #print("tag ",tag)
                          temp= ((v1<<16) & 0xFF0000)| 0x154#0x3FC ;#0x1FC;
                          #print("temp 0 = ",temp)
                          temp = struct.pack('I',temp)
                          efuse_data_table.append(temp)   
                          temp= ((v2<<16) & 0xFF0000)| 0x155#0x3FD #0x1FD;
                          #print("temp 1 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)  
                          temp= ((v3<<16) & 0xFF0000)| 0x156#0x3FD #0x1FD;
                          #print("temp 2 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          temp= ((v4<<(16)) & 0xFF0000)| 0x157#0x3FD #0x1FD;
                          #print("temp 3 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          log_file_cnt.append("OTP CRC value Updated")

                          plat_id  =self.plat_id.get()
                          if ( "" != plat_id):
                              tag = int(self.plat_id.get(),16)
                              value = tag 
                              if (tag > 0xFFFF):
                                messagebox.showinfo('Platform ID Warning window', 'Platform ID value is not provided or greater than 2 byte, please provide the valid value')
                                return 3 
                              v1 = (value  & (0xFF))
                              v2 =((value>>8 ) & (0xFF))
                              temp= ((v1<<16) & 0xFF0000)| 0x160#0x3FC ;#0x1FC;
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)  
                              temp= ((v2<<16) & 0xFF0000)| 0x161#0x3FC ;#0x1FC;
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)                  

                          security_features_var  =self.security_features_var.get()
                          if ( "" != security_features_var):
                              tag = int(self.security_features_var.get(),16)
                              value = tag 
                              if (tag > 0xFF):
                                messagebox.showinfo('Security Features Warning window', 'Security Features value is not provided or greater than 1 byte, please provide the valid value')
                                return 3 
                              v1 = (value  & (0xFF))
                              temp= ((v1<<16) & 0xFF0000)| 0x162
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)   
                              log_file_cnt.append("Security Features value  Updated")                  

                          dice_riot_feature_var  =self.dice_riot_feature_var.get()
                          if ( "" != dice_riot_feature_var):
                              tag = int(self.dice_riot_feature_var.get(),16)
                              value = tag 
                              if (tag > 0xFF):
                                messagebox.showinfo('DICE_RIOT & Optional Features Warning window', 'DICE_RIOT & Optional Features value is not provided or greater than 1 byte, please provide the valid value')
                                return 3 
                              v1 = (value  & (0xFF))
                              temp= ((v1<<16) & 0xFF0000)| 0x163
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)   
                              log_file_cnt.append("DICE_RIOT & Optional Features value  Updated")                  

                          crisis_flash_feature_var  =self.crisis_flash_feature_var.get()
                          if ( "" != crisis_flash_feature_var):
                              tag = int(self.crisis_flash_feature_var.get(),16)
                              value = tag 
                              if (tag > 0xFF):
                                messagebox.showinfo('Crisis Flash & Load Failure Recovery Warning window', 'Crisis Flash & Load Failure Recovery value is not provided or greater than 1 byte, please provide the valid value')
                                return 3 
                              v1 = (value  & (0xFF))
                              temp= ((v1<<16) & 0xFF0000)| 0x164
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)   
                              log_file_cnt.append("Crisis Flash & Load Failure Recovery value  Updated")
                          
                          optional_feature_var  =self.optional_feature_var.get()
                          if ( "" != optional_feature_var):
                              tag = int(self.optional_feature_var.get(),16)
                              value = tag 
                              if (tag > 0xFF):
                                messagebox.showinfo('Optional Features Warning window', 'Optional Features value is not provided or greater than 1 byte, please provide the valid value')
                                return 3 
                              v1 = (value  & (0xFF))
                              temp= ((v1<<16) & 0xFF0000)| 0x165
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)   
                              log_file_cnt.append("Optional Features value  Updated")
                          
                          secure_boot_var  =self.secure_boot_var.get()
                          if ( "" != secure_boot_var):
                              tag = int(self.secure_boot_var.get(),16)
                              value = tag 
                              if (tag > 0xFF):
                                messagebox.showinfo('Secure Boot Warning window', 'Secure Boot value is not provided or greater than 1 byte, please provide the valid value')
                                return 3 
                              v1 = (value  & (0xFF))
                              temp= ((v1<<16) & 0xFF0000)| 0x167
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)   
                              log_file_cnt.append("Secure Boot value  Updated")                  

                          custom_features_var  =self.custom_features_var.get()
                          if ( "" != custom_features_var):
                              tag = int(self.custom_features_var.get(),16)
                              value = tag 
                              if (tag > 0xFF):
                                messagebox.showinfo('Custom Features Warning window', 'Custom Features value is not provided or greater than 1 byte, please provide the valid value')
                                return 3 
                              v1 = (value  & (0xFF))
                              temp= ((v1<<16) & 0xFF0000)| 0x16E
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)   
                              log_file_cnt.append("Custom Features value  Updated")                  

                          crisis_mode_var  =self.crisis_mode_var.get()
                          if ( "" != crisis_mode_var):
                              tag = int(self.crisis_mode_var.get(),16)
                              value = tag 
                              if (tag > 0xFF):
                                messagebox.showinfo('Crisis Mode Warning window', 'Crisis Mode value is not provided or greater than 1 byte, please provide the valid value')
                                return 3 
                              v1 = (value  & (0xFF))
                              temp= ((v1<<16) & 0xFF0000)| 0x16F
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)   
                              log_file_cnt.append("Crisis Mode value  Updated")

                          if 1== self.plat_ECCP384var.get() :
                            self.plat_sha384_bin_gen()
                            opensslpath = self.opensslpath.get()
                            cmd = opensslpath + " version "
                            cmd ='"%s"'%cmd
                            ret = os.system(cmd)
                            if ret:
                              messagebox.showinfo('Opensll path  Warning window', 'openssl path is missing ')
                              return 1
                            key_fileloc_1=fldloc+"/keys/plat_hash384.bin"
                            if True == os.path.isfile(key_fileloc_1):
                                with open (key_fileloc_1,"rb") as key_in_file:
                                    if 1 == self.plat_ECCP384var.get():
                                        key_in_file.seek(0)
                                        key_file_data = key_in_file.read()
                                        #print("Authentication enable ")
                                        idx = 0
                                        #keyfileflags =key_in_file[255] 
                                        for i in range(864,912):
                                            temp= key_file_data[idx]<< 16 | (i)
                                            temp = struct.pack('I',temp)       
                                            efuse_data_table.append(temp) 
                                            idx = idx+ 1
                          if 1 == self.otp_read_lock_var_0.get():
                              otp_read_lock_byte_var_0 = int(self.otp_read_lock_byte_var_0.get(),16)
                              value = otp_read_lock_byte_var_0 
                              if (otp_read_lock_byte_var_0 > 0xffffffff):
                                messagebox.showinfo('OTP Read Byte Lock - Byte 0-3  Warning window', 'OTP Read Byte Lock - Byte 0-3  value is not provided or greater than 4 byte, please provide the valid value')
                                return 3 
                              value = value & 0xffffffff#<< 4
                              v1 = (value  & (0xFF))
                              v2 =((value>>8 ) & (0xFF))
                              v3 =((value>>16 )  & (0xFF))
                              v4 =((value>>24)  & (0xFF))
                              #print("tag ",tag)
                              temp= ((v1<<16) & 0xFF0000)| 0x3C0
                              #print("temp 0 = ",temp)
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)   
                              temp= ((v2<<16) & 0xFF0000)| 0x3C1
                              #print("temp 1 = ",temp)
                              temp = struct.pack('I',temp)       
                              efuse_data_table.append(temp)  
                              temp= ((v3<<16) & 0xFF0000)| 0x3C2
                              #print("temp 2 = ",temp)
                              temp = struct.pack('I',temp)       
                              efuse_data_table.append(temp)
                              temp= ((v4<<(16)) & 0xFF0000)| 0x3C3
                              #print("temp 3 = ",temp)
                              temp = struct.pack('I',temp)       
                              efuse_data_table.append(temp)
                              log_file_cnt.append("OTP Read Byte Lock - Byte 0-3 value Updated")                  

                          if 1== self.otp_write_lock_var_0.get():
                              otp_write_lock_byte_var_0 = int(self.otp_write_lock_byte_var_0.get(),16)
                              value = otp_write_lock_byte_var_0 
                              if (otp_write_lock_byte_var_0 > 0xffffffff):
                                messagebox.showinfo('OTP Write Byte Lock - Byte 0-3  Warning window', 'OTP Write Byte Lock - Byte 0-3  value is not provided or greater than 4 byte, please provide the valid value')
                                return 3 
                              value = value & 0xffffffff#<< 4
                              v1 = (value  & (0xFF))
                              v2 =((value>>8 ) & (0xFF))
                              v3 =((value>>16 )  & (0xFF))
                              v4 =((value>>24)  & (0xFF))
                              #print("tag ",tag)
                              temp= ((v1<<16) & 0xFF0000)| 0x3C4
                              #print("temp 0 = ",temp)
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)   
                              temp= ((v2<<16) & 0xFF0000)| 0x3C5
                              #print("temp 1 = ",temp)
                              temp = struct.pack('I',temp)       
                              efuse_data_table.append(temp)  
                              temp= ((v3<<16) & 0xFF0000)| 0x3C6
                              #print("temp 2 = ",temp)
                              temp = struct.pack('I',temp)       
                              efuse_data_table.append(temp)
                              temp= ((v4<<(16)) & 0xFF0000)| 0x3C7
                              #print("temp 3 = ",temp)
                              temp = struct.pack('I',temp)       
                              efuse_data_table.append(temp)
                              log_file_cnt.append("OTP Write Byte Lock - Byte 0-3 value Updated")

                          if 1== self.otp_write_secure_lock.get():
                              otp_write_secure_lock_byte  =self.otp_write_secure_lock_byte.get()
                              if ( "" != otp_write_secure_lock_byte):
                                  tag = int(self.otp_write_secure_lock_byte.get(),16)
                                  value = tag 
                                  if (tag > 0xFF):
                                    messagebox.showinfo('OTP WRITE SECURE_LOCK Warning window', 'OTP WRITE SECURE_LOCK value is not provided or greater than 1 byte, please provide the valid value')
                                    return 3 
                                  v1 = (value  & (0xFF))
                                  temp= ((v1<<16) & 0xFF0000)| 0x3C8
                                  temp = struct.pack('I',temp)
                                  efuse_data_table.append(temp)   
                                  log_file_cnt.append("OTP WRITE SECURE_LOCK value  Updated")                  

                          if 1 == self.otp_read_secure_lock.get():
                              otp_read_secure_lock_byte  =self.otp_read_secure_lock_byte.get()
                              if ( "" != otp_read_secure_lock_byte):
                                  tag = int(self.otp_read_secure_lock_byte.get(),16)
                                  value = tag 
                                  if (tag > 0xFF):
                                    messagebox.showinfo('OTP READ SECURE_LOCK Warning window', 'OTP READ SECURE_LOCK value is not provided or greater than 1 byte, please provide the valid value')
                                    return 3 
                                  v1 = (value  & (0xFF))
                                  temp= ((v1<<16) & 0xFF0000)| 0x3C9
                                  temp = struct.pack('I',temp)
                                  efuse_data_table.append(temp)   
                                  log_file_cnt.append("OTP READ SECURE_LOCK value  Updated")                  

                          if 1 == self.cfg_lock_byte_0.get():
                              cfg_lock_byte_0_val  =self.cfg_lock_byte_0_val.get()
                              if ( "" != cfg_lock_byte_0_val):
                                  tag = int(self.cfg_lock_byte_0_val.get(),16)
                                  value = tag 
                                  if (tag > 0xFF):
                                    messagebox.showinfo('CFG_LOCK Byte 0 Warning window', 'CFG_LOCK Byte 0 value is not provided or greater than 1 byte, please provide the valid value')
                                    return 3 
                                  v1 = (value  & (0xFF))
                                  temp= ((v1<<16) & 0xFF0000)| 0x3CA
                                  temp = struct.pack('I',temp)
                                  efuse_data_table.append(temp)   
                                  log_file_cnt.append("CFG_LOCK Byte 0 value  Updated")                  

                          if 1 == self.cfg_lock_byte_1.get():
                              cfg_lock_byte_1_val  =self.cfg_lock_byte_1_val.get()
                              if ( "" != cfg_lock_byte_1_val):
                                  tag = int(self.cfg_lock_byte_1_val.get(),16)
                                  value = tag 
                                  if (tag > 0xFF):
                                    messagebox.showinfo('CFG_LOCK Byte 1 Warning window', 'CFG_LOCK Byte 1 value is not provided or greater than 1 byte, please provide the valid value')
                                    return 3 
                                  v1 = (value  & (0xFF))
                                  temp= ((v1<<16) & 0xFF0000)| 0x3CB
                                  temp = struct.pack('I',temp)
                                  efuse_data_table.append(temp)   
                                  log_file_cnt.append("CFG_LOCK Byte 1 value  Updated")                  

                          if 1 == self.cfg_lock_byte_2.get():
                              cfg_lock_byte_2_val  =self.cfg_lock_byte_2_val.get()
                              if ( "" != cfg_lock_byte_2_val):
                                  tag = int(self.cfg_lock_byte_2_val.get(),16)
                                  value = tag 
                                  if (tag > 0xFF):
                                    messagebox.showinfo('CFG_LOCK Byte 2 Warning window', 'CFG_LOCK Byte 2 value is not provided or greater than 1 byte, please provide the valid value')
                                    return 3 
                                  v1 = (value  & (0xFF))
                                  temp= ((v1<<16) & 0xFF0000)| 0x3CC
                                  temp = struct.pack('I',temp)
                                  efuse_data_table.append(temp)   
                                  log_file_cnt.append("CFG_LOCK Byte 2 value  Updated")                  

                          if 1 == self.cfg_lock_byte_3.get():
                              cfg_lock_byte_3_val  =self.cfg_lock_byte_3_val.get()
                              if ( "" != cfg_lock_byte_3_val):
                                  tag = int(self.cfg_lock_byte_3_val.get(),16)
                                  value = tag 
                                  if (tag > 0xFF):
                                    messagebox.showinfo('CFG_LOCK Byte 3 Warning window', 'CFG_LOCK Byte 3 value is not provided or greater than 1 byte, please provide the valid value')
                                    return 3 
                                  v1 = (value  & (0xFF))
                                  temp= ((v1<<16) & 0xFF0000)| 0x3CD
                                  temp = struct.pack('I',temp)
                                  efuse_data_table.append(temp)   
                                  log_file_cnt.append("CFG_LOCK Byte 3 value  Updated")                  

                          if 1 == self.cfg_lock_byte_4.get():
                              cfg_lock_byte_4_val  =self.cfg_lock_byte_4_val.get()
                              if ( "" != cfg_lock_byte_4_val):
                                  tag = int(self.cfg_lock_byte_4_val.get(),16)
                                  value = tag 
                                  if (tag > 0xFF):
                                    messagebox.showinfo('CFG_LOCK Byte 4 Warning window', 'CFG_LOCK Byte 4 value is not provided or greater than 1 byte, please provide the valid value')
                                    return 3 
                                  v1 = (value  & (0xFF))
                                  temp= ((v1<<16) & 0xFF0000)| 0x3CE
                                  temp = struct.pack('I',temp)
                                  efuse_data_table.append(temp)   
                                  log_file_cnt.append("CFG_LOCK Byte 4 value  Updated")

                          if 1 == self.TAGvar.get():
                              tagadd = self.tagAddr.get()
                              try:
                                tagaddr =int(self.tagAddr.get(),16)
                              except ValueError:
                                   messagebox.showinfo('TAGAddr0 Warning window', 'Tag0 address is not empty, please provide the valid TAG address')
                                   return 3                        
                              if ( "" != tagadd) and ("00000000" != tagadd):
                                  tag = int(self.tagAddr.get(),16)
                                  val = self.TAGvar_1.get()
                                  val_1 = self.Tagflashvar_0.get()
                                  if (tag & 0x3)>0 or tag > 0xfffffffc:
                                    messagebox.showinfo('TagAddr0 Warning window', 'TagAddr0 Address is multiple of 4 byte , please provide the valid TagAddr0 in 4 byte boundary')
                                    return 3
                                  value = (tag & 0xfffffffc )| ((val)|(val_1<<1))
                                  #value = (tag << 2 )| ((val)|(val_1<<1))
                                  v1 = (value  & (0xFF))
                                  v2 =((value>>8 ) & (0xFF))
                                  v3 =((value>>16 )  & (0xFF))
                                  v4 =((value>>24)  & (0xFF))
                                  #print("tag ",tag)
                                  temp= ((v1<<16) & 0xFF0000)| 0x3E0#0x3FC ;#0x1FC;
                                  #print("temp 0 = ",temp)
                                  temp = struct.pack('I',temp)
                                  efuse_data_table.append(temp)   
                                  temp= ((v2<<16) & 0xFF0000)| 0x3E1#0x3FD #0x1FD;
                                  #print("temp 1 = ",temp)
                                  temp = struct.pack('I',temp)       
                                  efuse_data_table.append(temp)  
                                  temp= ((v3<<16) & 0xFF0000)| 0x3E2#0x3FD #0x1FD;
                                  #print("temp 2 = ",temp)
                                  temp = struct.pack('I',temp)       
                                  efuse_data_table.append(temp)
                                  temp= (((v4<<16)) & 0xFF0000)| 0x3E3#0x3FD #0x1FD;
                                  #print("temp 3 = ",temp)
                                  temp = struct.pack('I',temp)       
                                  efuse_data_table.append(temp)
                                  temp = "Tag0 SPI Flash Base Address location "+tagadd
                                  log_file_cnt.append(temp)
                              else:
                                   messagebox.showinfo('TAGAddr0 Warning window', 'Tag0 address is not empty, please provide the valid TAG address')
                                   return 3
                              if 1 == self.TAGvar_1.get():
                                  tagadd1 = self.tagAddr1.get()
                                  try:
                                    tagadd1 = int(self.tagAddr1.get(),16)
                                    if ( "" != tagadd1) and ("00000000" != tagadd1):
                                          #print(tagadd1)
                                          #val = self.TAGvar_1.get()
                                          #val_1 = self.Tagflashvar_1.get()
                                          val_1 = self.Tagflashvar_1.get()
                                          if (tagadd1 & 0x3)>0 or tagadd1 > 0xfffffffc:
                                            messagebox.showinfo('TagAddr1 Warning window', 'TagAddr1 Address is multiple of 4 byte , please provide the valid TagAddr1 in 4 byte boundary')
                                            return 3
                                          value = (tagadd1 & 0xfffffffc )| (val_1<<1)
                                          v1 = (value  & (0xFF))
                                          v2 =((value>>8 ) & (0xFF))
                                          v3 =((value>>16 )  & (0xFF))
                                          v4 =((value>>24)  & (0xFF))
                                          #print("tag ",tag)
                                          temp= ((v1<<16) & 0xFF0000)| 0x3E4#0x3FC ;#0x1FC;
                                          #print("temp 0 = ",temp)
                                          temp = struct.pack('I',temp)
                                          efuse_data_table.append(temp)   
                                          temp= ((v2<<16) & 0xFF0000)| 0x3E5#0x3FD #0x1FD;
                                          #print("temp 1 = ",temp)
                                          temp = struct.pack('I',temp)       
                                          efuse_data_table.append(temp)  
                                          temp= ((v3<<16) & 0xFF0000)| 0x3E6#0x3FD #0x1FD;
                                          #print("temp 2 = ",temp)
                                          temp = struct.pack('I',temp)       
                                          efuse_data_table.append(temp)
                                          temp= ((v4<<16) & 0xFF0000)| 0x3E7#0x3FD #0x1FD;
                                          #print("temp 3 = ",temp)
                                          temp = struct.pack('I',temp)       
                                          efuse_data_table.append(temp)
                                          temp = "Tag1 SPI Flash Base Address location "
                                          log_file_cnt.append(temp)
                                    else:
                                       messagebox.showinfo('TAGAddr1 Warning window', 'Tag1 address is not empty, please provide the valid TAG address')
                                       return 3        
                                  except ValueError:
                                      messagebox.showinfo('TAGAddr1 Warning window', 'Tag0 address is not empty, please provide the valid TAG address')
                                      return 3 

                              tag = int(self.flashcomp1.get(),16)
                              value = tag & 0XFFFFFF00
                              if ((tag & 0xFF)):
                                    messagebox.showinfo('Flash comp1  Warning window', 'Flash comp1 Base Address value is not 256 Byte boundary , please provide the valid value')
                                    return 3  
                              if (tag > 0XFFFFFFFF ):
                                    messagebox.showinfo('Flash comp1  Warning window', 'Flash comp1 Base Address value is not 256 Byte boundary or greater than 4 bytes, please provide the valid value')
                                    return 3  
                              #value = (value >> 8)
                              v1 = (value  & (0xFF))
                              v2 =((value>>8 ) & (0xFF))
                              v3 =((value>>16 )  & (0xFF))
                              v4 =((value>>24)  & (0xFF))
                              temp= ((v1<<16) & 0xFF0000)| 0x3e8
                              temp = struct.pack('I',temp)
                              efuse_data_table.append(temp)   
                              temp= ((v2<<16) & 0xFF0000)| 0x3e9
                              temp = struct.pack('I',temp)       
                              efuse_data_table.append(temp)  
                              temp= ((v3<<16) & 0xFF0000)| 0x3ea
                              temp = struct.pack('I',temp)       
                              efuse_data_table.append(temp)
                              temp = "Flash  Componenet 1 = "+tagadd
                              log_file_cnt.append(temp)

                          cr_flashcomp1 = int(self.cr_flashcomp1.get(),16)
                          value = cr_flashcomp1 
                          if (cr_flashcomp1 > 0xffffffff):
                            messagebox.showinfo('CR_FLASH TAG  Base Address - Byte 0-3  Warning window', 'CR_FLASH TAG  Base Address - Byte 0-3  value is not provided or greater than 4 byte, please provide the valid value')
                            return 3 
                          value = value & 0xffffffff#<< 4
                          v1 = (value  & (0xFF))
                          v2 =((value>>8 ) & (0xFF))
                          v3 =((value>>16 )  & (0xFF))
                          v4 =((value>>24)  & (0xFF))
                          #print("tag ",tag)
                          temp= ((v1<<16) & 0xFF0000)| 0x3EC
                          #print("temp 0 = ",temp)
                          temp = struct.pack('I',temp)
                          efuse_data_table.append(temp)   
                          temp= ((v2<<16) & 0xFF0000)| 0x3ED 
                          #print("temp 1 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)  
                          temp= ((v3<<16) & 0xFF0000)| 0x3EE
                          #print("temp 2 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          temp= ((v4<<(16)) & 0xFF0000)| 0x3EF
                          #print("temp 3 = ",temp)
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          log_file_cnt.append("CR_FLASH TAG  Base Address - Byte 0-3 value Updated")
                          # # tagadd = self.eckeycount.get()
                          # # if (tagadd ) =="" or tagadd > 32 :
                          # #    messagebox.showinfo('ECDSAKey count Warning window', 'ECDSAKey count is not provided or greater than , please provide the valid value')
                          # #    return 3                   
                          # if False == soteria_flag or True ==soteria_cus_flag:
                          #   if 0 == self.soft_jtag_wire.get():
                          #       temp|=0x004003f2  #0x008001E2 #for B1
                          #       log_file_cnt.append("DEBUG select  : 2 WIRE SWD DEBUG Port ")
                          #   if 1 == self.soft_jtag_wire.get():
                          #       temp|=0x000003f2  #0x008001E2 #for B1
                          #       log_file_cnt.append("DEBUG select  : 4 WIRE JTAG DEBUG Port ")
                          # if temp & 0xFFFF0000:
                          #   temp = struct.pack('I',temp)       
                          #   efuse_data_table.append(temp)    
                          
                          # #temp = 0x000003F1
                          # if False == soteria_flag or True ==soteria_cus_flag:                  
                          #     otp_crc_var = int(self.otp_crc_var.get(),16)
                          #     value = otp_crc_var 
                          #     if (otp_crc_var > 0xffffffff):
                          #       messagebox.showinfo('OTP CRC value  Warning window', 'OTP CRC  value is not provided or greater than 4 byte, please provide the valid value')
                          #       return 3 
                          #     value = value & 0xffffffff#<< 4
                          #     v1 = (value  & (0xFF))
                          #     v2 =((value>>8 ) & (0xFF))
                          #     v3 =((value>>16 )  & (0xFF))
                          #     v4 =((value>>24)  & (0xFF))
                          #     #print("tag ",tag)
                          #     temp= ((v1<<16) & 0xFF0000)| 0x154#0x3FC ;#0x1FC;
                          #     #print("temp 0 = ",temp)
                          #     temp = struct.pack('I',temp)
                          #     efuse_data_table.append(temp)   
                          #     temp= ((v2<<16) & 0xFF0000)| 0x155#0x3FD #0x1FD;
                          #     #print("temp 1 = ",temp)
                          #     temp = struct.pack('I',temp)       
                          #     efuse_data_table.append(temp)  
                          #     temp= ((v3<<16) & 0xFF0000)| 0x156#0x3FD #0x1FD;
                          #     #print("temp 2 = ",temp)
                          #     temp = struct.pack('I',temp)       
                          #     efuse_data_table.append(temp)
                          #     temp= ((v4<<(16)) & 0xFF0000)| 0x157#0x3FD #0x1FD;
                          #     #print("temp 3 = ",temp)
                          #     temp = struct.pack('I',temp)       
                          #     efuse_data_table.append(temp)
                          #     log_file_cnt.append("OTP CRC value Updated")
                          # temp = 0x000003F1
                          # if False == soteria_flag or True ==soteria_cus_flag:                  
                          #   cus_revision_var = int(self.cus_revision_var.get(),16)
                          #   cus_revision_var = cus_revision_var & 0xFF
                          #   temp |= 0x000003F1 | (cus_revision_var << 16)
                          #   log_file_cnt.append("Customer Revision  value is updated, Refer the Datasheets or OTP sheets to be provided ")
                          # if temp & 0xFFFF0000:
                          #   temp = struct.pack('I',temp)       
                          #   efuse_data_table.append(temp)                                        
                          # temp = 0x00000150
                          # if False == soteria_flag or True ==soteria_cus_flag:                  
                          #   ECDSA_key_revocation_byte_0_var = int(self.ECDSA_key_revocation_byte_0_var.get(),16)
                          #   ECDSA_key_revocation_byte_0_var = ECDSA_key_revocation_byte_0_var & 0xFF
                          #   temp |= 0x00000150 | (ECDSA_key_revocation_byte_0_var << 16)
                          #   log_file_cnt.append("ECDSA Key revocation Byte 0 value is updated, Refer the Datasheets or OTP sheets to be provided ")
                          # if temp & 0xFFFF0000:
                          #   temp = struct.pack('I',temp)       
                          #   efuse_data_table.append(temp)                                        
                          # temp = 0x00000162
                          # if False == soteria_flag or True ==soteria_cus_flag:                  
                          #   security_features_var = int(self.security_features_var.get(),16)
                          #   security_features_var = security_features_var & 0xCF
                          #   temp |= 0x00000162 | (security_features_var << 16)
                          #   log_file_cnt.append("Security  Features value is updated, Refer the Datasheets or OTP sheets to be provided ")
                          # if True == soteria_flag:                  
                          #   security_features_var = int(self.security_features_var.get(),16)
                          #   security_features_var = security_features_var & 0xC0
                          #   temp |= 0x00000162 | (security_features_var << 16)
                          #   log_file_cnt.append("Security  Features value is updated, Refer the Datasheets or OTP sheets to be provided ")
                          # if temp & 0xFFFF0000:
                          #   temp = struct.pack('I',temp)       
                          #   efuse_data_table.append(temp)                                        
                          
                          # temp = 0x0000005D
                          # if False == soteria_flag or True ==soteria_cus_flag:                  
                          #   secure_boot_var = int(self.secure_boot_var.get(),16)
                          #   secure_boot_var = secure_boot_var & 0x1F
                          #   temp |= 0x0000005D | (secure_boot_var << 16)
                          #   log_file_cnt.append("Secure Boot value is updated, Refer the Datasheets or OTP sheets to be provided ")
                          # if True == soteria_flag:                  
                          #   security_features_var = int(self.security_features_var.get(),16)
                          #   security_features_var = security_features_var & 0xC0
                          #   temp |= 0x00000162 | (security_features_var << 16)
                          #   log_file_cnt.append("Secure Boot value is updated , Refer the Datasheets or OTP sheets to be provided ")
                          # if temp & 0xFFFF0000:
                          #   temp = struct.pack('I',temp)       
                          #   efuse_data_table.append(temp)                                        
                          # temp = 0x0000005d
                          # if 1 == self.ap1_reset_var.get():
                          #   temp = 0x0002005d
                          #   #temp = struct.pack('I',temp) 
                          #   #efuse_data_table.append(temp)    
                          #   log_file_cnt.append("PP-Low out is set in AP1 Reset Feature")
                          # else:
                          #   log_file_cnt.append("Hardware Default is set in AP1 Reset Feature")
                          # if 1 == self.extrst_var.get():
                          #   temp = temp |0x0004005d
                          #   #temp = struct.pack('I',temp) 
                          #   #efuse_data_table.append(temp)    
                          #   log_file_cnt.append("PP-Low out is set in  EXTRST Feature")
                          # else:
                          #   log_file_cnt.append("Hardware Default is set in  EXTRST Feature")
                          # if 1 == self.ap1_reset_var.get() or 1 == self.extrst_var.get():
                          #   if temp & 0xFFFF0000:
                          #       temp = struct.pack('I',temp) 
                          #       efuse_data_table.append(temp)    
                          # plat_id  =self.plat_id.get()
                          # # if (plat_id ) =="":
                          # #    messagebox.showinfo('Platform ID Warning window', 'Platform ID value is not provided , please provide the valid value')
                          # #    return 3 
                          # if ( "" != plat_id):
                          #     tag = int(self.plat_id.get(),16)
                          #     value = tag 
                          #     if (tag > 0xFFFF):
                          #       messagebox.showinfo('Platform ID Warning window', 'Platform ID value is not provided or greater than 2 byte, please provide the valid value')
                          #       return 3 
                          #     v1 = (value  & (0xFF))
                          #     v2 =((value>>8 ) & (0xFF))
                          #     temp= ((v1<<16) & 0xFF0000)| 0x160#0x3FC ;#0x1FC;
                          #     temp = struct.pack('I',temp)
                          #     efuse_data_table.append(temp)  
                          #     temp= ((v2<<16) & 0xFF0000)| 0x161#0x3FC ;#0x1FC;
                          #     temp = struct.pack('I',temp)
                          #     efuse_data_table.append(temp)  
                          #     log_file_cnt.append("Platform ID Updated")
                          # if False == soteria_flag:
                          #     tagadd = self.customerrev.get()
                          #     # if (tagadd ) =="":
                          #     #    messagebox.showinfo('Customer Revision Warning window', 'Customer Revision value is not provided , please provide the valid value')
                          #     #    return 3 
                          #     if ( "" != tagadd):
                          #         tag = int(self.customerrev.get(),16)
                          #         value = tag 
                          #         if (tag > 0xFF):
                          #           messagebox.showinfo('Customer Revision Warning window', 'Customer Revision value is not provided , please provide the valid value')
                          #           return 3 
                          #         v1 = (value  & (0xFF))
                          #         temp= ((v1<<16) & 0xFF0000)| 0x3f1#0x3FC ;#0x1FC;
                          #         #print("temp 0 = ",temp)
                          #         temp = struct.pack('I',temp)
                          #         efuse_data_table.append(temp)  
                          #         log_file_cnt.append("Customer Revision Updated")
                          # tagadd = self.flashcomp1.get()
                          # # if (tagadd ) =="":
                          # #    messagebox.showinfo('Flash Components 1 Warning window', 'Flash Components 1 Address is not provided , please provide the valid address')
                          # #    return 3  
                          # if ( "" != tagadd) and ("00000000" != tagadd):
                          #     tag = int(self.flashcomp1.get(),16)
                          #     value = tag & 0XFFFFFF00
                          #     if ((tag & 0xFF)):
                          #           messagebox.showinfo('Flash comp1  Warning window', 'Flash comp1 Base Address value is not 256 Byte boundary , please provide the valid value')
                          #           return 3  
                          #     if (tag > 0XFFFFFFFF ):
                          #           messagebox.showinfo('Flash comp1  Warning window', 'Flash comp1 Base Address value is not 256 Byte boundary or greater than 4 bytes, please provide the valid value')
                          #           return 3  
                          #     #value = (value >> 8)
                          #     v1 = (value  & (0xFF))
                          #     v2 =((value>>8 ) & (0xFF))
                          #     v3 =((value>>16 )  & (0xFF))
                          #     v4 =((value>>24)  & (0xFF))
                          #     # print(" value 1 %x ",(v1))
                          #     # print(" value 2 %x ",(v2 ))
                          #     # print(" value 3 %x ",(v3 ))
                          #     # print(" value 4 %x ",(v4 ))
                          #     # print("value >>8 ",hex(value  & (0xFF)))
                          #     # print("value <<16 ",hex(value  & (0xFF00)))
                          #     # print("value ",hex(value & (0xFF0000)))
                          #     # print("value ",hex(value & (0xFF000000)))
                          #     #print("value >>24 ",value >>24 )
                          #         #print("tag ",tag)
                          #     temp= ((v1<<16) & 0xFF0000)| 0x3e8#0x3FC ;#0x1FC;
                          #     #print("temp 0 = ",temp)
                          #     temp = struct.pack('I',temp)
                          #     efuse_data_table.append(temp)   
                          #     temp= ((v2<<16) & 0xFF0000)| 0x3e9#0x3FD #0x1FD;
                          #     #print("temp 1 = ",temp)
                          #     temp = struct.pack('I',temp)       
                          #     efuse_data_table.append(temp)  
                          #     temp= ((v3<<16) & 0xFF0000)| 0x3ea#0x3FD #0x1FD;
                          #     #print("temp 2 = ",temp)
                          #     temp = struct.pack('I',temp)       
                          #     efuse_data_table.append(temp)
                          #     temp = "Flash  Componenet 1 = "+tagadd
                          #     #print("temp ",temp)
                          #     log_file_cnt.append(temp)
                          # if 1 == self.AUTHEnvar.get():
                          #     tagadd = self.ecdsaaddress.get()
                          #     if ( "" != tagadd) and ("00000000" != tagadd):
                          #         tag = int(self.ecdsaaddress.get(),16)
                          #         if (tag > 0xFFFFFFFF):
                          #           messagebox.showinfo('ECDSA Key Storage Flash Address 0 Warning window', 'ECDSA Key Storage Flash Address 0 is multiple of 16 byte or not to be greater than 4 byte, please provide the valid ecdsaaddress 0 in 16 byte boundary')
                          #           return 3                        
                          #         value = tag & 0xfffffff0#<< 4
                          #         v1 = (value  & (0xFF))
                          #         v2 =((value>>8 ) & (0xFF))
                          #         v3 =((value>>16 )  & (0xFF))
                          #         v4 =((value>>24)  & (0xFF))
                          #         #print("tag ",tag)
                          #         temp= ((v1<<16) & 0xFF0000)| 0x168#0x3FC ;#0x1FC;
                          #         #print("temp 0 = ",temp)
                          #         temp = struct.pack('I',temp)
                          #         efuse_data_table.append(temp)   
                          #         temp= ((v2<<16) & 0xFF0000)| 0x169#0x3FD #0x1FD;
                          #         #print("temp 1 = ",temp)
                          #         temp = struct.pack('I',temp)       
                          #         efuse_data_table.append(temp)  
                          #         temp= ((v3<<16) & 0xFF0000)| 0x16A#0x3FD #0x1FD;
                          #         #print("temp 2 = ",temp)
                          #         temp = struct.pack('I',temp)       
                          #         efuse_data_table.append(temp)
                          #         temp= ((v4<<(16)) & 0xFF0000)| 0x16B#0x3FD #0x1FD;
                          #         #print("temp 3 = ",temp)
                          #         temp = struct.pack('I',temp)       
                          #         efuse_data_table.append(temp)
                          #         #print("temp ",temp)
                          #         temp = "ECDSA Key Flash Base Address 0 location used = "+tagadd
                          #         #print("temp ",temp)
                          #         log_file_cnt.append(temp)
                          #     tagadd = self.ecdsaaddress_1.get()
                          #     if ( "" != tagadd) and ("00000000" != tagadd):
                          #         tag = int(self.ecdsaaddress_1.get(),16)
                          #         if (tag > 0xFFFFFFFF):
                          #           messagebox.showinfo('ECDSA Key Storage Flash Address 1 Warning window', 'ECDSA Key Storage Flash Address 1 is multiple of 16 byte or not to be greater than 4 byte, please provide the valid ecdsaaddress 1 in 16 byte boundary')
                          #           return 3                        
                          #         value = tag & 0xfffffff0#<< 4
                          #         v1 = (value  & (0xFF))
                          #         v2 =((value>>8 ) & (0xFF))
                          #         v3 =((value>>16 )  & (0xFF))
                          #         v4 =((value>>24)  & (0xFF))
                          #         #print("tag ",tag)
                          #         temp= ((v1<<16) & 0xFF0000)| 0x16C#0x3FC ;#0x1FC;
                          #         #print("temp 0 = ",temp)
                          #         temp = struct.pack('I',temp)
                          #         efuse_data_table.append(temp)   
                          #         temp= ((v2<<16) & 0xFF0000)| 0x16D#0x3FD #0x1FD;
                          #         #print("temp 1 = ",temp)
                          #         temp = struct.pack('I',temp)       
                          #         efuse_data_table.append(temp)  
                          #         temp= ((v3<<16) & 0xFF0000)| 0x16E#0x3FD #0x1FD;
                          #         #print("temp 2 = ",temp)
                          #         temp = struct.pack('I',temp)       
                          #         efuse_data_table.append(temp)
                          #         temp= ((v4<<(16)) & 0xFF0000)| 0x16F#0x3FD #0x1FD;
                          #         #print("temp 3 = ",temp)
                          #         temp = struct.pack('I',temp)       
                          #         efuse_data_table.append(temp)
                          #         #print("temp ",temp)
                          #         temp = "ECDSA Key Flash Base Address 1 location used = "+tagadd
                          #         #print("temp ",temp)
                          #         log_file_cnt.append(temp)
                          # if True: 
                          #     if (1 == self.otp_write_lock_var_0.get()):
                          #       if "" != self.otp_write_lock_byte_var_0.get():
                          #           try:
                          #               value = int(self.otp_write_lock_byte_var_0.get(),16)     
                          #               if (value > 0xFFFFFFFF):
                          #                 messagebox.showinfo('OTP_WRITE LOCK Warning window', 'OTP Write value is not provided , please provide the valid value')
                          #                 return 3 
                          #               else:
                          #                 v1 = (((value >>24)   & (0xFF))& (0xFC))
                          #                 v2 =((value>>16 ) & (0xFF))
                          #                 v3 =((value>>8 )  & (0xFF))
                          #                 v4 =((value)  & (0xFF)) 
                          #                 #print("tag ",tag)
                          #                 if v4 > 1:
                          #                   log_name = "OTP Write lock Byte 0 : Bits that are set to 1 in this byte will write-lock the associated OTP region [7:0]" 
                          #                   log_file_cnt.append(log_name)
                          #                   temp= ((v4<<16) & 0xFF0000)| 0x3F4#0x3FC ;#0x1FC;
                          #                   temp = struct.pack('I',temp)   
                          #                   efuse_data_table.append(temp)      
                          #                 if v3 > 1:
                          #                   log_name = "OTP Write lock Byte 1 :Bits that are set to 1 in this byte will write-lock the associated OTP region [15:8]" 
                          #                   log_file_cnt.append(log_name)
                          #                   temp= ((v3<<16) & 0xFF0000)| 0x3F5#0x3FD #0x1FD;
                          #                   temp = struct.pack('I',temp)   
                          #                   efuse_data_table.append(temp)      
                          #                 if v2 > 1:
                          #                   log_name = "OTP Write lock Byte 2 :Bits that are set to 1 in this byte will write-lock the associated OTP region [23:16]" 
                          #                   log_file_cnt.append(log_name)
                          #                   temp= ((v2<<16) & 0xFF0000)| 0x3F6#0x3FD #0x1FD;
                          #                   temp = struct.pack('I',temp)    
                          #                   efuse_data_table.append(temp)   
                          #                 if v1 > 1:
                          #                   log_name = "OTP Write lock Byte 3 :Bits that are set to 1 in this byte will write-lock the associated OTP region [31:26]" 
                          #                   log_file_cnt.append(log_name)
                          #                   temp= ((v1<<16) & 0xFF0000)| 0x3F7#0x3FD #0x1FD;
                          #                   temp = struct.pack('I',temp)     
                          #                   efuse_data_table.append(temp)     
                          #                 # temp= ((v1<<16) & 0xFF0000)| 0x3F4#0x3FC ;#0x1FC;
                          #                 # #print("temp 0 = ",temp)
                          #                 # temp = struct.pack('I',temp)
                          #                 # efuse_data_table.append(temp)   
                          #                 # temp= ((v2<<16) & 0xFF0000)| 0x3F5#0x3FD #0x1FD;
                          #                 # #print("temp 1 = ",temp)
                          #                 # temp = struct.pack('I',temp)       
                          #                 # efuse_data_table.append(temp)  
                          #                 # temp= ((v3<<16) & 0xFF0000)| 0x3F6#0x3FD #0x1FD;
                          #                 # #print("temp 2 = ",temp)
                          #                 # temp = struct.pack('I',temp)       
                          #                 # efuse_data_table.append(temp)
                          #                 # temp= ((v4<<16) & 0xFF0000)| 0x3F7#0x3FD #0x1FD;
                          #                 # #print("temp 3 = ",temp)
                          #                 # temp = struct.pack('I',temp)       
                          #                 # efuse_data_table.append(temp)   
                          #           except:
                          #               messagebox.showinfo('OTP_WRITE LOCK Warning window', 'OTP Write value is not provided , please provide the valid value within the 4 byte in hex')
                          #               return 3 
                          #       else:
                          #           messagebox.showinfo('OTP_WRITE LOCK Warning window', 'OTP Write value is not provided , please provide the valid value within the 4 byte in hex')
                          #           return 3
                          # if True:    
                          #     if (1 == self.otp_read_lock_var_0.get()):
                          #       if "" != self.otp_read_lock_byte_var_0.get():
                          #           try:
                          #               value = int(self.otp_read_lock_byte_var_0.get(),16)     
                          #               if (value > 0xFFFFFFFF):
                          #                 messagebox.showinfo('OTP_READ LOCK Warning window', 'OTP READ value is not provided , please provide the valid value within the 4 byte in hex')
                          #                 return 3 
                          #               else:
                          #                 #v1 = (((value>>24)  & (0xFF))& (0xFC))
                          #                 #v2 =((value>>16 ) & (0xFF))
                          #                 #v3 =((value>>8 )  & (0xFF))
                          #                 v4 =((value)  & (0x3)) 
                          #                 if v4 > 1:
                          #                   log_name = "OTP Read lock Byte 0 :Bits that are set to 1 in this byte will read-lock the associated OTP region [7:0]" 
                          #                   log_file_cnt.append(log_name)
                          #                   temp= ((v4<<16) & 0xFF0000)| 0x3F8#0x3FC ;#0x1FC;
                          #                   temp = struct.pack('I',temp)
                          #                   efuse_data_table.append(temp)   
                          #                 # if v3 > 1:
                          #                 #   log_name = "OTP Read lock Byte 1 :Bits that are set to 1 in this byte will read-lock the associated OTP region [15:8]" 
                          #                 #   log_file_cnt.append(log_name)
                          #                 #   temp= ((v3<<16) & 0xFF0000)| 0x3F9#0x3FD #0x1FD;
                          #                 #   temp = struct.pack('I',temp)   
                          #                 #   efuse_data_table.append(temp)      
                          #                 # if v2 > 1:
                          #                 #   log_name = "OTP Read lock Byte 2 :Bits that are set to 1 in this byte will read-lock the associated OTP region [23:16]" 
                          #                 #   log_file_cnt.append(log_name)
                          #                 #   temp= ((v2<<16) & 0xFF0000)| 0x3FA#0x3FD #0x1FD;
                          #                 #   temp = struct.pack('I',temp)    
                          #                 #   efuse_data_table.append(temp)   
                          #                 # if v1 > 1:
                          #                 #   log_name = "OTP Read lock Byte 3 :Bits that are set to 1 in this byte will read-lock the associated OTP region [31:26]" 
                          #                 #   log_file_cnt.append(log_name)
                          #                 #   temp= ((v1<<16) & 0xFF0000)| 0x3FB#0x3FD #0x1FD;
                          #                 #   temp = struct.pack('I',temp)   
                          #                 #   efuse_data_table.append(temp)       
                          #                 #print("tag ",tag)
                          #                 # temp= ((v1<<16) & 0xFF0000)| 0x3F8#0x3FC ;#0x1FC;
                          #                 # #print("temp 0 = ",temp)
                          #                 # temp = struct.pack('I',temp)
                          #                 # efuse_data_table.append(temp)   
                          #                 # temp= ((v2<<16) & 0xFF0000)| 0x3F9#0x3FD #0x1FD;
                          #                 # #print("temp 1 = ",temp)
                          #                 # temp = struct.pack('I',temp)       
                          #                 # efuse_data_table.append(temp)  
                          #                 # temp= ((v3<<16) & 0xFF0000)| 0x3FA#0x3FD #0x1FD;
                          #                 # #print("temp 2 = ",temp)
                          #                 # temp = struct.pack('I',temp)       
                          #                 # efuse_data_table.append(temp)
                          #                 # temp= ((v4<<16) & 0xFF0000)| 0x3FB#0x3FD #0x1FD;
                          #                 # #print("temp 3 = ",temp)
                          #                 # temp = struct.pack('I',temp)       
                          #                 # efuse_data_table.append(temp)   
                          #           except:
                          #               messagebox.showinfo('OTP_Read LOCK Warning window', 'OTP Read value is not provided , please provide the valid value within the 4 byte in hex')
                          #               return 3  
                          #       else:
                          #          messagebox.showinfo('OTP_READ LOCK Warning window', 'OTP Write value is not provided , please provide the valid value within the 4 byte in hex')
                          #          return 3     
                          # if 1 == self.TAGvar.get():
                          #     tagadd = self.tagAddr.get()
                          #     try:
                          #       tagaddr =int(self.tagAddr.get(),16)
                          #     except ValueError:
                          #          messagebox.showinfo('TAGAddr0 Warning window', 'Tag0 address is not empty, please provide the valid TAG address')
                          #          return 3                        
                          #     #tagadd1 = self.tagAddr1.get()
                          #     # if 1 == self.TAGvar.get():
                          #     #   tagadd1 = self.tagAddr.get()
                          #     #   tagadd1 = int(tagadd1,16)
                          #     #   tagadd1 = tagadd1 +4
                          #     if ( "" != tagadd) and ("00000000" != tagadd):
                          #         tag = int(self.tagAddr.get(),16)
                          #         val = self.TAGvar_1.get()
                          #         val_1 = self.Tagflashvar_0.get()
                          #         if (tag & 0x3)>0 or tag > 0xfffffffc:
                          #           messagebox.showinfo('TagAddr0 Warning window', 'TagAddr0 Address is multiple of 4 byte , please provide the valid TagAddr0 in 4 byte boundary')
                          #           return 3
                          #         value = (tag & 0xfffffffc )| ((val)|(val_1<<1))
                          #         #value = (tag << 2 )| ((val)|(val_1<<1))
                          #         v1 = (value  & (0xFF))
                          #         v2 =((value>>8 ) & (0xFF))
                          #         v3 =((value>>16 )  & (0xFF))
                          #         v4 =((value>>24)  & (0xFF))
                          #         #print("tag ",tag)
                          #         temp= ((v1<<16) & 0xFF0000)| 0x3E0#0x3FC ;#0x1FC;
                          #         #print("temp 0 = ",temp)
                          #         temp = struct.pack('I',temp)
                          #         efuse_data_table.append(temp)   
                          #         temp= ((v2<<16) & 0xFF0000)| 0x3E1#0x3FD #0x1FD;
                          #         #print("temp 1 = ",temp)
                          #         temp = struct.pack('I',temp)       
                          #         efuse_data_table.append(temp)  
                          #         temp= ((v3<<16) & 0xFF0000)| 0x3E2#0x3FD #0x1FD;
                          #         #print("temp 2 = ",temp)
                          #         temp = struct.pack('I',temp)       
                          #         efuse_data_table.append(temp)
                          #         temp= (((v4<<16)) & 0xFF0000)| 0x3E3#0x3FD #0x1FD;
                          #         #print("temp 3 = ",temp)
                          #         temp = struct.pack('I',temp)       
                          #         efuse_data_table.append(temp)
                          #         temp = "Tag0 SPI Flash Base Address location "+tagadd
                          #         log_file_cnt.append(temp)
                          #     else:
                          #          messagebox.showinfo('TAGAddr0 Warning window', 'Tag0 address is not empty, please provide the valid TAG address')
                          #          return 3
                          #     if 1 == self.TAGvar_1.get():
                          #         tagadd1 = self.tagAddr1.get()
                          #         try:
                          #           tagadd1 = int(self.tagAddr1.get(),16)
                          #           if ( "" != tagadd1) and ("00000000" != tagadd1):
                          #                 #print(tagadd1)
                          #                 #val = self.TAGvar_1.get()
                          #                 #val_1 = self.Tagflashvar_1.get()
                          #                 val_1 = self.Tagflashvar_1.get()
                          #                 if (tagadd1 & 0x3)>0 or tagadd1 > 0xfffffffc:
                          #                   messagebox.showinfo('TagAddr1 Warning window', 'TagAddr1 Address is multiple of 4 byte , please provide the valid TagAddr1 in 4 byte boundary')
                          #                   return 3
                          #                 value = (tagadd1 & 0xfffffffc )| (val_1<<1)
                          #                 v1 = (value  & (0xFF))
                          #                 v2 =((value>>8 ) & (0xFF))
                          #                 v3 =((value>>16 )  & (0xFF))
                          #                 v4 =((value>>24)  & (0xFF))
                          #                 #print("tag ",tag)
                          #                 temp= ((v1<<16) & 0xFF0000)| 0x3E4#0x3FC ;#0x1FC;
                          #                 #print("temp 0 = ",temp)
                          #                 temp = struct.pack('I',temp)
                          #                 efuse_data_table.append(temp)   
                          #                 temp= ((v2<<16) & 0xFF0000)| 0x3E5#0x3FD #0x1FD;
                          #                 #print("temp 1 = ",temp)
                          #                 temp = struct.pack('I',temp)       
                          #                 efuse_data_table.append(temp)  
                          #                 temp= ((v3<<16) & 0xFF0000)| 0x3E6#0x3FD #0x1FD;
                          #                 #print("temp 2 = ",temp)
                          #                 temp = struct.pack('I',temp)       
                          #                 efuse_data_table.append(temp)
                          #                 temp= ((v4<<16) & 0xFF0000)| 0x3E7#0x3FD #0x1FD;
                          #                 #print("temp 3 = ",temp)
                          #                 temp = struct.pack('I',temp)       
                          #                 efuse_data_table.append(temp)
                          #                 temp = "Tag1 SPI Flash Base Address location "
                          #                 log_file_cnt.append(temp)
                          #           else:
                          #              messagebox.showinfo('TAGAddr1 Warning window', 'Tag1 address is not empty, please provide the valid TAG address')
                          #              return 3        
                          #     # else:
                          #     #      messagebox.showinfo('TAGAddr1 Warning window', 'Tag1 address is not empty, please provide the valid TAG address')
                          #     #      return 3
                          #         except ValueError:
                          #             messagebox.showinfo('TAGAddr1 Warning window', 'Tag0 address is not empty, please provide the valid TAG address')
                          #             return 3 

                          once = True
                          if [] == custom_data:
                              log_file_cnt.append("No Custom User Data")
                              log_file_cnt.append("\tIDX	Data")
                              val = 0x0
                              val = "\t"+hex((val >> 24 | ((val >> 8) & 0x100)) & 0x1FF).upper()+"\t"+hex((val >> 8 ) & 0xFF).upper()
                              log_file_cnt.append(val)
                          else:
                              for item in custom_data:
                                  if once == True:
                                      log_file_cnt.append("Custom User data details")
                                      log_file_cnt.append(cust_content)
                                      once = False
                                  val = ((int(binascii.hexlify(item), 16)) & 0xFFFFFFFF )#0xFF0100FF)
                                  dat = ((val >> 8 ) & 0xFF)
                                  idx = ((val >> 24 | ((val >> 8) & 0x100)) & 0xFFFF)#0x1FF)
                                  val = "\t"+hex((val >> 24 | ((val >> 8) & 0x100)) & 0xFFFF).upper()+"\t"+hex((val >> 8 ) & 0xFF).upper()
                                  if dat:
                                      if ((1 == self.ECDHENCvar.get()) and (keyfileflags & ENCT_ENBALE_BIT)): 
                                          efuse_data_table.append(item)        
                                      else:
                                          efuse_data_table.append(item)
                          
                          temp=0x00FFDEAD
                          temp = struct.pack('I',temp)       
                          efuse_data_table.append(temp)
                          fldloc = self.outdir.get()
                          fldloc = "/".join(fldloc.split('\\')) 
                          dirpath1=fldloc+"/efuse_log.txt"
                          with open(dirpath1,"wt+") as in_file:
                              for lines in log_file_cnt:
                                  lines = str(lines)
                                  in_file.write(" - "+lines+"\n")
                          pathfilename = dirpath1
                          in_file.close()
                          srec_file_name = "tools/srec_cat.exe"
                          srec_file_name_path = os.path.normpath(srec_file_name)
                          if not os.path.exists(srec_file_name_path):
                                messagebox.showinfo('Srec_cat.exe file Warning window', 'Under tools folder "srec_cat.exe" file is not available, please copy srec_cat.exe to "tools" folder')
                                return 3

                          if 0 == warningMSG:
                              rtn = warning_windox().show()
                          else:
                              rtn = True
                           
                          if True == rtn:
                              dirpath=fldloc+"/out_binaries/efuse.bin" 
                              with open(dirpath,"wb+") as in_file:
                                  for lines in efuse_data_table:
                                      lines=(lines[:-1])
                                      in_file.write(lines) 
                              in_file.close()    
                              if 1 == headerflag:
                                 self.generateheader()
                              if 1 == sqtpflag:
                                 self.generatesqtpfile()
                              if 1 == MultipleDev:
                                  self.generate_sqtp_W_multiple_custom_data()    
                              self.otp_dump_function()
                              efuse_data_table = []
                              binpath=fldloc+"/out_binaries"
                              file_name = '*.hex'
                              with os.scandir(binpath) as entries:
                                for entry in entries:
                                    if entry.is_file():
                                        extension = entry.name
                                        extension = extension.split(".")[-1]
                                        if extension == "hex":
                                            cmd = binpath+"/otp_efuse*"
                                            cmd = "\\".join(cmd.split('/')) 
                                            cmd="del /q /f "+cmd
                                            op = os.system(cmd)
                              
                              with open ("efuse/original_binary/otp_prog_original.bin","rb") as in_file:
                                  in_file.seek(0)
                                  # read file as bytes
                                  file_data = in_file.read()
                                  with open (fldloc+"/out_binaries/otp_efuse.bin","wb+") as out_file:
                                      efuse_file = open(dirpath,"rb")
                                      efuse_file.seek(0)
                                      efuse_data =efuse_file.read()
                                      bin_file_size = os.path.getsize(dirpath)
                                      endoffset = 0xA00+bin_file_size
                                      datain = file_data[:0xA00]+efuse_data+file_data[endoffset:]
                                      out_file.write(datain)
                              in_file.close() 
                              out_file.close() 
                              efuse_file.close()
                              
                                 
                              binpath=fldloc+"/out_binaries"
                              cmd = "tools/srec_cat.exe "+binpath+"/otp_efuse.bin -binary -offset 0xE0000 -o "+binpath+"/otp_efuse1.hex -intel"
                              cmd = "\\".join(cmd.split('/')) 
                              op = os.system(cmd) 
                              in_file = open (binpath+"/otp_efuse1.hex","rt")
                              out_file = open (binpath+"/otp_efuse.hex","wt")
                              org_file = open ("efuse/original_binary/otp_prog_original.hex","rt")
                              lineno = 0
                              ListOfMismatch = []
                              for org, new in zip(org_file, in_file):
                                  if new != org:
                                      ListOfMismatch.append(lineno)
                                      if 0 == lineno or 146 == lineno:#starting or End terminator
                                          out_file.write(org)
                                      else:
                                          out_file.write(new)
                                  else:
                                      out_file.write(org)
                                  lineno = lineno + 1
                              nooflines = 0
                              org_file.seek(0)

                              for lines in org_file:
                                  nooflines = nooflines + 1
                              
                              if(len(ListOfMismatch) > 0):
                                if ListOfMismatch[-1] != nooflines:
                                    out_file.write(lines)
                              
                              org_file.close()    
                              in_file.close() 
                              out_file.close()

                              binpath=fldloc+"/out_binaries"

                              with open ("efuse/original_binary/otp_prog_original.bin","rb") as in_file:
                                table = in_file.read()
                                offset   =  struct.unpack("<L", table[0x4:0x5]+table[0x5:0x6]+table[0x6:0x7]+table[0x7:0x8])[0]
                                in_file.close()

                              cmd = "tools/srec_cat.exe "+binpath+"/otp_efuse.hex -intel -execution-start-address="+str(offset)+" -o "+binpath+"/otp_efuse_load.hex"+" -intel"
                              cmd = "\\".join(cmd.split('/')) 
                              op = os.system(cmd) 
                              
                              cmd = binpath+"/otp_efuse.hex"
                              cmd = "\\".join(cmd.split('/')) 
                              cmd="del /q /f "+cmd
                              op = os.system(cmd) 

                              cmd = binpath+"/otp_efuse_load.hex"
                              cmd = "\\".join(cmd.split('/')) 
                              cmd1 = binpath+"/otp_efuse.hex"
                              cmd1 = "\\".join(cmd1.split('/')) 
                              #cmd="rename "+cmd+ " "+cmd1
                              #print("cmd cmd1 ",cmd,cmd1)
                              #op = os.system(cmd) 
                              op = os.rename(cmd,cmd1)

                              cmd = binpath+"/otp_efuse1.hex"
                              cmd = "\\".join(cmd.split('/')) 
                              cmd="del /q /f "+cmd
                              op = os.system(cmd) 

                              cmd = dirpath
                              cmd = "\\".join(cmd.split('/')) 
                              cmd="del /f /q "+cmd        
                              op = os.system(cmd) 
                              buffer = open(binpath+"/otp_efuse.hex","rb")
                              a = bytearray(buffer.read())
                              crc = 0xffffffff
                              for x in a:
                                crc ^= x << 24;
                                for k in range(8):
                                    if crc & 0x80000000:
                                        crc = (crc << 1) ^ 0x04C11DB7 
                                    else:
                                        crc = crc << 1
                              crc = ~crc
                              crc &= 0xffffffff
                              crc_value = hex(crc)
                              hex_file_crc32 = crc_value
                              buffer.close() 
                            #print("zlib %X" ,crc_value)
                              cmd = binpath+"/otp_efuse.hex"
                              cmd = "\\".join(cmd.split('/'))
                              cmd1 = binpath+"/otp_efuse"+"_"+crc_value+".hex"
                              cmd1 = "\\".join(cmd1.split('/'))
                              op = os.rename(cmd,cmd1)

                            # prev =0
                            # for eachLine in open(binpath+"/otp_efuse.bin","rb"):
                            #     prev = zlib.crc32(eachLine, prev)
                            #prev =0
                            #for eachLine in open(binpath+"/otp_efuse.hex","rb"):
                            #    prev = zlib.crc32(eachLine, prev)
                              buffer = open(binpath+"/otp_efuse.bin","rb")
                              a = bytearray(buffer.read())
                              crc = 0xffffffff
                              for x in a:
                                crc ^= x << 24;
                                for k in range(8):
                                    if crc & 0x80000000:
                                        crc = (crc << 1) ^ 0x04C11DB7 
                                    else:
                                        crc = crc << 1
                              crc = ~crc
                              crc &= 0xffffffff
                              crc_value = hex(crc)
                            #crc_value = hex(prev & 0xFFFFFFFF)
                              bin_file_crc32 = crc_value 
                              buffer.close()
                            #print("zlib %X" ,crc_value)
                              cmd = binpath+"/otp_efuse.bin"
                              cmd = "\\".join(cmd.split('/'))
                              cmd1 = binpath+"/otp_efuse"+"_"+crc_value+".bin"
                              cmd1 = "\\".join(cmd1.split('/'))
                              op = os.rename(cmd,cmd1)
                              text = "otp_efuse"+"_"+hex_file_crc32+".hex = " +hex_file_crc32+"\n"+ "otp_efuse"+"_"+bin_file_crc32+".bin  = "+bin_file_crc32
                              messagebox.showinfo('Efuse generator CRC32 checksum ', text)                      
                              if(1 == display_done):
                                  custom_data = []
                                  #self.CUSvar.set(0)
                                  #self.custIDX.set("1E0")#("C0")
                                  #self.custDAT.set("00")
                                  self.CustFilekey.set("")
                                  if 1 == self.CUSvar.get():
                                      self.CUSvar.set(0)
                                      self.Hex2Dec.set(1)
                                      self.custIDX.set("240")
                                      self.custDAT.set("00")
                                      self.custIDXbar.config(state="disabled")
                                      self.custDATbar.config(state="disabled")
                                      self.hex.config(state="disabled")
                                      self.dec.config(state="disabled")
                                      self.Ebutton.config(state="disabled")
                                      self.CUSTfilebar.config(state="disabled")
                                      self.bbutton2.config(state="disabled")
                                      self.ViewCusDButton.config(state="disabled")
                                  custdatexd = 0
                                  Done_windox()
                                  otp_write_lock_en =0
                                  cust_enter_var =0
                                  write_lock_flag_15 = 0
                                  write_lock_flag_16 = 0
                                  write_lock_flag_17 = 0
                                  write_lock_flag_18 = 0
                                  write_lock_flag_19 = 0
                                  write_lock_flag_20 = 0
                                  write_lock_flag_21 = 0
                                  write_lock_flag_22 = 0
                                  write_lock_flag_23 = 0
                                  write_lock_flag_24 = 0
                                  write_lock_flag_25 = 0
                                  write_lock_flag_26 = 0
                                  write_lock_flag_27 = 0
                                  write_lock_flag_28 = 0
                                  write_lock_flag_29 = 0
                                  write_lock_flag_30 = 0

                                  otp_lock_15 = 0
                                  otp_lock_16 = 0
                                  otp_lock_17 = 0
                                  otp_lock_18 = 0
                                  otp_lock_19 = 0
                                  otp_lock_20 = 0
                                  otp_lock_21 = 0
                                  otp_lock_22 = 0
                                  otp_lock_23 = 0
                                  otp_lock_24 = 0
                                  otp_lock_25 = 0 
                                  otp_lock_26 = 0
                                  otp_lock_27 = 0
                                  otp_lock_28 = 0
                                  otp_lock_29 = 0
                                  otp_lock_30 = 0
                                  log_file_cnt = 0
                                  generate_efuse_data = 0
                                  #warning_main_wind_flag = 1
                          else:
                              log_file_cnt =0
                              self.ATEvar.set(1)
                              self.Hex2Dec.set(1)
                              self.JTAGvar.set(0)
                              self.AUTHvar.set(0)
                             # self.JTAGvar1.set(0)
                              self.ENCvar.set(0)
                              self.TAGvar.set(0)
                              self.tagAddr.set("0000")
                              self.CUSvar.set(0)
                              #self.ecdsabar.config(state="disabled")
                              #self.ecdsapassbar.config(state="disabled")  
                              self.ecdhbar.config(state="disabled")
                              self.ecdhpassbar.config(state="disabled")

                              self.CUSvar.set(0)
                              self.custIDX.set("240")#("C0")
                              self.custDAT.set("00")


                              self.custIDXbar.config(state="disabled")
                              self.custDATbar.config(state="disabled")
                              self.hex.config(state="disabled")
                              self.dec.config(state="disabled")
                              self.Ebutton.config(state="disabled")
                              self.CUSTfilebar.config(state="disabled")
                              self.bbutton2.config(state="disabled")
                              self.ViewCusDButton.config(state="disabled")
                              custdatexd = 0
                              self.ECDHENCvar.set(0)
                              self.ECDHENC_CB.config(state="disabled")
                              if True ==  COMP_flag:
                                  self.COMPvar.set(0)

                              if(True == DSW_flag ):
                                  self.DESWvar.set(0)
                                  self.WDTDelay.set(0)
                                  self.WDTENvar.set(0)

                              if(True == MOB_flag):
                                  self.DSWvar.set(0)
                                  self.WDTDelay.set(0)
                                  self.WDTENvar.set(0)
                                  self.DSWgpio.set("")
                                  self.DSWlbl3.config(state="disabled")
                                  dswgpiosel = 0 
                              otp_write_lock_en =0
                              write_lock_flag_15 = 0
                              write_lock_flag_16 = 0
                              write_lock_flag_17 = 0
                              write_lock_flag_18 = 0
                              write_lock_flag_19 = 0
                              write_lock_flag_20 = 0
                              write_lock_flag_21 = 0
                              write_lock_flag_22 = 0
                              write_lock_flag_23 = 0
                              write_lock_flag_24 = 0
                              write_lock_flag_25 = 0
                              write_lock_flag_26 = 0
                              write_lock_flag_27 = 0
                              write_lock_flag_28 = 0
                              write_lock_flag_29 = 0
                              write_lock_flag_30 = 0

                              otp_lock_15 = 0
                              otp_lock_16 = 0
                              otp_lock_17 = 0
                              otp_lock_18 = 0
                              otp_lock_19 = 0
                              otp_lock_20 = 0
                              otp_lock_21 = 0
                              otp_lock_22 = 0
                              otp_lock_23 = 0
                              otp_lock_24 = 0
                              otp_lock_25 = 0 
                              otp_lock_26 = 0
                              otp_lock_27 = 0
                              otp_lock_28 = 0
                              otp_lock_29 = 0
                              otp_lock_30 = 0

                              self.AEMvar.set(0)
                              #self.ECDSALCKvar.set(0)
                              #self.ECDSALCK_CB.config(state ="disabled")
                              self.ECDHENC_CB.config(state="disabled")
                              '''
                              self.ECDHLCK_CB.config(state="disabled")
                              '''
                              #self.ECDHPrivLCK_CB.config(state="disabled")
                              #self.ECDHPubLCK_CB.config(state="disabled")
                              #self.ECDHENCvar.set(0)
                              #self.ECDHPrivLCKvar.set(0)
                              #self.ECDHPubLCKvar.set(0)
                              self.tagbar.config(state="disabled")
                              cmd = fldloc
                              cmd = "\\".join(cmd.split('/')) 
                              cmd="del /f /q "+cmd+"\keys\*.* "        
                              op = os.system(cmd)
                              generate_efuse_data =0
                              #warning_main_wind_flag =1
                     except:
                            generate_efuse_data = 1
                     
            def generatesqtpfile(self):    
                global MaskVal
                global PatternVal
                global TypeVal    
                fldloc = self.outdir.get()
                fldloc = "/".join(fldloc.split('\\')) 
                dirpath=fldloc+"/out_binaries/efuse.bin" 
                sqtppath=fldloc+"/out_binaries/sqptfile.txt" 
                efuse_file = open(dirpath,"rb")
                efuse_file.seek(0)
                efuse_data =efuse_file.read()
                with open(sqtppath,"wt+") as in_file:
                    in_file.write("<header>\n")
                    in_file.write("mask,"+MaskVal+"\n")
                    in_file.write("pattern,"+PatternVal+"\n")
                    in_file.write("type,"+TypeVal+"\n")
                    in_file.write("</header>\n")
                    in_file.write("<data>\n")
                    cnt = idx = dat = incnt = outcnt = 0
                    buffer = []
                    for indx in range(0, 1024):
                        dat = 0
                        dat = hex(dat).zfill(2).split("x")[1].upper()
                        buffer.append(dat)
                        
                    for items in efuse_data:
                        if 0 == cnt:
                            idx = items
                        if 1 == cnt:    
                            idx = idx + (items << 8)
                        if 2 == cnt:  
                            dat = items
                            dat = hex(dat).zfill(2).split("x")[1].upper()
                        #if 3 == cnt:  
                            if 57005 == idx:#DEAD
                                break
                            else:
                                if idx >= 0 and idx <= 1024:#512:
                                    del buffer[idx]
                                    buffer.insert(idx,dat ) 
                            cnt = 0
                        else:
                            cnt = cnt + 1
                    dat = ""
                    for items in buffer:
                        dat = dat + str(items).zfill(2)
                        if 28 == outcnt:
                            if (15 == incnt):
                                dat =dat+"\n"
                                in_file.write(dat)
                                dat = ""
                                incnt = 0
                                outcnt = outcnt +1
                            else:
                                incnt = incnt +1

                        else:
                            if (35 == incnt):
                                dat =dat+"\\"+"\n"
                                in_file.write(dat)
                                dat = ""
                                incnt = 0
                                outcnt = outcnt +1
                            else:
                                incnt = incnt +1
                                    
                        if 30 == outcnt:
                            in_file.write(dat)
                            break
               
                    in_file.write("</data>\n")
                in_file.close    
                efuse_file.close
                
            def generateheader(self):
                fldloc = self.outdir.get()
                fldloc = "/".join(fldloc.split('\\')) 
                dirpath=fldloc+"/out_binaries/efuse.bin" 
                headpath=fldloc+"/out_binaries/efuse_data.h" 
                efuse_file = open(dirpath,"rb")
                efuse_file.seek(0)
                efuse_data =efuse_file.read()
                
                with open(headpath,"wt+") as in_file:
                
                    cnt = idx = dat = incnt = outcnt = 0
                    in_file.write("/***************************************************************************** \n")
                    in_file.write("* Copyright 2019 Microchip Technology Inc. and its subsidiaries.               \n")
                    in_file.write("* You may use this software and any derivatives exclusively with               \n")
                    in_file.write("* Microchip products.                                                          \n")
                    in_file.write("* THIS SOFTWARE IS SUPPLIED BY MICROCHIP 'AS IS'.                              \n")
                    in_file.write("* NO WARRANTIES, WHETHER EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE,\n")
                    in_file.write("* INCLUDING ANY IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY,       \n")
                    in_file.write("* AND FITNESS FOR A PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP      \n")
                    in_file.write("* PRODUCTS, COMBINATION WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.    \n")
                    in_file.write("* IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,    \n")
                    in_file.write("* INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND        \n")
                    in_file.write("* WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS    \n")
                    in_file.write("* BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.              \n")
                    in_file.write("* TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL     \n")
                    in_file.write("* CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF     \n")
                    in_file.write("* FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.    \n")
                    in_file.write("* MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE          \n")
                    in_file.write("* OF THESE TERMS.                                                              \n")
                    in_file.write("*****************************************************************************/ \n")
                    in_file.write("                                                                               \n")
                    in_file.write("/** @file efuse_data.h                                                         \n")
                    in_file.write(" *EVERGLADES efuse_data                                                        \n")
                    in_file.write(" */                                                                            \n")
                    in_file.write("/** @defgroup EVERGLADES efuse_data                                            \n")
                    in_file.write(" */                                                                            \n")
                    in_file.write("#ifndef _EFUSE_DATA_H                                                          \n")
                    in_file.write("#define _EFUSE_DATA_H                                                          \n")
                    in_file.write("typedef unsigned          char uint8_t;                                        \n")
                    in_file.write("typedef unsigned short    int uint16_t;                                       \n")
                    in_file.write("                                                                               \n")
                    in_file.write("typedef struct efuse_table_define {                                            \n")
                    in_file.write("    uint16_t index;                                                            \n")
                    in_file.write("    uint8_t value;                                                             \n")
                    in_file.write("} _EFUSE_TBLE_DFE_;                                                            \n")
                    in_file.write("                                                                               \n")
                    in_file.write("const _EFUSE_TBLE_DFE_ device_efuse_table_ [] = {\n")
                                
                    message = ""
                    in_file.write("    ")
                    for items in efuse_data:
                        if 0 == cnt:
                            idx = items 
                        if 1 == cnt:    
                            idx = idx + (items << 8)
                        if 2 == cnt:  
                            dat = items
                        #if 3 == cnt:  
                            if 57005 == idx:#DEAD
                                message = "{0xDEAD,0xFF}, "
                            else:
                                if idx == 9 or idx == 8:
                                    message = "{"+str(idx)+", "+hex(dat).zfill(2)+"}, "
                                else:    
                                    message = "{"+str(idx).zfill(2)+", "+hex(dat).zfill(2)+"}, "
                            in_file.write(message)
                            incnt = incnt + 1
                            cnt = 0
                            if (8 == incnt):
                                in_file.write("\n    ")
                                message = ""
                                outcnt = outcnt + incnt
                                incnt = 0
                        else:
                            cnt = cnt + 1
                    outcnt = outcnt + incnt       
         
                    message = "{00, 0x00}, "   
                    for idx in range (outcnt, 1024):
                        if (8 == incnt):
                            in_file.write("\n    ")
                            incnt = 0
                        in_file.write(message)
                        incnt = incnt + 1
                    message = "{0xDEAD,0xFF}     //terminator\n"    
                    in_file.write(message)
                    in_file.write("};                                                                             \n")
                    in_file.write("                                                                               \n")
                    in_file.write("#define TOTAL_SIZE sizeof(device_efuse_table_)/sizeof(device_efuse_table_[0]); \n")
                    in_file.write("#endif                                                                         \n")
                    in_file.write("/* end efuse_data.h */                                                         \n")
                    in_file.write("/**   @}                                                                       \n")
                    in_file.write(" */                                                                            \n")
                in_file.close    
                efuse_file.close
                
            def generate_ec384_keys(self, opensslp, PrivKeyFile, PrivKeyPassword,i):
                opensslpath = self.opensslpath.get()
                cmd = opensslpath + " version "
                cmd ='"%s"'%cmd
                ret = os.system(cmd)
                if ret:
                	messagebox.showinfo('Opensll path  Warning window', 'openssl path is missing ')
                	return 1
                #print("generate_ec384_keys")
                cmd = opensslp +' ecparam -name secp384r1 -genkey | '+ opensslp + ' ec -out '+ PrivKeyFile+'.pem -passout pass:'+PrivKeyPassword+' -aes-256-cbc'
                op = os.system(cmd)   
                opstr = PrivKeyFile.split("\\")[-1]
                    
                subjopt = "/C=US/ST=NYC/L=Hauppauge/O=MCHP/OU=CPG-FW/CN=CEC1712"    
                cmd = opensslp +" req -new -key "+PrivKeyFile+".pem -out "+PrivKeyFile+"_csr.pem -passin pass:"+PrivKeyPassword+" -subj "+subjopt
                op = os.system(cmd) 
                if (op):
                    return 1
                cmd = opensslp+" x509 -req -days 3650 -in "+PrivKeyFile+"_csr.pem -signkey "+PrivKeyFile+".pem -out "+PrivKeyFile+"_crt.pem -passin pass:"+PrivKeyPassword
                op = os.system(cmd) 
                if (op):
                    return 2
                # opensslpath = self.opensslpath.get()
                # cmd = opensslpath + " version "
                # cmd ='"%s"'%cmd
                # ret = os.system(cmd)
                # if ret:
                # 	messagebox.showinfo('Opensll path  Warning window', 'openssl path is missing ')
                # 	return 1
                # #print("generate_ec384_keys")
                # if PrivKeyPassword =="":
                # 	cmd = opensslp +' ecparam -name secp384r1 -genkey | '+ opensslp + ' ec -out '+ PrivKeyFile+'.pem' 
                # else:
                # 	cmd = opensslp +' ecparam -name secp384r1 -genkey | '+ opensslp + ' ec -out '+ PrivKeyFile+'.pem -passout pass:'+PrivKeyPassword+' -aes-256-cbc'
                # op = os.system(cmd)   
                # opstr = PrivKeyFile.split("\\")[-1]
                    
                # subjopt = "/C=US/ST=NYC/L=Hauppauge/O=MCHP/OU=CPG-FW/CN=CEC1712"    
                # if PrivKeyPassword =="":
                # 	cmd = opensslp +" req -new -key "+PrivKeyFile+".pem -out "+PrivKeyFile+"_csr.pem"+" -subj "+subjopt   
                # else:
                # 	cmd = opensslp +" req -new -key "+PrivKeyFile+".pem -out "+PrivKeyFile+"_csr.pem -passin pass:"+PrivKeyPassword+" -subj "+subjopt
                # op = os.system(cmd) 
                # if (op):
                #     return 1
                # if PrivKeyPassword =="":
                # 	cmd = opensslp+" x509 -req -days 3650 -in "+PrivKeyFile+"_csr.pem -signkey "+PrivKeyFile+".pem -out "+PrivKeyFile+"_crt.pem"
                # else:
                # 	cmd = opensslp+" x509 -req -days 3650 -in "+PrivKeyFile+"_csr.pem -signkey "+PrivKeyFile+".pem -out "+PrivKeyFile+"_crt.pem -passin pass:"+PrivKeyPassword
                # op = os.system(cmd) 
                # if (op):
                #     return 2

                # privatekey = PrivKeyFile+"_crt.pem"
                # file = "ecdsa_key_file_"+str(i)+".bin"
                # tfile = "full_ecdsa_key_file.bin"
                # print("ecdsakeyname ",file)
                # hashkeyname = "hash_ecdsa_key_file_"+str(i)+".bin"
                # print("hashkeyname ",hashkeyname)
                # self.ecdsa_public_key(privatekey,file,tfile,hashkeyname)
                '''    
                cmd = opensslp+" x509 -in "+PrivKeyFile+"_crt.pem -text -noout > "+PrivKeyFile+"_dump.txt"
                op = os.system(cmd) 

                if (op):
                    return 3
                cmd = opensslp+" ec -in "+PrivKeyFile+".pem -text -passin pass:"+PrivKeyPassword+"  > "+PrivKeyFile+"_pub_pvt_dump.txt"  
                op = os.system(cmd) 
                if (op):
                    return 4
                '''
                #print("generate_ec384_keys end")
                return 0

            def browse_keys(self):
                #print("browse_keys ")
               #print(" ec384keybin ")
                global browse_flag
                ret =0
                fldloc = self.outdir.get()
                #print("ec384keybin browse_flag ",browse_flag)
                #if browse_flag ==1:
                #   self.browse_keys()
                #   return 0
                fldloc = fldloc+"\\keys"
                full_ecdsa_key = fldloc+"\\"+"full_ecdsa_key_file.bin"
                hash_full_ecdsa_key = fldloc+"\\"+"each_hash_bin.bin"
                hash_of_each_ecdsa_key_file = fldloc+"\\"+"hash_of_hash.bin"
                cfgfile = "ECDSA_Key_info.ini"
                #tfile = "full_ecdsa_key_file.bin"
                tfile_data = open(full_ecdsa_key,"wb+")
                #print("ec384keybin 0")
                tfile_data.seek(0)
                each_hash_bin = open(hash_full_ecdsa_key,"wb+")
                #print("ec384keybin 0")
                each_hash_bin.seek(0)
                #print("ec384keybin 1")
                if (os.path.exists(cfgfile)):
                    config = configparser.ConfigParser()
                    config.read(cfgfile)
                    #print("ec384keygen called 2")
                    #print("Ecdsa file info ")
                    i=0
                    for each_section in config.sections():
                      for (each_key, each_val) in config.items(each_section):
                        if each_key == "ecdsakeyfilename":
                            private_key = each_val
                        if each_key == "ecdsakeyfilenamepass":
                            private_key_pass = each_val
                            #print("private_key_password ",private_key_password)
                      i = i+1
                      #privatekey = fldloc+"\\keys"+"\\"+private_key+"_crt.pem"
                      
                      hashkeyname = "hash_ecdsa_key_"+str(i)+".bin"
                      #print("hashkeyname ",hashkeyname)
                      #print("privatekey ",privatekey)
                      file = "ecdsa_key_"+str(i)+".bin"
                      #print("file ",file)
                      #print(" browse private_key ",private_key)
                      #print(" private_key_pass ",private_key_pass)
                      ret = self.browse_ecdsa_public_key(private_key,private_key_pass,file,tfile_data,hashkeyname,each_hash_bin)
                      if ret > 0:
                        return ret
                tfile_data.close()
                key_count  = self.eckeycount.get()
                #print("key count %d ",key_count)
                each_hash_bin.seek(key_count*48)
                while (key_count < 32 ):
                    for indx in range(0, 48):
                        each_hash_bin.write(bytearray(1))
                    key_count = key_count+1 
                each_hash_bin.close()
                if os.path.exists(hash_full_ecdsa_key):
                   _opensslp = self.opensslpath.get()
                   #print("Hash384 is generated ")
                   #print("_opensslp ",_opensslp)
                   cmd = _opensslp+" dgst -sha384 -binary -out "+hash_of_each_ecdsa_key_file +" "+ hash_full_ecdsa_key
                   os.system(cmd)
                #print(" ec384keybin End")
                return ret 
            def ec384keybin(self):
                #print(" ec384keybin ")
                global browse_flag
                ret =0
                fldloc = self.outdir.get()
                #print("ec384keybin browse_flag ",browse_flag)
                if browse_flag ==1:
                   self.browse_keys()
                   return 0
                fldloc = fldloc+"\\keys"
                full_ecdsa_key = fldloc+"\\"+"full_ecdsa_key_file.bin"
                hash_full_ecdsa_key = fldloc+"\\"+"each_hash_bin.bin"
                hash_of_each_ecdsa_key_file = fldloc+"\\"+"hash_of_hash.bin"
                cfgfile = "ECDSA_Key_info.ini"
                #tfile = "full_ecdsa_key_file.bin"
                tfile_data = open(full_ecdsa_key,"wb+")
                #print("ec384keybin 0")
                tfile_data.seek(0)
                each_hash_bin = open(hash_full_ecdsa_key,"wb+")
                #print("ec384keybin 0")
                each_hash_bin.seek(0)
                #print("ec384keybin 1")
                if (os.path.exists(cfgfile)):
                    config = configparser.ConfigParser()
                    config.read(cfgfile)
                    #print("ec384keygen called 2")
                    #print("Ecdsa file info ")
                    i=0
                    for each_section in config.sections():
                      for (each_key, each_val) in config.items(each_section):
                        if each_key == "ecdsakeyfilename":
                            private_key = each_val
                        if each_key == "ecdsakeyfilenamepass":
                            private_key_pass = each_val
                            #print("private_key_password ",private_key_password)
                      i = i+1
                      #privatekey = fldloc+"\\keys"+"\\"+private_key+"_crt.pem"
                      if browse_flag == 0:
                        privatekey = private_key+".pem"
                      
                      hashkeyname = "hash_ecdsa_key_"+str(i)+".bin"
                      #print("hashkeyname ",hashkeyname)
                      #print("privatekey ",privatekey)
                      file = "ecdsa_key_"+str(i)+".bin"
                      #print("file ",file)
                      #print(" private_key ",private_key)
                      #print(" private_key_pass ",private_key_pass)
                      ret = self.ecdsa_public_key(privatekey,private_key_pass,file,tfile_data,hashkeyname,each_hash_bin)
                      if ret > 0:
                        return ret        
                tfile_data.close()
                key_count  = self.eckeycount.get()
                #print("key count %d ",key_count)
                each_hash_bin.seek(key_count*48)
                while (key_count < 32 ):
                    for indx in range(0, 48):
                        each_hash_bin.write(bytearray(1))
                    key_count = key_count+1 
                each_hash_bin.close()
                if os.path.exists(hash_full_ecdsa_key):
                   _opensslp = self.opensslpath.get()
                   #print("Hash384 is generated ")
                   #print("_opensslp ",_opensslp)
                   cmd = _opensslp+" dgst -sha384 -binary -out "+hash_of_each_ecdsa_key_file +" "+ hash_full_ecdsa_key
                   os.system(cmd)
                #print(" ec384keybin End")
                return ret 

            def ec384keygen(self):
                #print("ec384keygen called ")
                self.chk_config_ini()
                if self.opensslpath.get() == "Choose OpenSSL path" or  self.opensslpath.get() == "":
                    msgidx = 6
                    error_windox()            
                    return 3
                _opensslp = self.opensslpath.get()
                openssl_file = os.path.normpath(_opensslp)
                if not os.path.exists(openssl_file):
                     messagebox.showinfo('OpenSSl.exe file Warning window', 'Under tools folder "openssl.exe" file is not available, please provide the proper path of the openssl.exe or copy openssl.exe to "tools" folder')
                     return 3
                cfgfile = "ECDSA_Key_info.ini"
                fldloc = self.outdir.get()
                fldloc = fldloc+"\\keys"
                full_ecdsa_key = fldloc+"\\"+"full_ecdsa_key_file.bin"
                f = open(full_ecdsa_key,"wb")
                f.close()
                #print("ec384keygen called 1")
                if (os.path.exists(cfgfile)):
                    config = configparser.ConfigParser()
                    config.read(cfgfile)
                    #print("ec384keygen called 2")
                    #print("Ecdkeysa file info ")
                    i=0
                    for each_section in config.sections():
                      for (each_key, each_val) in config.items(each_section):
                        if each_key == "ecdsakeyfilename":
                            private_key = each_val
                            #print("private_key ",private_key)
                        if each_key == "ecdsakeyfilenamepass":
                            private_key_password = each_val
                            #print("private_key_password ",private_key_password)
                      i = i+1    
                      try:
                         filepath=private_key
                         #print("filepath ",filepath)
                         filepath="/".join(filepath.split('\\')) 
                         ecdsafile = open(filepath,"rt")
                         ecdsafile.close()
                         if "" == private_key:
                           msgidx = 3
                           error_windox()
                           return 4
                         cnt = "\\".join(private_key.split('/'))     
                         cmd = "copy /y "+cnt+" "+fldloc  
                         #print("File copied 0")
                         op = os.system(cmd) 
                         #print("File copied 1")
                         #self.ecdsa_public_key(ecdsafile_crt)
                      except:
                         _PrivKeyFile = fldloc+"\\"+private_key
                         _PrivKeyPassword = private_key_password
                         #print(_PrivKeyFile)
                         #print(_PrivKeyPassword)
                         if(self.generate_ec384_keys(_opensslp, _PrivKeyFile, _PrivKeyPassword,i)):
                           error_windox()                    
                           return 4
                         #if(self.ecdsa_public_key(_PrivKeyFile_crt)):
                         #  return 0
                #print("ec384keygen called End")    
                return 0

            def key_gen_(self):
                global msgidx
                global KeyRFlagsCrnt
                KeyRFlagsCrnt = self.parse_content()
                KeyRFlagsCrnt =0x10
                #print("KeyRFlagsCrnt % x ",KeyRFlagsCrnt)
                if "" == self.ecdhpass.get() or "Please enter Password" == self.ecdhpass.get():
                    self.ecdhpass.set("") 
                rtn = 0
                self.chk_config_ini()

                # if 0 == KeyRFlagsCrnt: 
                #     msgidx = 3
                #     error_windox()
                #     return 1

                if self.opensslpath.get() == "Choose OpenSSL path" or  self.opensslpath.get() == "":
                    #msgidx = 6
                    error_windox()            
                    return 3
                _opensslp = self.opensslpath.get()
                openssl_file = os.path.normpath(_opensslp)
                if not os.path.exists(openssl_file):
                     messagebox.showinfo('OpenSSl.exe file Warning window', 'Under tools folder "openssl.exe" file is not available, please provide the proper path of the openssl.exe or copy openssl.exe to "tools" folder')
                     return 3
                  
                if 0x10 & KeyRFlagsCrnt:
                    fldloc = self.outdir.get()
                    fldloc = fldloc+"\\keys"
                    try:
                        filepath=self.ecdhkey.get()
                        filepath="/".join(filepath.split('\\')) 
                        ecdhfile = open(filepath,"rt")
                        ecdhfile.close()
                        # if "" == self.ecdhpass.get():
                        #     msgidx = 3
                        #     error_windox()
                        #     return 4
                        cnt = "\\".join(self.ecdhkey.get().split('/'))     
                        cmd = "copy /y "+cnt+" "+fldloc  
                        op = os.system(cmd) 
                    except:
                        _PrivKeyFile = fldloc+"\\"+self.ecdhkey.get()            
                        _PrivKeyPassword = self.ecdhpass.get()
                        if( self.generate_keys(_opensslp, _PrivKeyFile, _PrivKeyPassword)):
                            #msgidx = 7
                            error_windox()                    
                            return 5 
                            
                if 0x20 & KeyRFlagsCrnt:
                    fldloc = self.outdir.get()
                    fldloc = fldloc+"\\keys"
                    try:
                        filepath=self.ecdsakey.get()
                        filepath="/".join(filepath.split('\\'))    
                        ecdsafile = open(filepath,"rt")
                        ecdsafile.close()
                        if "" == self.ecdsapass.get():
                            msgidx = 3
                            error_windox()
                            return 6
                        filename =  self.ecdsakey.get().split(".")[0]    
                        cnt = "\\".join(filename.split('/'))  
                        cmd = "copy /y "+cnt+".pem "+fldloc

                        op = os.system(cmd) 
                        cmd = "copy /y "+cnt+"_crt.pem "+fldloc
                        op = os.system(cmd)
                        
                    except:
                        _PrivKeyFile = fldloc+"\\"+self.ecdsakey.get()
                        _PrivKeyPassword = self.ecdsapass.get()
                        if( self.generate_keys(_opensslp, _PrivKeyFile, _PrivKeyPassword)):
                            lbl = Label(self, text="Error in generating ECDSA ECC Private Key").grid(column = 1,sticky=W, pady=0, padx=1)
                            return 7
                return 0      
                
            def generate_keys(self, opensslp, PrivKeyFile, PrivKeyPassword):
                opensslpath = self.opensslpath.get()
                cmd = opensslpath + " version "
                cmd ='"%s"'%cmd
                ret = os.system(cmd)
                if ret:
                  messagebox.showinfo('Opensll path  Warning window', 'openssl path is missing ')
                  return 1
                if PrivKeyPassword =="":
                  cmd = opensslp +' ecparam -name secp384r1 -genkey | '+ opensslp + ' ec -out '+ PrivKeyFile+'.pem' 
                else:
                  cmd = opensslp +' ecparam -name secp384r1 -genkey | '+ opensslp + ' ec -out '+ PrivKeyFile+'.pem -passout pass:'+PrivKeyPassword+' -aes-256-cbc'
                op = os.system(cmd)   
                opstr = PrivKeyFile.split("\\")[-1]
                    
                subjopt = "/C=US/ST=NYC/L=Hauppauge/O=MCHP/OU=CPG-FW/CN=CEC1712"    
                if PrivKeyPassword =="":
                  cmd = opensslp +" req -new -key "+PrivKeyFile+".pem -out "+PrivKeyFile+"_csr.pem"+" -subj "+subjopt   
                else:
                  cmd = opensslp +" req -new -key "+PrivKeyFile+".pem -out "+PrivKeyFile+"_csr.pem -passin pass:"+PrivKeyPassword+" -subj "+subjopt
                op = os.system(cmd) 
                #if (op):
                #    return 1
                if PrivKeyPassword =="":
                  cmd = opensslp+" x509 -req -days 3650 -in "+PrivKeyFile+"_csr.pem -signkey "+PrivKeyFile+".pem -out "+PrivKeyFile+"_crt.pem"
                else:
                  cmd = opensslp+" x509 -req -days 3650 -in "+PrivKeyFile+"_csr.pem -signkey "+PrivKeyFile+".pem -out "+PrivKeyFile+"_crt.pem -passin pass:"+PrivKeyPassword
                op = os.system(cmd) 
                #if (op):
                #    return 2
                # cmd = opensslp +' ecparam -name secp384r1 -genkey | '+ opensslp + ' ec -out '+ PrivKeyFile+'.pem -passout pass:'+PrivKeyPassword+' -aes-256-cbc'
                # op = os.system(cmd)   
                # opstr = PrivKeyFile.split("\\")[-1]
                    
                # subjopt = "/C=US/ST=NYC/L=Hauppauge/O=MCHP/OU=CPG-FW/CN=CEC1712"    
                # cmd = opensslp +" req -new -key "+PrivKeyFile+".pem -out "+PrivKeyFile+"_csr.pem -passin pass:"+PrivKeyPassword+" -subj "+subjopt
                # op = os.system(cmd) 
                # if (op):
                #     return 1
                # cmd = opensslp+" x509 -req -days 3650 -in "+PrivKeyFile+"_csr.pem -signkey "+PrivKeyFile+".pem -out "+PrivKeyFile+"_crt.pem -passin pass:"+PrivKeyPassword
                # op = os.system(cmd) 
                # if (op):
                #     return 2
                '''    
                cmd = opensslp+" x509 -in "+PrivKeyFile+"_crt.pem -text -noout > "+PrivKeyFile+"_dump.txt"
                op = os.system(cmd) 

                if (op):
                    return 3
                cmd = opensslp+" ec -in "+PrivKeyFile+".pem -text -passin pass:"+PrivKeyPassword+"  > "+PrivKeyFile+"_pub_pvt_dump.txt"  
                op = os.system(cmd) 
                if (op):
                    return 4
                '''
                return 0

            def get_key(self, file, pass_phrase_1):
                if os.path.exists(file):
                    #keydata = open(fldloc+"\\"+"keys_info1.txt","wt")
                    #keydata.write("; CEC1702 Key extraction tool from key files \n\n")
                    #keydata.write("[EFUSE]\n") 
                    crypto_be = cryptography.hazmat.backends.default_backend()
                    # extension = os.path.splitext(file)[1] 
                    # if extension ==".txt":
                    #     aesk_f = open(file,"rt+")
                    #     for line in aesk_f:
                    #         AESKEY = list(line)
                    #         AESKEY = AESKEY[0:96]
                    #         #line1 = AESKEY[::-1]
                    #         for j in range(0,4):
                    #             key = []
                    #             k = j*16
                    #             for i in range (k,k+16,2):
                    #                 key.append(line1[i+1]+line1[i])
                    #                 cnt = line1[i+1]+line1[i]
                    #             val = str(j)+''.join(key)
                    #             #print("val ",val)
                    #     aesk_f.close()
                    #     print("val ",val)
                    #     return val
                                #return key
                    with open (file, "r") as ecdhdata:
                        data = ecdhdata.readlines()
                        str1 = ''.join(data)
                        h3 = str1.splitlines()
                        cert_file = h3[0]
                        encrypt_file =h3[1]	
                    if cert_file== "-----BEGIN EC PRIVATE KEY-----":
                        try:
                            pattern = re.compile("ENCRYPTED")
                            encrypt_file = re.findall(pattern,encrypt_file)
                            encrypt_file =encrypt_file[0]
                            if encrypt_file =="ENCRYPTED":
                                aes_key = h3[2]
                                pattern = re.compile("DEK-Info: AES-256-CBC")
                                aes_key = re.findall(pattern,aes_key) 
                                aes_key =aes_key[0]
                                if aes_key =="DEK-Info: AES-256-CBC":
                                    with open(file, 'rb') as encypt_key:
                                        pass_phrase = pass_phrase_1.encode("ascii")
                                        try:
                                            #root_ca_priv_key = root_ca_priv_key.encode('utf-8')
                                            root_ca_priv_key = serialization.load_pem_private_key(
                                            data=encypt_key.read(),
                                            password=pass_phrase,
                                            backend=crypto_be)
                                            #base64_cert = root_ca_priv_key.private_bytes(Encoding.PEM).decode('utf-8')
                                            #print("base64_cert ",root_ca_priv_key.private_numbers().private_value.to_bytes(48, 'big'))
                                            root_ca_priv_key = root_ca_priv_key.private_numbers().private_value.to_bytes(48, 'big').hex()
                                            #print("root_ca_priv_key  ",str(root_ca_priv_key))
                                            # private_key = root_ca_priv_key.private_bytes(
                                            # encoding=serialization.Encoding.bytes,
                                            # format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            # encryption_algorithm=serialization.BestAvailableEncryption(pass_phrase)
                                            # )
                                            # print("root_ca_priv_key  ",(private_key))
                                            # private_key_list = []
                                            # pis = private_key.splitlines()
                                            # for p in pis:
                                                # private_key_list.append(p.decode("utf-8"))
                                                # private_key_list.append('\n')
                                            # pri_key_string = ''.join(private_key_list)
                                            # print("root_ca_priv_key  ",(pri_key_string))
                                            #print("root_ca_priv_key  ",root_ca_priv_key.private_key.private_numbers())
                                            #ECDSAcnt = "ECDSAPrivKeyFile = "+ecdsa_key
                                            #ECDSAcnt = "/".join(ECDSAcnt.split('\\')) 
                                            #keydata.write(ECDSAcnt+"\n")
                                            #ECDSAPASScnt = "ECDSAPrivKeyPassword = "+self.ecdsapass.get()
                                            #ECDSAPASScnt = "/".join(ECDSAPASScnt.split('\\')) 
                                            #keydata.write(ECDSAPASScnt+"\n")
                                        except:
                                            print("ECDH2 Password is incorrect or not provided the valid password\n")
                                            print("Efuse binary of OTP files is not generated \n")
                                            messagebox.showinfo('ECDH2 Password Warning window', 'ECDH2 Password is incorrect or not provided the valid password')
                                            #if "" == self.ecdsapass.get():
                                            msgidx = 13
                                            error_windox()
                                            return 6
                                            #return rtn
                                        return (root_ca_priv_key)
        								#pub_nums = root_ca_priv_key.public_key().public_numbers()
                                        #pubkey =  pub_nums.x.to_bytes(32, byteorder='big', signed=False)
                                        #pubkey += pub_nums.y.to_bytes(32, byteorder='big', signed=False)
                                        #print(binascii.hexlify(pubkey))
                                        #with open(key_fileloc,"rb+") as key_file:
                                        #    key_file.seek(0)
                                        #    key_file.write(pubkey)
                                            #key_file.write(pubkey_2)
                                        #    key_file.close() 
                        except:
                            with open(file, 'rb') as plain_priv_key:
                                root_ca_priv_key = serialization.load_pem_private_key(
                                data=plain_priv_key.read(),
                                password=None,
                                backend=crypto_be)
                                #ECDSAcnt = "ECDSAPrivKeyFile = "+ecdsa_key
                                #ECDSAcnt = "/".join(ECDSAcnt.split('\\')) 
                                #keydata.write(ECDSAcnt+"\n")
                                # Get the public key as X and Y integers concatenated
                                root_ca_priv_key = root_ca_priv_key.private_numbers().private_value.to_bytes(48, 'big').hex()
                                return root_ca_priv_key
        						#pub_nums = root_ca_priv_key.public_key().public_numbers()
                                #pubkey =  pub_nums.x.to_bytes(32, byteorder='big', signed=False)
                                #pubkey += pub_nums.y.to_bytes(32, byteorder='big', signed=False)
                                #print(binascii.hexlify(pubkey))   
                                #with open(key_fileloc,"rb+") as key_file:
                                #    key_file.seek(0)
                                #    key_file.write(pubkey)
                                        #key_file.write(pubkey_2)
                                #    key_file.close()  
        						
            def gene_conf_file(self, keyOPT, AESkey, ECDHkey, ECDHpass, ECDSAkey, ECDSApass ):

                fldloc = self.outdir.get()
                fldloc = "/".join(fldloc.split('\\'))
                # ecdh_pub_file_name = "tools/EVERGLADES_ECDH_ROM_crt.pem"
                # ecdh_pub_file_path = os.path.normpath(ecdh_pub_file_name)
                # if not os.path.exists(ecdh_pub_file_path):
                #      messagebox.showinfo('EVERGLADES_ECDH_ROM_crt.pem file Warning window', 'Under tools folder "EVERGLADES_ECDH_ROM_crt.pem" file is not available, please copy EVERGLADES_ECDH_ROM_crt.pem to "tools" folder')
                #      return 3
                  
                #print("Inside gene_conf_file 1")
                #print("keyOPT ",keyOPT)
                keydata = open(fldloc+"\\"+"keys\\key_file1.txt","wt")
                with open(fldloc+"\\"+"keys\\key_file.txt","wt") as in_file:
                    #in_file.write("; EVERGLADES Key extraction tool from key files \n\n")
                    #keydata.write("; EVERGLADES Key extraction tool from key files \n\n")
                    in_file.write("[ROM]\n")   
                    keydata.write("[ROM]\n") 
                    #print("Inside gene_conf_file 22")
                    #print("keyOPT ",keyOPT)
                    if 0x10 & keyOPT:     
                        a= str(ECDHkey)
                        filename = "/".join(a.split('\\'))
                        filename = filename.split("/")[-1]
                        filenameECDH = filename.split(".")[0]
                        cnt = "EFusePVTKey = "+fldloc+"/keys/"+filenameECDH+".pem"
                        cnt = "/".join(cnt.split('\\')) 
                        in_file.write(cnt+"\n")
                        keydata.write(cnt+"\n")
                        cnt = "EFusePVTKeyPassWord = "+ECDHpass
                        cnt = "/".join(cnt.split('\\')) 
                        #print("Inside gene_conf_file 2")
                        in_file.write(cnt+"\n")
                        keydata.write(cnt+"\n")
                        cnt = "EFusePVTKeyEN = true\n"
                        in_file.write(cnt)
                        keydata.write(cnt+"\n")

                        cnt = "ROMECDHPubKeyFile = tools/GlacierROMP384Prod_crt.pem\n"
                        in_file.write(cnt)
                        keydata.write(cnt+"\n")
                        #cnt = "ROMECDHPubKeyFile = tools/EvgldRomEP384Prod_crt.pem\n"
                        #in_file.write(cnt)
                        #keydata.write(cnt+"\n")
                        if 1 == self.ECDHENCvar.get():
                                #cnt = "ECDHROMKEYEC = true\n"
                                #in_file.write(cnt)
                                #keydata.write(cnt+"\n")
                                #if 0 == self.ecdhkeyvar.get():
                                #EvgldRomEP384Prod_crt.pem public key for production
                                cnt = "ROMECDHPubKeyFile = tools/GlacierROMP384Prod_crt.pem\n"
                                in_file.write(cnt)
                                keydata.write(cnt+"\n")
                                	#keydata.write(cnt+"\n")
                                #cnt = "ROMECDHPubKeyFile = tools/ECC384r_crt.pem\n"
                                if 1 == self.ecdhkeyvar.get():
                                	file = self.custom_ecdh_key_bin.get()
                                	file = "/".join(file.split('\\')) 
                                	cnt = "TestModeAes = true\n"
                                	in_file.write(cnt)
                                	keydata.write(cnt+"\n")
                                	extension = os.path.splitext(file)[1] 
                                	if extension ==".txt":
                                		aesk_f = open(file,"rt+")
                                		for line in aesk_f:
                                			AESKEY = list(line)
                                			AESKEY = AESKEY[0:96]
                                			line1 = AESKEY[::-1]
                                			for j in range(0,4):
                                				key = []
                                				k = j*16
                                				for i in range (k,k+16,2):
                                					key.append(line1[i+1]+line1[i])
                                					cnt = line1[i+1]+line1[i]
                                					#print("cnt ",cnt)
                                				#cnt="TestModeAesKeyGenConstant"+str(j)+" = 0x"+''.join(key)+"\n"
                                				#in_file.write("TestModeAesKeyGenConstant"+str(j)+" = 0x"+''.join(key)+"\n") 
                                                #print("val ",val)
                                		aesk_f.close()
                                		cnt="TestModeAesKeyGenConstant"+" = 0x"+''.join(key)+"\n"
                                		#print("val ",val)
                                		#return val
                                	else:
                                		if extension ==".bin":
                                			with open (self.custom_ecdh_key_bin.get(),"rb") as cus_file:
                                				file_data = cus_file.read()
                                				dat = binascii.hexlify(file_data[0:])
                                				dat = dat.decode("utf-8")
                                				#print("file_date ",str(dat))
                                				#print("file_date ",str(dat))
                                				cnt="TestModeAesKeyGenConstant"+" = 0x"+str(dat)+"\n"
                                				#print("cnt ",cnt)
                                				#print("file_date ",str(dat))
                                				#dat = str(dat)
                                				in_file.write("TestModeAesKeyGenConstant"+" = 0x"+str(dat)+"\n") 
                                				#print("file_date ",str(dat))
                                				#print("file_data1")
                                			cus_file.close()
                                		else:
        	                        		key = self.get_key(file,self.custom_ecdh_pass_key_bin.get())
        	                        		#print("file_data2")
        	                        		#print("key  ",key)
        	                            	#key="1234567890"
        	                        		cnt="TestModeAesKeyGenConstant"+" = 0x"+''.join(key)+"\n"
        	                        		in_file.write("TestModeAesKeyGenConstant"+" = 0x"+''.join(key)+"\n") 
        	                        		#print("file_data3")
                                	#in_file.write(cnt)
                                	#keydata.write(cnt+"\n")
                                	#cnt = "ROMECDHPubKeyFile = "+file
                                	#keydata.write(cnt+"\n")
                                	#print("cnt ",cnt)
                                in_file.write(cnt)
                                keydata.write(cnt+"\n")
                                
                    if 0x20 & keyOPT: 
                        a= str(ECDSAkey)
                        filename = "/".join(a.split('\\'))
                        filename = filename.split("/")[-1]
                        filename = filename.split(".")[0]
                        ECDSAcnt = "ECDSAPrivKeyFile = "+fldloc+"/keys/"+filename+".pem"
                        ECDSAcnt = "/".join(ECDSAcnt.split('\\')) 
                        in_file.write(ECDSAcnt+"\n")
                        keydata.write(ECDSAcnt+"\n")
                        ECDSAPASScnt = "ECDSAPrivKeyPassword = "+ECDSApass
                        ECDSAPASScnt = "/".join(ECDSAPASScnt.split('\\')) 
                        in_file.write(ECDSAPASScnt+"\n")
                        keydata.write(ECDSAPASScnt+"\n")
                        cnt ="ECDSAPubKeyCrtFile = "+fldloc+"/keys/"+filename+"_crt.pem"
                        cnt = "/".join(cnt.split('\\')) 
                        in_file.write(cnt+"\n")
                        keydata.write(cnt+"\n")


                    in_file.write("\n\n\n")    
                    keydata.write("\n\n\n")
                    in_file.write("; SPI Image Generator - config File details\n")   
                    keydata.write("; SPI Image Generator - config File details\n")           
                    in_file.write("; -----------------------------------------\n")    
                    keydata.write("; -----------------------------------------\n")
                    in_file.write("; Copy below information into the image generator config file\n")   
                    keydata.write("; Copy below information into the image generator config file\n")
                    in_file.write("; \n")
                    keydata.write("; \n")
                    #print("Inside gene_conf_file 3")
                    if 0x10 & keyOPT: 
                      if 0 == self.ECDHENCvar.get():
                        cnt =";ROMECDHPubKeyFile = "+fldloc+"/keys/"+filenameECDH+"_crt.pem"
                        cnt = "/".join(cnt.split('\\')) 
                        #print("Inside gene_conf_file 4")
                        in_file.write(cnt+"\n")
                        keydata.write(cnt+"\n")
                    if 0x20 & keyOPT: 
                        in_file.write("; "+ECDSAcnt+"\n")
                        keydata.write("; "+ECDSAcnt+"\n")
                        in_file.write("; "+ECDSAPASScnt+"\n")
                        keydata.write("; "+ECDSAPASScnt+"\n")

                    in_file.write("\n; ----E.n.d..o.f..f.i.l.e----\n\n")
                    keydata.write("\n; ----E.n.d..o.f..f.i.l.e----\n\n")
                    
                in_file.close()
                keydata.close()
                
            def moveme(self):
                file=self.filename.get()
                self.contents.set(file)
                
            def clearcontenttag1(self, event):
                tagadd1 = self.tagAddr1.get()

                if "0000" == tagadd1 or len(tagadd1) >= 9:
                    self.tagAddr1.set("")

            def flash_clearcontent4_update2(self, *dummy):
                flashcomp1 = self.flashcomp1.get()
                if len(flashcomp1) >= 9:
                    self.flashcomp1.set(0)       

            def cr_flashcomp1_clearcontent4_update2(self, *dummy):
                cr_flashcomp1 = self.cr_flashcomp1.get()
                if len(cr_flashcomp1) >= 9:
                    self.cr_flashcomp1.set(0)    	
            
            def eckeycount_clearcontent(self, event):
                eckeycount = self.eckeycount.get()
                if eckeycount >= 33:
                    self.eckeycount.set(0)
            
            def flash_clearcontent4(self, event):
                flashcomp1 = self.flashcomp1.get()
                if len(flashcomp1) >= 9:
                    self.flashcomp1.set(0)    

            def cr_flashcomp1_clearcontent4(self, event):
                cr_flashcomp1 = self.cr_flashcomp1.get()
                if len(cr_flashcomp1) >= 9:
                    self.cr_flashcomp1.set(0)

            def otp_clearcontentvalue_2(self, *dummy):
                otp_crc_var = self.otp_crc_var.get()
                if len(otp_crc_var) >= 9:
                    self.otp_crc_var.set(0)     

            def otp_read_lock_clearcontentvalue_2(self, *dummy):
                otp_read_lock_byte_var_0 = self.otp_read_lock_byte_var_0.get()
                if len(otp_read_lock_byte_var_0) >= 9:
                    self.otp_read_lock_byte_var_0.set(0)      

            def otp_write_secure_lock_byte_clearcontentvalue_2(self, *dummy):
                otp_write_secure_lock_byte = self.otp_write_secure_lock_byte.get()
                if len(otp_write_secure_lock_byte) >= 3:
                    self.otp_write_secure_lock_byte.set(0)       

            def otp_read_secure_lock_byte_clearcontentvalue_2(self, *dummy):
                otp_read_secure_lock_byte = self.otp_read_secure_lock_byte.get()
                if len(otp_read_secure_lock_byte) >= 3:
                    self.otp_read_secure_lock_byte.set(0)     

            def cfg_lock_byte_0_val_clearcontentvalue_2(self, *dummy):
                cfg_lock_byte_0_val = self.cfg_lock_byte_0_val.get()
                if len(cfg_lock_byte_0_val) >= 3:
                    self.cfg_lock_byte_0_val.set(0)       

            def cfg_lock_byte_1_val_clearcontentvalue_2(self, *dummy):
                cfg_lock_byte_1_val = self.cfg_lock_byte_1_val.get()
                if len(cfg_lock_byte_1_val) >= 3:
                    self.cfg_lock_byte_1_val.set(0)      

            def cfg_lock_byte_2_val_clearcontentvalue_2(self, *dummy):
                cfg_lock_byte_2_val = self.cfg_lock_byte_2_val.get()
                if len(cfg_lock_byte_2_val) >= 3:
                    self.cfg_lock_byte_2_val.set(0)        

            def cfg_lock_byte_3_val_clearcontentvalue_2(self, *dummy):
                cfg_lock_byte_3_val = self.cfg_lock_byte_3_val.get()
                if len(cfg_lock_byte_3_val) >= 3:
                    self.cfg_lock_byte_3_val.set(0)       

            def cfg_lock_byte_4_val_clearcontentvalue_2(self, *dummy):
                cfg_lock_byte_4_val = self.cfg_lock_byte_4_val.get()
                if len(cfg_lock_byte_4_val) >= 3:
                    self.cfg_lock_byte_4_val.set(0)      

            def otp_write_lock_clearcontentvalue_2(self, *dummy):
                otp_write_lock_byte_var_0 = self.otp_write_lock_byte_var_0.get()
                if len(otp_write_lock_byte_var_0) >= 9:
                    self.otp_write_lock_byte_var_0.set(0)       

            def platform_ID_clearcontentvalue_2(self, *dummy):
                plat_id = self.plat_id.get()
                if len(plat_id) >= 5:
                    self.plat_id.set(0)         

            def prod_debug_clearcontentvalue_2(self, *dummy):
                prod_debug = self.prod_debug.get()
                if len(prod_debug) >= 3:
                    self.prod_debug.set(0)     

            def ecdsa_key_rev_clearcontentvalue_2(self, *dummy):
                ECDSA_key_revocation_byte_0_var = self.ECDSA_key_revocation_byte_0_var.get()
                if len(ECDSA_key_revocation_byte_0_var) >= 9:
                    self.ECDSA_key_revocation_byte_0_var.set(0)      

            def secure_boot_clearcontentvalue_2(self, *dummy):
                secure_boot_var = self.secure_boot_var.get()
                if len(secure_boot_var) >= 3:
                    self.secure_boot_var.set(0)   

            def security_features_clearcontentvalue_2(self, *dummy):
                security_features_var = self.security_features_var.get()
                if len(security_features_var) >= 3:
                    self.security_features_var.set(0)    

            def dice_riot_feature_var_clearcontentvalue_2(self, *dummy):
                dice_riot_feature_var = self.dice_riot_feature_var.get()
                if len(dice_riot_feature_var) >= 3:
                    self.dice_riot_feature_var.set(0)    

            def crisis_flash_feature_var_clearcontentvalue_2(self, *dummy):
                crisis_flash_feature_var = self.crisis_flash_feature_var.get()
                if len(crisis_flash_feature_var) >= 3:
                    self.crisis_flash_feature_var.set(0)  

            def optional_feature_var_clearcontentvalue_2(self, *dummy):
                optional_feature_var = self.optional_feature_var.get()
                if len(optional_feature_var) >= 3:
                    self.optional_feature_var.set(0)    

            def custom_features_var_clearcontentvalue_2(self, *dummy):
                custom_features_var = self.custom_features_var.get()
                if len(custom_features_var) >= 3:
                    self.custom_features_var.set(0)    

            def crisis_mode_var_clearcontentvalue_2(self, *dummy):
                crisis_mode_var = self.crisis_mode_var.get()
                if len(crisis_mode_var) >= 3:
                    self.crisis_mode_var.set(0)
            
            def prod_debug_clearcontentvalue(self, event):
                prod_debug = self.prod_debug.get()
                if len(prod_debug) >= 3:
                    self.prod_debug.set(0)  
            def platform_ID_clearcontentvalue(self, event):
                plat_id = self.plat_id.get()
                if len(plat_id) >= 5:
                    self.plat_id.set(0)     

            def otp_crc_var_clearcontent5(self, event):
                otp_crc_var = self.otp_crc_var.get()
                if len(otp_crc_var) >= 9 :
                    self.otp_crc_var.set("00000000")  

            def otp_rollback_var_0_clearcontent5(self, event):
                otp_rollback_var_0 = self.otp_rollback_var_0.get()
                if len(otp_rollback_var_0) >= 9 :
                    self.otp_rollback_var_0.set("00000000")     

            def otp_rollback_var_1_clearcontent5(self, event):
                otp_rollback_var_1 = self.otp_rollback_var_1.get()
                if len(otp_rollback_var_1) >= 9 :
                    self.otp_rollback_var_1.set("00000000")     

            def otp_rollback_var_2_clearcontent5(self, event):
                otp_rollback_var_2 = self.otp_rollback_var_2.get()
                if len(otp_rollback_var_2) >= 9 :
                    self.otp_rollback_var_2.set("00000000")     

            def otp_rollback_var_3_clearcontent5(self, event):
                otp_rollback_var_3 = self.otp_rollback_var_3.get()
                if len(otp_rollback_var_3) >= 9 :
                    self.otp_rollback_var_3.set("00000000")     

            def ecdsa_rollback_var_0_clearcontent5(self, event):
                ecdsa_rollback_var_0 = self.ecdsa_rollback_var_0.get()
                if len(ecdsa_rollback_var_0) >= 9 :
                    self.ecdsa_rollback_var_0.set("00000000") 

            def otp_read_lock_clearcontentvalue(self, event):
                otp_read_lock_byte_var_0 = self.otp_read_lock_byte_var_0.get()
                if len(otp_read_lock_byte_var_0) >= 3:
                    self.otp_read_lock_byte_var_0.set(0)     

            def otp_write_secure_lock_byte_clearcontentvalue(self, event):
                otp_write_secure_lock_byte = self.otp_write_secure_lock_byte.get()
                if len(otp_write_secure_lock_byte) >= 3:
                    self.otp_write_secure_lock_byte.set(0)      

            def otp_read_secure_lock_byte_clearcontentvalue(self, event):
                otp_read_secure_lock_byte = self.otp_read_secure_lock_byte.get()
                if len(otp_read_secure_lock_byte) >= 3:
                    self.otp_read_secure_lock_byte.set(0)        

            def cfg_lock_byte_0_val_clearcontentvalue(self, event):
                cfg_lock_byte_0_val = self.cfg_lock_byte_0_val.get()
                if len(cfg_lock_byte_0_val) >= 3:
                    self.cfg_lock_byte_0_val.set(0)     

            def cfg_lock_byte_1_val_clearcontentvalue(self, event):
                cfg_lock_byte_1_val = self.cfg_lock_byte_1_val.get()
                if len(cfg_lock_byte_1_val) >= 3:
                    self.cfg_lock_byte_1_val.set(0)          

            def cfg_lock_byte_2_val_clearcontentvalue(self, event):
                cfg_lock_byte_2_val = self.cfg_lock_byte_2_val.get()
                if len(cfg_lock_byte_2_val) >= 3:
                    self.cfg_lock_byte_2_val.set(0)          

            def cfg_lock_byte_3_val_clearcontentvalue(self, event):
                cfg_lock_byte_3_val = self.cfg_lock_byte_3_val.get()
                if len(cfg_lock_byte_3_val) >= 3:
                    self.cfg_lock_byte_3_val.set(0)       

            def cfg_lock_byte_4_val_clearcontentvalue(self, event):
                cfg_lock_byte_4_val = self.cfg_lock_byte_4_val.get()
                if len(cfg_lock_byte_4_val) >= 3:
                    self.cfg_lock_byte_4_val.set(0)      
            

            def otp_write_lock_clearcontentvalue(self, event):
                otp_write_lock_byte_var_0 = self.otp_write_lock_byte_var_0.get()
                if len(otp_write_lock_byte_var_0) >= 9:
                    self.otp_write_lock_byte_var_0.set(0)      

            def otp_clearcontentvalue(self, event):
                otp_crc_var = self.otp_crc_var.get()
                if len(otp_crc_var) >= 9:
                    self.otp_crc_var.set(0)      

            def ecdsa_key_rev_clearcontentvalue(self, event):
                ECDSA_key_revocation_byte_0_var = self.ECDSA_key_revocation_byte_0_var.get()
                if len(ECDSA_key_revocation_byte_0_var) >= 9:
                    self.ECDSA_key_revocation_byte_0_var.set(0)      


            def secure_boot_clearcontentvalue(self, event):
                secure_boot_var = self.secure_boot_var.get()
                if len(secure_boot_var) >= 3:
                    self.secure_boot_var.set(0)
            def ecdsa_clearcontentvalue_1(self, *dummy):
                ecdsaaddress = self.ecdsaaddress_1.get()
                if len(ecdsaaddress) >= 9:
                    self.ecdsaaddress_1.set(0)
            def ecdsa_clearcontentvalue_func(self, event):
                ecdsaaddress = self.ecdsaaddress_1.get()
                if len(ecdsaaddress) >= 9:
                    self.ecdsaaddress_1.set(0)
            def ecdsa_clearcontentvalue_2(self, *dummy):
                ecdsaaddress = self.ecdsaaddress.get()
                if len(ecdsaaddress) >= 9:
                    self.ecdsaaddress.set(0)
            def ecdsa_clearcontentvalue(self, event):
                ecdsaaddress = self.ecdsaaddress.get()
                if len(ecdsaaddress) >= 9:
                    self.ecdsaaddress.set(0)    

            def security_features_clearcontentvalue(self, event):
                security_features_var = self.security_features_var.get()
                if len(security_features_var) >= 3:
                    self.security_features_var.set(0)     

            def dice_riot_feature_var_clearcontentvalue(self, event):
                dice_riot_feature_var = self.dice_riot_feature_var.get()
                if len(dice_riot_feature_var) >= 3:
                    self.dice_riot_feature_var.set(0)    

            def crisis_flash_feature_var_clearcontentvalue(self, event):
                crisis_flash_feature_var = self.crisis_flash_feature_var.get()
                if len(crisis_flash_feature_var) >= 3:
                    self.crisis_flash_feature_var.set(0)    

            def optional_feature_var_clearcontentvalue(self, event):
                optional_feature_var = self.optional_feature_var.get()
                if len(optional_feature_var) >= 3:
                    self.optional_feature_var.set(0)    

            def custom_features_var_clearcontentvalue(self, event):
                custom_features_var = self.custom_features_var.get()
                if len(custom_features_var) >= 3:
                    self.custom_features_var.set(0)    

            def crisis_mode_var_clearcontentvalue(self, event):
                crisis_mode_var = self.crisis_mode_var.get()
                if len(crisis_mode_var) >= 3:
                    self.crisis_mode_var.set(0)

            def clearcontentvalue(self, event):
                pass

            def security_features_var_clearcontent(self, event):
                security_features_var = self.security_features_var.get()
                if len(security_features_var) >= 3:
                    self.security_features_var.set("0")    

            def DSWgpio_clearcontent5(self, event):
                DSWgpio = self.DSWgpio.get()
                if len(DSWgpio) >= 3:
                    self.DSWgpio.set("0")     

            def otp_region_read_lock_var_0_clearcontent5(self, event):
                otp_region_read_lock_var_0 = self.otp_region_read_lock_var_0.get()
                if len(otp_region_read_lock_var_0) >= 3:
                    self.otp_region_read_lock_var_0.set("0")  

            def otp_region_read_lock_var_1_clearcontent5(self, event):
                otp_region_read_lock_var_1 = self.otp_region_read_lock_var_1.get()
                if len(otp_region_read_lock_var_1) >= 3:
                    self.otp_region_read_lock_var_1.set("0")  

            def otp_region_read_lock_var_2_clearcontent5(self, event):
                otp_region_read_lock_var_2 = self.otp_region_read_lock_var_2.get()
                if len(otp_region_read_lock_var_2) >= 3:
                    self.otp_region_read_lock_var_2.set("0")  

            def otp_region_read_lock_var_3_clearcontent5(self, event):
                otp_region_read_lock_var_3 = self.otp_region_read_lock_var_3.get()
                if len(otp_region_read_lock_var_3) >= 3:
                    self.otp_region_read_lock_var_3.set("0")  

            def otp_region_write_lock_var_0_clearcontent5(self, event):
                otp_region_write_lock_var_0 = self.otp_region_write_lock_var_0.get()
                if len(otp_region_write_lock_var_0) >= 3:
                    self.otp_region_write_lock_var_0.set("0")     


            def otp_region_write_lock_var_1_clearcontent5(self, event):
                otp_region_write_lock_var_1 = self.otp_region_write_lock_var_1.get()
                if len(otp_region_write_lock_var_1) >= 3:
                    self.otp_region_write_lock_var_1.set("0")     

            def otp_region_write_lock_var_2_clearcontent5(self, event):
                otp_region_write_lock_var_2 = self.otp_region_write_lock_var_2.get()
                if len(otp_region_write_lock_var_2) >= 3:
                    self.otp_region_write_lock_var_2.set("0")     

            def otp_region_write_lock_var_3_clearcontent5(self, event):
                otp_region_write_lock_var_3 = self.otp_region_write_lock_var_3.get()
                if len(otp_region_write_lock_var_3) >= 3:
                    self.otp_region_write_lock_var_3.set("0")      

            def DPWREN_GPIO_sel_var_clearcontent5(self, event):
                DPWREN_GPIO_sel_var = self.DPWREN_GPIO_sel_var.get()
                if len(DPWREN_GPIO_sel_var) >= 3:
                    self.DPWREN_GPIO_sel_var.set("0")       

            def PRIM_PWRGD_GPIO_sel_var_clearcontent5(self, event):
                PRIM_PWRGD_GPIO_sel_var = self.PRIM_PWRGD_GPIO_sel_var.get()
                if len(PRIM_PWRGD_GPIO_sel_var) >= 3:
                    self.PRIM_PWRGD_GPIO_sel_var.set("0")      

            def RSMRST_GPIO_sel_var_clearcontent5(self, event):
                RSMRST_GPIO_sel_var = self.RSMRST_GPIO_sel_var.get()
                if len(RSMRST_GPIO_sel_var) >= 3:
                    self.RSMRST_GPIO_sel_var.set("0")     

            def DSW_PWRGD_GPIO_sel_var_clearcontent5(self, event):
                DSW_PWRGD_GPIO_sel_var = self.DSW_PWRGD_GPIO_sel_var.get()
                if len(DSW_PWRGD_GPIO_sel_var) >= 3:
                    self.DSW_PWRGD_GPIO_sel_var.set("0")    

            def SUS_PWR_EN_GPIO_sel_var_clearcontent5(self, event):
                SUS_PWR_EN_GPIO_sel_var = self.SUS_PWR_EN_GPIO_sel_var.get()
                if len(SUS_PWR_EN_GPIO_sel_var) >= 3:
                    self.SUS_PWR_EN_GPIO_sel_var.set("0")      

            def SLP_SUS_GPIO_sel_var_clearcontent5(self, event):
                SLP_SUS_GPIO_sel_var = self.SLP_SUS_GPIO_sel_var.get()
                if len(SLP_SUS_GPIO_sel_var) >= 3:
                    self.SLP_SUS_GPIO_sel_var.set("0")        

            def otp_read_256_var_clearcontent5(self, event):
                otp_read_256_var = self.otp_read_256_var.get()
                if len(otp_read_256_var) >= 9 :
                    self.otp_read_256_var.set("00000000")       

            def otp_crc_var_clearcontent5(self, event):
                otp_crc_var = self.otp_crc_var.get()
                if len(otp_crc_var) >= 9 :
                    self.otp_crc_var.set("00000000")  

            def otp_rollback_var_0_clearcontent5(self, event):
                otp_rollback_var_0 = self.otp_rollback_var_0.get()
                if len(otp_rollback_var_0) >= 9 :
                    self.otp_rollback_var_0.set("00000000")     

            def otp_rollback_var_1_clearcontent5(self, event):
                otp_rollback_var_1 = self.otp_rollback_var_1.get()
                if len(otp_rollback_var_1) >= 9 :
                    self.otp_rollback_var_1.set("00000000")     

            def otp_rollback_var_2_clearcontent5(self, event):
                otp_rollback_var_2 = self.otp_rollback_var_2.get()
                if len(otp_rollback_var_2) >= 9 :
                    self.otp_rollback_var_2.set("00000000")     

            def otp_rollback_var_3_clearcontent5(self, event):
                otp_rollback_var_3 = self.otp_rollback_var_3.get()
                if len(otp_rollback_var_3) >= 9 :
                    self.otp_rollback_var_3.set("00000000")     

            def ecdsa_rollback_var_0_clearcontent5(self, event):
                ecdsa_rollback_var_0 = self.ecdsa_rollback_var_0.get()
                if len(ecdsa_rollback_var_0) >= 9 :
                    self.ecdsa_rollback_var_0.set("00000000") 

            def otp_write_260_var_clearcontent5(self, event):
                otp_write_260_var = self.otp_write_260_var.get()
                if len(otp_write_260_var) >= 9 :
                    self.otp_write_260_var.set("00000000")            

            def progflashvar_2_clearcontent5(self, event):
                progflashvar_2 = self.progflashvar_2.get()
                if len(progflashvar_2) >= 3 :
                    self.progflashvar_2.set("0")        

            def power_sequence_var_clearcontent5(self, event):
                power_sequence_var = self.power_sequence_var.get()
                if len(power_sequence_var) >= 3 :
                    self.power_sequence_var.set("0")    

            def progflashvar_1_clearcontent5(self, event):
                progflashvar_1 = self.progflashvar_1.get()
                if len(progflashvar_1) >= 3 :
                    self.progflashvar_1.set("0")
            
            def clearcontent5(self, event):
                tagadd = self.tagAddr.get()

                if "0000" == tagadd or len(tagadd) >= 9:
                    self.tagAddr.set("")
                    
            def clearcontent1(self, event):
                ecdhk_ = self.ecdhkey.get()
                if "No ECDH" == ecdhk_ or"Please enter Filename" == ecdhk_ or "Enter ECDH Key filename to generate" == ecdhk_ :
                    self.ecdhkey.set("")
                
            def clearcontent2(self, event):
                ecdhp_ = self.ecdhpass.get()
                if "No ECDH" == ecdhp_ or "Please enter Password" == ecdhp_ or "Enter ECDH Password" == ecdhp_ :
                    self.ecdhpass.set("" )
                
            def clearcontent3(self, event):
                ecdsak_ = self.ecdsakey.get()
                if "NO ECDSA" == ecdsak_ or "Please enter Filename" == ecdsak_ or "Enter ECDSA Key filename to generate" == ecdsak_ :
                    self.ecdsakey.set("")
                
            def plat_sha384_bin_gen(self):
                ret =0
                fldloc = self.outdir.get()
                self.chk_config_ini()
                fldloc = fldloc+"\\keys"
                privatekey = self.plat_ecdsa_sha384_key_hash_bin.get()
                ret = self.plat_sha384_ecdsa_public_key(privatekey)#,private_key_pass,file,tfile_data,hashkeyname,each_hash_bin)
                if ret > 0:
                   return ret        
            def sha384_bin_gen(self):
                ret =0
                fldloc = self.outdir.get()
                self.chk_config_ini()
                fldloc = fldloc+"\\keys"
                privatekey = self.ecdsa_sha384_key_hash_bin.get()
                ret = self.sha384_ecdsa_public_key(privatekey)#,private_key_pass,file,tfile_data,hashkeyname,each_hash_bin)
                if ret > 0:
                   return ret        

            def ECCP384sel(self):
                opt = self.ECCP384var.get()
                if 1==opt:
                    #self.ecdsa_sha384_key_lbl.config(state="normal")
                    self.ecdsa_sha384_key_outdirbar.config(state="normal")
                    self.ecdsa_sha384_key_hash_button.config(state="normal")
                    self.ecdsa_sha384_key_lbl.config(state="normal")
                    #self.ecdsa_sha384_key_lbl(state="normal")
                else:
                    #self.ecdsa_sha384_key_lbl.config(state="disabled")
                    self.ecdsa_sha384_key_outdirbar.config(state="disabled")
                    self.ecdsa_sha384_key_hash_button.config(state="disabled")
                    self.ecdsa_sha384_key_lbl.config(state="disabled")
                    #self.ecdsa_sha384_key_lbl(state="disabled")
                

            def plat_ECCP384sel(self):
                opt = self.plat_ECCP384var.get()
                if 1==opt:
                    #self.ecdsa_sha384_key_lbl.config(state="normal")
                    self.plat_ecdsa_sha384_key_outdirbar.config(state="normal")
                    self.plat_ecdsa_sha384_key_hash_button.config(state="normal")
                else:
                    #self.ecdsa_sha384_key_lbl.config(state="disabled")
                    self.plat_ecdsa_sha384_key_outdirbar.config(state="disabled")
                    self.plat_ecdsa_sha384_key_hash_button.config(state="disabled")
                
                # global key_count
                # global ap_key_window_active
                # opt = self.ECCP384var.get()
                # eckeycount = self.eckeycount.get()
                # #eckeycount = int(eckeycount,16)
                # #value_count = eckeycount
                # if eckeycount >= 33:
                #     #msgidx =18
                #     messagebox.showinfo('ECKeyCount Warning window', 'ECKeyCount is not provided or greater than 32, please provide the valid value')
                #     #error_windox()
                #     return

                # #pubkeycount = int(pubkeycount,16)
                # #print(pubkeycount)
                # if 0== ap_key_window_active:
                #     if 1== opt:
                #         #selection = "ECC508 Enabled "
                #         #self.pathbar_1.config(state="disabled")
                #         #self.bbutton_hash.config(state="disabled")
                #         #self.newWindowq = Gui()
                #         if eckeycount == 0:
                #             #msgidx =12
                #             #error_windox()
                #             messagebox.showinfo('ECKeyCount Warning window', 'ECKeyCount is zero or not provided or greater than 32, please provide the valid value')
                #             return
                #         if key_count != eckeycount:
                #             cfgfile = "ECDSA_Key_info.ini"
                #             if (os.path.exists(cfgfile)):
                #               os.remove(cfgfile)

                #         self.newWindowq = ECCP384_settings_windox(eckeycount)


            def clearcontent4(self, event):
                pass
                #ecdsap_ = self.ecdsapass.get()
                #if "NO ECDSA" == ecdsap_ or "Please enter Password" == ecdsap_ or "Enter ECDSA Password" == ecdsap_ :
                #    self.ecdsapass.set("")      
            def new_window_settings(self):
                global setting_win_flag
                if 0 == setting_win_flag:
                    self.newWindow = settings_windox()
                
                if 1 == setting_win_flag:
                    setting_win_flag =1
                    setting_win_flag = setting_win_flag +1
                    selected_choice = messagebox.askquestion("Settings", "You have already selected the Settings dialog box for setting the environmental variables, Do you want to open the 'settings' and want to change ?, press 'yes' to open the setting window to change the 'Set Environmental variables'  , 'No' to proceed with the previous 'settings' of environmental variables of openssl path, Generate Header file,Disable warning window,SQTP process")
                    if selected_choice == 'yes':
                        setting_win_flag =0
                        self.newWindow = settings_windox()
                    elif selected_choice == 'no':
                         setting_win_flag =0
                        
                

            def chk_config_ini(self):    
                try:
                    conf_f = open("opensslcfg.ini","rt")   
                    for lines in conf_f:
                        if lines == "":
                            self.opensslpath.set("Choose OpenSSL path")
                            return
                        self.opensslpath.set(str(lines))
                except:
                    self.opensslpath.set("Choose OpenSSL path")  

        class ECCP384_settings_windox(Frame):     
            def __init__(self,variable1):
                global ap_key_window_active
                if 0 == ap_key_window_active:
                    new =Frame.__init__(self)
                    new = Toplevel(self)
                    new.title("ECC384 Key Hash Generation ")
                    global txfile
                    global pvt_key
                    global value_count 
                    global browse_flag
                    canvas = tk.Canvas(new,width=600, height=200)
                    scroll_y = tk.Scrollbar(new, orient="vertical", command=canvas.yview)
                    new.wm_protocol ("WM_DELETE_WINDOW", self.quit)
                    frame = tk.Frame(new)
                    if os.path.exists("mchp.ico"):
                      new.iconbitmap('mchp.ico')

                    self.tx_file=StringVar()
                    self.DSWgpio = StringVar()
            #        self.key_algo = key_algo
            #        self.key_attr = key_attr
                    self.ecckeycount = variable1
                    self.ecdsakey = StringVar()
                    self.pvtecdsakey = StringVar()
                    self.pvtkey = []


                    myrow = 0
                    myrow = myrow +1
                    self.ap_pubkey_algo = StringVar()

                    with_extension = 0
                    #self.variables = []
                    self.entries = []
                    self.bbutton = []
                    #self.variables_1 = []
                    self.entries_1 = []

                    self.pub_entries = []
                    self.pub_bbutton = []
                    #self.variables_1 = []
                    self.pub_entries_1 = []
                    #myrow = myrow +1
                    for i in range(variable1):
                        myrow = myrow +1
                        ap_pub_key_name = "ECDSA Key filename"+str(with_extension)
                        tk.Label(frame, text=ap_pub_key_name).grid(row=myrow, column=0)
                        self.entries_1.append(tk.Entry(frame, bg='yellow',width = 40))
                        self.entries_1[i].grid(row=myrow, column=1)
                        self.entries_1[i].bind('<Return>', partial(self.action1, i))
                        self.bbutton.append(tk.Button(frame, text="Browse",width = 12, command=partial(self.browsefldr_1,i)))
                        self.bbutton[i].grid(row=myrow, column=2)
                        myrow = myrow +1
                        pub_key_name = "ECDSA Key Password"+str(with_extension)
                        tk.Label(frame, text=pub_key_name).grid(row=myrow, column=0)
                        self.pub_entries_1.append(tk.Entry(frame, bg='yellow',width = 40))
                        self.pub_entries_1[i].grid(row=myrow, column=1)
                        self.pub_entries_1[i].bind('<Return>', partial(self.action2, i))
                        #self.pub_bbutton.append(tk.Button(frame, text="Browse",width = 12, command=partial(self.browsefldr_2,i)))
                        #self.pub_bbutton[i].grid(row=myrow, column=2)
                        with_extension = with_extension+1


                    if variable1 > 0:
                        #self.entries[0].insert('end', '')
                        self.entries_1[0].insert('end', '')
                        self.pub_entries_1[0].insert('end', '')
                    
                    cfgfile = "ECDSA_Key_info.ini"
                    if (os.path.exists(cfgfile)):
                        config = configparser.ConfigParser()
                        config.read(cfgfile)
                        i=0
                        for each_section in config.sections():
                          for (each_key, each_val) in config.items(each_section):
                            if each_key == "ecdsakeyfilename":
                                from_file = each_val
                                self.entries_1[i].delete(0, 'end')
                                self.entries_1[i].insert('end', each_val)
                            if each_key == "ecdsakeyfilenamepass":
                                from_file = each_val
                                self.pub_entries_1[i].delete(0, 'end')
                                self.pub_entries_1[i].insert('end', each_val)
                          i = i+1
                      

                    # #cfgfile.close()
                    # print("loop22")
                    # for i in range(len(self.entries_1)):
                    #   text = self.entries_1[i].get()
                    #   config = configparser.SafeConfigParser()
                    #   ECKEY = "ECKEY "
                    #   ECKEY = ECKEY +'"%d"'%i
                    #   print(ECKEY)
                    #   key_name = "ECDSAKeyfilename"+str(i)
                    #   key_name_1 = "ECDSAPubKeyfilename"+str(i)
                    #   text_1 = self.pub_entries_1[i].get()
                    #   print("key_name ",key_name)
                    #   config.add_section(ECKEY)
                    #   config.set(ECKEY,key_name,text)
                    #   config.set(ECKEY,key_name_1,text_1)
                    #   print("text ",text)
                    #   config.write(cfgfile)
            #         number_of_line_1 =0
            #         if os.path.exists("pubfilecfg.ini"):
            #             pub_conf_f = open("pubfilecfg.ini","r") #as conf_f:
            #             for line in pub_conf_f:
            #                 number_of_line_1 += 1
            #                 #print("number_of_line ",number_of_line_1)
            #             pub_conf_f.close()
            #             pub_conf_f = open("pubfilecfg.ini","r") #as conf_f:
            #             data_1 = pub_conf_f.readlines()
            #             str_2 = ''.join(data_1)
            #             h4 = str_2.splitlines()
            # #           j = h3[0]
            #             i =0
            #             for i in range(number_of_line_1):
            #                 self.entries_1[i].delete(0, 'end')
            #                 self.entries_1[i].insert('end', h4[i])



                    myrow = myrow +1
                    frame.button = Button( frame, text = "OK", width = 25,
                                              command = self.close_window )
                    frame.button.grid(row=myrow, column=1, sticky=W+E, pady=0, padx=1)
                    canvas.create_window(0, 0, anchor='nw', window=frame)
                    canvas.update_idletasks()
                    canvas.configure(scrollregion=canvas.bbox('all'), 
                             yscrollcommand=scroll_y.set)

                    canvas.pack(fill='both', expand=True, side='left')
                    scroll_y.pack(fill='y', side='right')
                    ap_key_window_active =1
                #cfgfile = open("ECDSA_Key_info.ini",'w')
                #cfgfile.close()

            def on_configure(self):
            # update scrollregion after starting 'mainloop'
            # when all widgets are in canvas
                canvas.configure(scrollregion=canvas.bbox('all'))

            def browsefldr_2(self,ix):
                pathdir = os.getcwd()
                pathdir = pathdir+"\\"
                path = askopenfilename(initialdir=pathdir,
                                   filetypes =(("PEM File", "*.pem"),("All Files","*.*"))
                                   #title = "set path Openssl.exe"
                                   )
                path = "\\".join(path.split('/'))                   
                path = path.replace(pathdir,'')
                #text = self.entries_1[ix].get()
                #pvt_key = self.entries_1[ix].get()
                #print(text)
                #info = "entry ix=%d text=%s" % (ix, text)
                self.pub_entries_1[ix].delete(0, 'end')
                self.pub_entries_1[ix].insert('end', path)   

            def browsefldr_1(self,ix):
                global browse_flag
                pathdir = os.getcwd()
                pathdir = pathdir+"\\"
                path = askopenfilename(initialdir=pathdir,
                                   filetypes =(("PEM File", "*.pem"),("All Files","*.*"))
                                   #title = "set path Openssl.exe"
                                   )
                path = "\\".join(path.split('/'))                   
                path = path.replace(pathdir,'')
                #print("browsefldr_1 called ")
                #text = self.entries_1[ix].get()
                #pvt_key = self.entries_1[ix].get()
                #print(text)
                #info = "entry ix=%d text=%s" % (ix, text)
                self.entries_1[ix].delete(0, 'end')
                self.entries_1[ix].insert('end', path)    
                browse_flag = 1 

            def folder_create(self,dir_path):
                fldname = dir_path#self.outdir.get();
                if fldname == "":
                    cnt_time=datetime.datetime.now()
                    upd_time ='{0:%Y}{0:%m}{0:%d}_{0:%w}{0:%H%M%S}'.format(cnt_time)
                    fldname = "efuse\efuse_"+upd_time
                    cmd = "IF NOT EXIST "+fldname+" MD "+fldname  
                    op = os.system(cmd) 
                    #self.outdir.set(fldname)
                outkeydir=fldname+"\keys"
                cmd = "IF NOT EXIST "+outkeydir+" MD "+outkeydir  
                op = os.system(cmd) 
                buildbindir=fldname+"\out_binaries"
                cmd = "IF NOT EXIST "+buildbindir+" MD "+buildbindir  
                op = os.system(cmd) 

            def action2(self, ix, event):
                #print("action2")
                #print("Action1 fun called ")
                text = self.pub_entries_1[ix].get()
                pvt_key = self.pub_entries_1[ix].get()
                #print(text)
                #info = "entry ix=%d text=%s" % (ix, text)
                self.pub_entries_1[ix].delete(0, 'end')
                self.pub_entries_1[ix].insert('end', text)
                #print("actionw End")

            def action1(self, ix, event):
                #print("Action1 fun called ")
                text = self.entries_1[ix].get()
                pvt_key = self.entries_1[ix].get()
                #print("action1")
                #print("action1 End")
                #config.set('Person','Age', "50")


            def action(self, ix, event):
                #print("Action fun called ")
                text = self.entries[ix].get()
                #print(text)
                #info = "entry ix=%d text=%s" % (ix, text)
                self.entries[ix].delete(0, 'end')
                self.entries[ix].insert('end', text)

            def callbackFunc1(self, event):
                pass
                #print("AP_PUBcallbackFunc1")
                #for i in range(len(self.entries)):
                    #print(self.entries[i].get())
                # myrow = 1
                # myrow = myrow +1
                # with_extension = self.combo_1.get()
                # ap_pvt_key_name = "AP Pvt Key filename"+str(with_extension)
                # ap_pvt_key_name_1 = "AP Pub Key filename"+str(with_extension)
                # print(ap_pvt_key_name)
                # self.lbl_1.config(text = ap_pvt_key_name)
                #self.lbl_2.config(text = ap_pvt_key_name_1)
                # if self.combo_1.get() == "1":
                #   name1= self.pvtecdsakey.get()
                #   print("1 ",name1)
                #   self.pvtkey.append(name1)
                # if self.combo_1.get() == "2":
                #   name2= self.pvtecdsakey.get()
                #   print("2 ",name2)
                #   self.pvtkey.append(name2)

                #for i in range(len(self.pvtkey)):
                #   print(self.pvtkey[i])



            def clearcontent4(self, event):
                txfile = self.tx_file.get()
                if "NO TX" == txfile or "Please enter TX Filename" == txfile or "Enter Tx Key File path" == txfile :
                    self.tx_file.set("")

            def ap_pvt_key_hash(self, event):
                pvtecdsak_ = self.pvtecdsakey.get()
                # if self.combo_1.get() == "1":
                #   name1= self.pvtecdsakey.get()
                #   print("1 ",name1)
                #   self.pvtkey.append(name1)
                # if self.combo_1.get() == "2":
                #   name2= self.pvtecdsakey.get()
                #   print("2 ",name2)
                #   self.pvtkey.append(name2)

                #print(pvtecdsak_)
                #f = pvtecdsak_.find(",")
                #print (pvtecdsak_[f+1:])
                #format1 = ecdsak_.split(",")
                #print("The format of your file is: ",format1[-1])
                #print(ecdsak_[ecdsak_.index(',')+1:])
                #print(ecdsak_[ecdsak_.find(',')+1:])
                #finList[] = (ecdsak_) 
                #print(finList[0])
                #print(finList[1])
                if "NO ECDSA" == pvtecdsak_ or "Please enter Filename" == pvtecdsak_ or "Enter ECDSA Key filename to generate" == pvtecdsak_ :
                    self.pvtecdsakey.set("")

            def ap_pub_key_hash(self, event):
                ecdsak_ = self.ecdsakey.get()

            def hash_gen(self, event,text):
                #print("hash_gen")
                with open (text, "r") as myfile:
                    data = myfile.readlines()

                str1 = ''.join(data)
            
            def clearcontent5(self, event):
                tagadd = self.pubkeycount.get()

            def close_window(self):
                global txfile
                global ap_key_window_active
                global pvt_key
                conf_f = open("pvtfilecfg.ini","wt+") #as conf_f:  
                pub_conf_f = open("pubfilecfg.ini","wt+") #as conf_f:          

                cfgfile = open("ECDSA_Key_info.ini",'wt')
                for i in range(len(self.entries_1)):
                  text = self.entries_1[i].get()
                  #text = text+".pem"
                  config = configparser.SafeConfigParser()
                  ECKEY = "ECKEY "
                  ECKEY = ECKEY +'"%d"'%i
                  #print(ECKEY)
                  key_name = "ECDSAKeyfilename"
                  key_name_1 = "ECDSAKeyfilenamepass"
                  text_1 = self.pub_entries_1[i].get()
                  #print("key_name ",key_name)
                  config.add_section(ECKEY)
                  config.set(ECKEY,key_name,text)
                  config.set(ECKEY,key_name_1,text_1)
                  #print("text ",text)
                  config.write(cfgfile)
                  #cfgfile.close()

                #cfgfile.close()
                #cfgfile = open("ECDSA_Key_info.ini",'wt')
                #for i in range(len(self.pub_entries_1)):
                  # text = self.pub_entries_1[i].get()
                  # config = configparser.SafeConfigParser()
                  # ECKEY = "ECKEY "
                  # ECKEY = ECKEY +'"%d"'%i
                  # print(ECKEY)
                  # key_name = "ECDSAPubKeyfilename"+str(i)
                  # print("key_name ",key_name)
                  # config.add_section(ECKEY)
                  # config.set(ECKEY,key_name,text)
                  # print("text ",text)
                  # config.write(cfgfile)
                  #cfgfile.close()

                cfgfile.close()
                pvt_key = self.entries

                for i in range(len(self.entries)):
                    #print(self.entries[i].get())
                    conf_f.write(self.entries[i].get()+"\n")

                for i in range(len(self.entries_1)):
                    #print(self.entries_1[i].get())
                    pub_conf_f.write(self.entries_1[i].get()+"\n")            

                txfile =self.tx_file.get()
        #        with open("pvtfilecfg.ini","wt+") as conf_f:  
        #            conf_f.write(txfile)
                conf_f.close()
                pub_conf_f.close()
                global key_count 
                key_count = self.ecckeycount
                #print("gloabl vlaue key_count ",key_count)
                self.destroy()
                ap_key_window_active =0
                

            def browsepath(self):
                pathdir = os.getcwd()
                pathdir = pathdir+"\\"
                tx_file = askopenfilename(initialdir=pathdir,
                                   filetypes =(("hex File", "*.hex"),("All Files","*.*")),
                                   title = "set path tranport key file"
                                   )
                tx_file = "\\".join(tx_file.split('/'))
                self.tx_file.set(tx_file)
                self.flag = 1
                with open("pvtfilecfg.ini","wt+") as conf_f:  
                    conf_f.write(tx_file)
                conf_f.close()

            def quit(self):   
                #print("quiit winodw") 
                global ap_key_window_active
                self.destroy()
                ap_key_window_active =0

            def tx_config_ini(self):    
                conf_f = open("pvtfilecfg.ini","rt")
                for lines in conf_f:
                    self.tx_file.set(lines)

                
        class error_windox3(Frame):     
            def __init__(self):
                global error_windox3_flag
                if 0 == error_windox3_flag:
                     new =Frame.__init__(self)
                     new = Toplevel(self)
                     new.title("Data Entry Error Hexa value")
                     new.lbl = Label(new, text="Data is out of range").grid(column = 2,sticky=W+E, pady=0, padx=1)
                     new.lbl = Label(new, text="Expected range for Data").grid(column = 2,sticky=W+E, pady=0, padx=1)
                     new.lbl = Label(new, text=" Hex : 00-FF ").grid(column = 2,sticky=W+E, pady=0, padx=1)
                     new.button = Button( new, text = "OK", width = 25,
                                              command = self.close_window )
                     new.button.grid( column=2, sticky=W, pady=0, padx=1)
                     error_windox3_flag =1
                #if 1 ==error_windox3_flag:
                #     self.show_window()
                
            def close_window(self):
                global error_windox3_flag
                error_windox3_flag =0
                self.destroy()

            def show_window(self):
                #global rtnvalue
                global error_windox3_flag
                error_windox3_flag =0
                #self.wait_window() #wait for rtnvalue to be udpate from above comments
                #return rtnvalue
                self.destroy()
                
        class error_windox2(Frame):     
            def __init__(self):
                new =Frame.__init__(self)
                new = Toplevel(self)
                new.title("Data Entry Error Decimel value")
                new.lbl = Label(new, text="Data is out of range").grid(column = 2,sticky=W+E, pady=0, padx=1)
                new.lbl = Label(new, text="Expected range for Data").grid(column = 2,sticky=W+E, pady=0, padx=1)
                new.lbl = Label(new, text=" Dec : 0-255 ").grid(column = 2,sticky=W+E, pady=0, padx=1)
                new.button = Button( new, text = "OK", width = 25,
                                         command = self.close_window )
                new.button.grid( column=2, sticky=W, pady=0, padx=1)
                
            def close_window(self):
                self.destroy()
                
        class error_windox1(Frame):     
            def __init__(self):
                new =Frame.__init__(self)
                new = Toplevel(self)
                new.title("Index  Entry Error")
                new.lbl = Label(new, text="Index out of range").grid(column = 2,sticky=W+E, pady=0, padx=1)
                new.lbl = Label(new, text="Expected range for Index").grid(column = 2,sticky=W+E, pady=0, padx=1)
                new.lbl = Label(new, text="               Dec - 576 - 863 ").grid(column = 2,sticky=W+E, pady=0, padx=1)
                new.lbl = Label(new, text="               Hex -  240 - 35F ").grid(column = 2,sticky=W+E, pady=0, padx=1)
                #new.lbl = Label(new, text="               Dec - 480 - 991 ").grid(column = 2,sticky=W+E, pady=0, padx=1)
                #new.lbl = Label(new, text="               Hex -  1E0 - 3DF ").grid(column = 2,sticky=W+E, pady=0, padx=1)
                new.button = Button( new, text = "OK", width = 25,
                                         command = self.close_window )
                new.button.grid( column=2, sticky=W, pady=0, padx=1)
                
            def close_window(self):
                self.destroy()


        class custom_window(Frame):
            global otp_lock_15
            global otp_lock_16
            global otp_lock_17
            global otp_lock_18
            global otp_lock_19
            global otp_lock_20
            global otp_lock_21
            global otp_lock_22
            global otp_lock_23
            global otp_lock_24
            global otp_lock_25
            global otp_lock_26
            global otp_lock_27
            global otp_lock_28
            global otp_lock_29
            global otp_lock_30
            global otp_write_lock_en
            global write_lock_flag_15
            global write_lock_flag_16
            global write_lock_flag_17
            global write_lock_flag_18
            global write_lock_flag_19
            global write_lock_flag_20
            global write_lock_flag_21
            global write_lock_flag_22
            global write_lock_flag_23
            global write_lock_flag_24
            global write_lock_flag_25
            global write_lock_flag_26
            global write_lock_flag_27
            global write_lock_flag_28
            global write_lock_flag_29
            global write_lock_flag_30
            def __init__(self):
                new = Frame.__init__(self)
                new = Toplevel(self)
                #(FrameSizeX, FrameSizeY, FramePosX, FramePosY) = get_screen_resolution(new,0,0)
               #new.geometry("%dx%d+%d+%d" % (size + (x, y)))
                #geom1 ="400x70+"+FramePosX+"+"+FramePosY
                #new.geometry(geom1)
                new.title("Customer Use Region Write Lock settings")

                Label(new, text ="OTP Write Lock for the 'Customer Use' region !!!  ", fg="red", font=("Helvetica", 16)).grid(row=0,  column=1,sticky=W+E, pady=0, padx=1)
                Label(new,text ="For OTP Write lock of 'Customer Use' region, Use the below enable/disable selection. ").grid(row=1, column=1,sticky=W+E, pady=0, padx=1)

                new.protocol("WM_DELETE_WINDOW", self.on_closing_main)
                # if 1 == otp_lock_15:
                #     self.Writeval15 = IntVar()
                #     self.CB0 = Checkbutton(new, variable=self.Writeval15, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_15)
                #     self.CB0.grid(row=3, column = 0, sticky = E )
                #     Label(new, text="OTP Write Lock 1 : (Dec :(480-511) , Hex :(0x1E0-0x1FF))").grid(row=3, column = 1, sticky=W, pady=0, padx=1)
                #     self.Writeval15.set(write_lock_flag_15)

                        
                # if 1 == otp_lock_16:        
                #     self.Writeval16 = IntVar()
                #     self.CB1 = Checkbutton(new, variable=self.Writeval16, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_16)
                #     self.CB1.grid(row=4, column = 0, sticky = E )
                #     Label(new, text="OTP Write Lock 2 : (Dec :(512-543) , Hex :(0x200-0x21F))").grid(row=4, column = 1, sticky=W, pady=0, padx=1)
                #     self.Writeval16.set(write_lock_flag_16)

                # if 1 == otp_lock_17:       
                #     self.Writeval17 = IntVar()
                #     self.CB2 = Checkbutton(new, variable=self.Writeval17, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_17)
                #     self.CB2.grid(row=5, column = 0, sticky = E )
                #     Label(new, text="OTP Write Lock 3 : (Dec :(544-575) , Hex :(0x220-0x23F))").grid(row=5, column = 1, sticky=W, pady=0, padx=1)
                #     self.Writeval17.set(write_lock_flag_17)

                # if 1 == otp_lock_18:  
                #     self.Writeval18 = IntVar()
                #     self.CB3 = Checkbutton(new, variable=self.Writeval18, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_18)
                #     self.CB3.grid(row=6, column = 0, sticky = E )
                #     Label(new, text="OTP Write Lock 4 : (Dec :(576-607) , Hex :(0x240-0x25F))").grid(row=6, column = 1, sticky=W, pady=0, padx=1)
                #     self.Writeval18.set(write_lock_flag_18)

                # if 1 == otp_lock_19:  
                #     self.Writeval19 = IntVar()
                #     self.CB4 = Checkbutton(new, variable=self.Writeval19, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_19)
                #     self.CB4.grid(row=7, column = 0, sticky = E )
                #     Label(new, text="OTP Write Lock 5 : (Dec :(608-639) , Hex :(0x260-0x27F))").grid(row=7, column = 1, sticky=W, pady=0, padx=1)
                #     self.Writeval19.set(write_lock_flag_19)

                # if 1 == otp_lock_20:  
                #     self.Writeval20 = IntVar()
                #     self.CB5 = Checkbutton(new, variable=self.Writeval20, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_20)
                #     self.CB5.grid(row=8, column = 0, sticky = E )
                #     Label(new, text="OTP Write Lock 6 : (Dec :(640-671) , Hex :(0x280-0x29F))").grid(row=8, column = 1, sticky=W, pady=0, padx=1)
                #     self.Writeval20.set(write_lock_flag_20)

                if 1 == otp_lock_21:  
                    self.Writeval21 = IntVar()
                    self.CB6 = Checkbutton(new, variable=self.Writeval21, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_21)
                    self.CB6.grid(row=9, column = 0, sticky = E )
                    Label(new, text="OTP Write Lock 7 : (Dec :(672-703) , Hex :(0x2A0-0x2BF))").grid(row=9, column = 1, sticky=W, pady=0, padx=1)
                    self.Writeval21.set(write_lock_flag_21)

                if 1 == otp_lock_22:  
                    self.Writeval22 = IntVar()
                    self.CB7 = Checkbutton(new, variable=self.Writeval22, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_22)
                    self.CB7.grid(row=10, column = 0, sticky = E )
                    Label(new, text="OTP Write Lock 8 : (Dec :(704-735) , Hex :(0x2C0-0x2DF))").grid(row=10, column = 1, sticky=W, pady=0, padx=1)
                    self.Writeval22.set(write_lock_flag_22)

                if 1 == otp_lock_23:  
                    self.Writeval23 = IntVar()
                    self.CB8 = Checkbutton(new, variable=self.Writeval23, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_23)
                    self.CB8.grid(row=11, column = 0, sticky = E )
                    Label(new, text="OTP Write Lock 9 : (Dec :(736-767) , Hex :(0x2E0-0x2FF))").grid(row=11, column = 1, sticky=W, pady=0, padx=1)
                    self.Writeval23.set(write_lock_flag_23)
                    
                if 1 == otp_lock_24:  
                    self.Writeval24 = IntVar()
                    self.CB9 = Checkbutton(new, variable=self.Writeval24, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_24)
                    self.CB9.grid(row=12, column = 0, sticky = E )
                    Label(new, text="OTP Write Lock 10 : (Dec :(768-799) , Hex :(0x300-0x31F))").grid(row=12, column = 1, sticky=W, pady=0, padx=1)
                    self.Writeval24.set(write_lock_flag_24)

                if 1 == otp_lock_25:  
                    self.Writeval25 = IntVar()
                    self.CB10 = Checkbutton(new, variable=self.Writeval25, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_25)
                    self.CB10.grid(row=13, column = 0, sticky = E )
                    Label(new, text="OTP Write Lock 11 : (Dec :(800-831) , Hex :(0x320-0x33F))").grid(row=13, column = 1, sticky=W, pady=0, padx=1)
                    self.Writeval25.set(write_lock_flag_25)
                        
                if 1 == otp_lock_26:  
                    self.Writeval26 = IntVar()
                    self.CB11 = Checkbutton(new, variable=self.Writeval26, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_26)
                    self.CB11.grid(row=14, column = 0, sticky = E )
                    Label(new, text="OTP Write Lock 12 : (Dec :(832-863) , Hex :(0x340-0x35F))").grid(row=14, column = 1, sticky=W, pady=0, padx=1)
                    self.Writeval26.set(write_lock_flag_26)
                
                if 1 == otp_lock_27:  
                    self.Writeval27 = IntVar()
                    self.CB12 = Checkbutton(new, variable=self.Writeval27, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_27)
                    self.CB12.grid(row=15, column = 0, sticky = E )
                    Label(new, text="OTP Write Lock 13 : (Dec :(864-895) , Hex :(0x360-0x37F))").grid(row=15, column = 1, sticky=W, pady=0, padx=1)
                    self.Writeval27.set(write_lock_flag_27)

                if 1 == otp_lock_28:  
                    self.Writeval28 = IntVar()
                    self.CB13 = Checkbutton(new, variable=self.Writeval28, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_28)
                    self.CB13.grid(row=16, column = 0, sticky = E )
                    Label(new, text="OTP Write Lock 14 : (Dec :(896-927) , Hex :(0x380-0x39F))").grid(row=16, column = 1, sticky=W, pady=0, padx=1)
                    self.Writeval28.set(write_lock_flag_28)

                if 1 == otp_lock_29:  
                    self.Writeval29 = IntVar()
                    self.CB14 = Checkbutton(new, variable=self.Writeval29, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_29)
                    self.CB14.grid(row=17, column = 0, sticky = E )
                    Label(new, text="OTP Write Lock 15 : (Dec :(928-959) , Hex :(0x3A0-0x3BF))").grid(row=17, column = 1, sticky=W, pady=0, padx=1)
                    self.Writeval29.set(write_lock_flag_29)

                if 1 == otp_lock_30:  
                    self.Writeval30 = IntVar()
                    self.CB15 = Checkbutton(new, variable=self.Writeval30, onvalue = 1, offvalue = 0, command=self.Write_loc_sel_30)
                    self.CB15.grid(row=18, column = 0, sticky = E )
                    Label(new, text="OTP Write Lock 16 : (Dec :(960-991) , Hex :(0x3C0-0x3DF))").grid(row=18, column = 1, sticky=W, pady=0, padx=1)
                    self.Writeval30.set(write_lock_flag_30)

                new.button = Button( new, text = "OK", width = 25,command = self.close_window_1 )
                new.button.grid(row=19, column=1, sticky=W+E, pady=0, padx=1)
                self.wait_window()

            def Write_loc_sel_15(self):
                val = self.Writeval15.get()
                global write_lock_flag_15
                if 1 == val:
                    write_lock_flag_15 =1
                else:
                    write_lock_flag_15 =0

            def Write_loc_sel_16(self):
                val = self.Writeval16.get()
                global write_lock_flag_16
                if 1 == val:
                    write_lock_flag_16 =1
                else:
                    write_lock_flag_16 =0
                
            def Write_loc_sel_17(self):
                val = self.Writeval17.get()
                global write_lock_flag_17
                if 1 == val:
                    write_lock_flag_17 =1
                else:
                    write_lock_flag_17 =0
                
            def Write_loc_sel_18(self):
                val = self.Writeval18.get()
                global write_lock_flag_18
                if 1 == val:
                    write_lock_flag_18 =1
                else:
                    write_lock_flag_18 =0
                
            def Write_loc_sel_19(self):
                val = self.Writeval19.get()
                global write_lock_flag_19
                if 1 == val:
                    write_lock_flag_19 =1
                else:
                    write_lock_flag_19 =0

            def Write_loc_sel_20(self):
                val = self.Writeval20.get()
                global write_lock_flag_20
                if 1 == val:
                    write_lock_flag_20 =1
                else:
                    write_lock_flag_20 =0
                
            def Write_loc_sel_21(self):
                val = self.Writeval21.get()
                global write_lock_flag_21
                if 1 == val:
                    write_lock_flag_21 =1
                else:
                    write_lock_flag_21 =0
                
            def Write_loc_sel_22(self):
                val = self.Writeval22.get()
                global write_lock_flag_22
                if 1 == val:
                    write_lock_flag_22 =1
                else:
                    write_lock_flag_22 =0
            
            def Write_loc_sel_23(self):
                val = self.Writeval23.get()
                global write_lock_flag_23
                if 1 == val:
                    write_lock_flag_23 =1
                else:
                    write_lock_flag_23 =0

            def Write_loc_sel_24(self):
                val = self.Writeval24.get()
                global write_lock_flag_24
                if 1 == val:
                    write_lock_flag_24 =1
                else:
                    write_lock_flag_24 =0
                    
            def Write_loc_sel_25(self):
                val = self.Writeval25.get()
                global write_lock_flag_25
                if 1 == val:
                    write_lock_flag_25 =1
                else:
                    write_lock_flag_25 =0

            def Write_loc_sel_26(self):
                val = self.Writeval26.get()
                global write_lock_flag_26
                if 1 == val:
                    write_lock_flag_26 =1
                else:
                    write_lock_flag_26 =0
                    
            def Write_loc_sel_27(self):
                val = self.Writeval27.get()
                global write_lock_flag_27
                if 1 == val:
                    write_lock_flag_27 =1
                else:
                    write_lock_flag_27 =0
                    
            def Write_loc_sel_28(self):
                val = self.Writeval28.get()
                global write_lock_flag_28
                if 1 == val:
                    write_lock_flag_28 =1
                else:
                    write_lock_flag_28 =0

            def Write_loc_sel_29(self):
                val = self.Writeval29.get()
                global write_lock_flag_29
                if 1 == val:
                    write_lock_flag_29 =1
                else:
                    write_lock_flag_29 =0

            def Write_loc_sel_30(self):
                val = self.Writeval30.get()
                global write_lock_flag_30
                if 1 == val:
                    write_lock_flag_30 =1
                else:
                    write_lock_flag_30 =0

            def close_window_1(self):
                global ref_active
                global write_lock_flag_15
                global write_lock_flag_16
                global write_lock_flag_17
                global write_lock_flag_18
                global write_lock_flag_19
                global write_lock_flag_20
                global write_lock_flag_21
                global write_lock_flag_22
                global write_lock_flag_23
                global write_lock_flag_24
                global write_lock_flag_25
                global write_lock_flag_26
                global write_lock_flag_27
                global write_lock_flag_28
                global write_lock_flag_29
                global write_lock_flag_30
                if (write_lock_flag_15 or write_lock_flag_16 or write_lock_flag_17 or write_lock_flag_18 or write_lock_flag_19 or write_lock_flag_20 or write_lock_flag_21
                    or write_lock_flag_22 or write_lock_flag_23 or write_lock_flag_24 or write_lock_flag_25 or write_lock_flag_26 or write_lock_flag_27 or write_lock_flag_28
                    or write_lock_flag_29 or write_lock_flag_30):
                    messagebox.showinfo('Customer Region OTP Write Lock selected in window', 'OTP write lock bit is enabled for the programmed customer region in the prevoius setting window & Data can be view in the view window')
                else:
                    messagebox.showinfo('Customer Region OTP Write Lock not selected in window', 'OTP write lock bit  is not selected for the selected customer region in the prevoius setting window & Data can be view in the view window')
                    

                if (0 == ref_active):
                    view_windox() 

                self.destroy()
                
            def on_closing_main(self):
                 global otp_lock_15
                 global otp_lock_16
                 global otp_lock_17
                 global otp_lock_18
                 global otp_lock_19
                 global otp_lock_20
                 global otp_lock_21
                 global otp_lock_22
                 global otp_lock_23
                 global otp_lock_24
                 global otp_lock_25
                 global otp_lock_26
                 global otp_lock_27
                 global otp_lock_28
                 global otp_lock_29
                 global otp_lock_30
                 global otp_write_lock_en
                 global write_lock_flag_15
                 global write_lock_flag_16
                 global write_lock_flag_17
                 global write_lock_flag_18
                 global write_lock_flag_19
                 global write_lock_flag_20
                 global write_lock_flag_21
                 global write_lock_flag_22
                 global write_lock_flag_23
                 global write_lock_flag_24
                 global write_lock_flag_25
                 global write_lock_flag_26
                 global write_lock_flag_27
                 global write_lock_flag_28
                 global write_lock_flag_29
                 global write_lock_flag_30

                 global setting_win_flag
                 global cust_enter_var

                 write_lock_flag_15 = 0
                 write_lock_flag_16 = 0
                 write_lock_flag_17 = 0
                 write_lock_flag_18 = 0
                 write_lock_flag_19 = 0
                 write_lock_flag_20 = 0
                 write_lock_flag_21 = 0
                 write_lock_flag_22 = 0
                 write_lock_flag_23 = 0
                 write_lock_flag_24 = 0
                 write_lock_flag_25 = 0
                 write_lock_flag_26 = 0
                 write_lock_flag_27 = 0
                 write_lock_flag_28 = 0
                 write_lock_flag_29 = 0
                 write_lock_flag_30 = 0

                 otp_lock_15 = 0
                 otp_lock_16 = 0
                 otp_lock_17 = 0
                 otp_lock_18 = 0
                 otp_lock_19 = 0
                 otp_lock_20 = 0
                 otp_lock_21 = 0
                 otp_lock_22 = 0
                 otp_lock_23 = 0
                 otp_lock_24 = 0
                 otp_lock_25 = 0 
                 otp_lock_26 = 0
                 otp_lock_27 = 0
                 otp_lock_28 = 0
                 otp_lock_29 = 0
                 otp_lock_30 = 0
                 otp_write_lock_en = 0
              
                 setting_win_flag = 0
                 cust_enter_var = 0

                 global generate_efuse_data
                 generate_efuse_data =0
                 self.destroy()
                
        class view_windox(Frame):     
            def __init__(self):
                global custom_data
                global refWin
                global ref_active
                if (0 == ref_active):
                    new = Frame.__init__(self)
                    new = Toplevel(self)
                    (FrameSizeX, FrameSizeY, FramePosX, FramePosY) = get_screen_resolution(new,0,0)
                    #new.geometry("%dx%d+%d+%d" % (size + (x, y)))
                    geom1 ="480x550+"+FramePosX+"+"+FramePosY
                    new.geometry(geom1)
                    new.title("Custom Data view Window")
                    S = Scrollbar(new)
                    refWin = Text(new)
                    refWin.pack(side=RIGHT, fill=Y, expand=False)
                    refWin.pack( fill=BOTH, expand=True)
                    ##refWin=Label(new,text='Refresh')
                    #refWin = Text(new)
                    refWin.config(yscrollcommand=S.set)
                    #refWin.pack()
                    new.wm_protocol ("WM_DELETE_WINDOW", self.close_window) 
                    S.config(command=refWin.yview)
                    #new.button = Button( new, text = "Exit", width = 25,
                    #                         command = self.close_window )
                    #new.button.pack(side="bottom") 
                    self.Refresher()
                    ref_active = 1
                    self.wait_window()

                
            def Refresher(self):
                global custom_data
                global refWin
                global cust_content
                if custom_data == []:
                    self.close_window()
                else:
                    content_of_file = "Offset | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
                    content_of_file = content_of_file + "--------------------------------------------------------\n"
                    row = cnt1 = 0
                    offse = 0x240#2A0#0x1E0 #0xC0            
                    row_cnt = hex(offse).upper().split('X')[1].zfill(3) + "   |"
                    for cnt in custom_data:    
                        val = ((int(binascii.hexlify(cnt), 16)) & 0x03FFFFFF )#0xFF0100FF)
                      #  val = "IDX = "+hex((val >> 24 | ((val >> 8) & 0x100)) & 0x1FF).upper()+" Data = "+hex((val >> 8 ) & 0xFF).upper()
                        val = hex((val >> 8 ) & 0xFF).upper().split('X')[1].zfill(2)
                        if cnt1 > 15:
                            content_of_file = content_of_file +" "+ row_cnt + "\n"
                            row = row + 1
                            offse = 0x240 + row*cnt1#0x1E0 + row*cnt1 #0xC0 + row*cnt1
                            cnt1 = 1
                            row_cnt = hex(offse).upper().split('X')[1].zfill(3) + "   | " + val
                        else:
                            row_cnt = row_cnt + " " + val
                            cnt1 = cnt1 + 1
                            
                    content_of_file = content_of_file +" "+ row_cnt
                    #refWin.config(text=content_of_file)
                    refWin.delete(1.0, END)
                    refWin.insert(END, content_of_file)
                    cust_content = content_of_file

                    self.after(1000, self.Refresher) # every second..
            def close_window(self):
                global ref_active
                ref_active = 0
                self.destroy()
                    
                
        class help_windox(Frame):     
            def __init__(self):
                global help_active
                if 0 == help_active:
                    new =Frame.__init__(self)
                    new = Toplevel(self)
                    new.title("Help Window")
                    content_of_file = ""
                    cmd = "attrib -R /s"
                    op = os.system(cmd) 
                    try:
                        with open("Help.txt","rt+") as help_f:
                            for lines in help_f:    
                                content_of_file = content_of_file + lines
                    except:
                        return
                  #  new.msg = Message(new, text=content_of_file)
                  #  new.msg.pack()
                    S = Scrollbar(new)
                    T = Text(new)
                    S.pack(side=RIGHT, fill=Y, expand=False)
                    T.pack( fill=BOTH, expand=True)
                    S.config(command=T.yview)
                    T.config(yscrollcommand=S.set)
                    T.insert(END, content_of_file)
                    new.wm_protocol ("WM_DELETE_WINDOW", self.quit)
                    help_f.close()       
                    new.button = Button( new, text = "OK", width = 25,
                                             command = self.close_window )
                    new.button.pack(side="bottom") 
                    help_active = 1
            def close_window(self):
                global help_active
                self.destroy()
                help_active  =0
            def quit(self):
                global help_active
                #print("close")
                self.destroy()
                help_active  =0
                
        class warning_windox(Frame):     
            def __init__(self):
                global rtnvalue
                global warning_main_wind_flag
                new =Frame.__init__(self)
                new = Toplevel(self)
                (FrameSizeX, FrameSizeY, FramePosX, FramePosY) = get_screen_resolution(new, -80,-200)
                #new.geometry("%dx%d+%d+%d" % (size + (x, y)))
                geom1 ="500x600+"+FramePosX+"+"+FramePosY
                new.geometry(geom1)
                new.title("Warning!!")
                global pathfilename
                content_of_file = ""
                Label(new, text ="Warning!!!", fg="red", font=("Helvetica", 16)).grid(row=0,  column=1,sticky=W+E, pady=0, padx=1)
                Label(new,text ="It's a One Time Programming").grid(row=1, column=1,sticky=W+E, pady=0, padx=1)
                Label(new,text ="Make sure all informations are correct").grid(row=2, column=1,sticky=W+E, pady=0, padx=1)
                with open(pathfilename,"rt+") as help_f:
                    once = True
                    rowcnt = 6
                    for lines in help_f:    
                        if True == once:
                            once = False
                        else:    
                            content_of_file = content_of_file + lines
                new.msg = Message(new, text=content_of_file)
                new.msg.grid(row=4, column=1,sticky=W, columnspan=3, rowspan=1,)
                help_f.close()       
                new.button = Button( new, text = "Continue", fg="Green", bg="white",width = 7,
                                         command = self.cont_window )
                new.button1 = Button( new, text = "Quit",fg="Red", bg="white",width = 7,
                                         command = self.quit_window )                                 
                new.button.grid(row=0,  column=3,sticky=W, pady=0, padx=1)
                new.button1.grid(row=0,  column=0,sticky=E, pady=0, padx=1)
                new.protocol("WM_DELETE_WINDOW", self.on_closing_main)
                warning_main_wind_flag =1

            def on_closing_main(self):
                global rtnvalue
                global warning_main_wind_flag
                warning_main_wind_flag = 0
                rtnvalue = 0
                self.destroy()
                
            def cont_window(self):
                global rtnvalue
                global warning_main_wind_flag
                warning_main_wind_flag =1
                rtnvalue = 1    
                self.destroy() 
                
            def quit_window(self):
                global rtnvalue
                global warning_main_wind_flag
                warning_main_wind_flag =1
                rtnvalue = 0
                self.destroy() 
                
            def show(self):
                global rtnvalue
                self.wait_window() #wait for rtnvalue to be udpate from above comments
                return rtnvalue
                 
        class Done_windox(Frame):     
            def __init__(self):
                new =Frame.__init__(self)
                new = Toplevel(self)
                (FrameSizeX, FrameSizeY, FramePosX, FramePosY) = get_screen_resolution(new, -335, -220)
                #new.geometry("%dx%d+%d+%d" % (size + (x, y)))
                geom1 ="120x50+"+FramePosX+"+"+FramePosY
                new.geometry(geom1)
                #new.geometry("120x50+960+540")
                new.title("Done")
                new.lbl = Label(new, text="Generated Efuse files ").grid(column = 2,sticky=W+E, pady=0, padx=1)
                new.button = Button( new, text = "OK", width = 15,
                                         command = self.close_window )
                new.button.grid(row=1, column=2, sticky=W, pady=0, padx=1)

            def close_window(self):
                self.destroy()    
                
        class error_windox(Frame):     
            def __init__(self):
                global message
                global msgidx
                new =Frame.__init__(self)
                new = Toplevel(self)
                new.title("Error")
                new.lbl = Label(new, text=message[msgidx]).grid(column = 2,sticky=W+E, pady=0, padx=1)
                new.button = Button( new, text = "OK", width = 25,
                                         command = self.close_window )
                new.button.grid(row=1, column=2, sticky=W, pady=0, padx=1)
            def close_window(self):
                self.destroy()
                
        class settings_windox(Frame):     
            def __init__(self):
                global setting_win_flag
                global settings_windox_browse_flag
                if 0 == setting_win_flag:
                     new =Frame.__init__(self)
                     new = Toplevel(self)
                     new.title("Settings")
                     global headerflag
                     global sqtpflag
                     global warningMSG
                     
                     filebswr=Label(new, text="Openssl Path").grid(sticky=W, pady=0, padx=1)
                     self.opensslpath=StringVar()

                     if ""==self.opensslpath.get():
                         self.chk_config_ini()
                     pathbar=Entry(new)
                     pathbar.grid(row=0,  column=1, columnspan=4, sticky=W+E, ipady=0, ipadx=40)
                     pathbar["textvariable"] = self.opensslpath
                     pathbar.bind("<Enter>")
                     
                     new.bbutton= Button(new, text="Browse", command=self.browsepath)
                     new.bbutton.grid(row=0, column=3, sticky=W, pady=0, padx=1)
                     
                     self.HDRval = IntVar()
                     self.CB7 = Checkbutton(new, variable=self.HDRval, onvalue = 1, offvalue = 0, command=self.HDRsel)
                     self.CB7.grid(row=1, column = 0, sticky = E )
                     Label(new, text="Generate Header File").grid(row=1, column = 1, sticky=W, pady=0, padx=1)
                     self.HDRval.set(headerflag)
                     
                     
                     self.WRNval = IntVar()
                     self.CB8 = Checkbutton(new, variable=self.WRNval, onvalue = 1, offvalue = 0, command=self.WARsel)
                     self.CB8.grid(row=2, column = 0, sticky = E )
                     Label(new, text="Disable Warning message").grid(row=2, column = 1, sticky=W, pady=0, padx=1)
                     self.WRNval.set(warningMSG)
                     
                     self.SQTPval = IntVar()
                     self.CB9 = Checkbutton(new, variable=self.SQTPval, onvalue = 1, offvalue = 0, command=self.SQTPsel)
                     self.CB9.grid(row=3, column = 0, sticky = E )
                     Label(new, text="Generate SQTP File").grid(row=3, column = 1, sticky=W, pady=0, padx=1)
                     self.SQTPval.set(sqtpflag)
                     
                     new.button = Button( new, text = "OK", width = 25,
                                              command = self.close_window )
                     new.button.grid(row=4, column=1, sticky=W+E, pady=0, padx=1)
                     setting_win_flag =2
                
            def SQTPsel(self):
                global sqtpflag
                sqtp = self.SQTPval.get()
                if True == sqtp:
                    sqtpflag = 1
                    sqtpHdrCfg()
                else:
                    sqtpflag = 0
           

            def HDRsel(self):
                global headerflag
                hdr = self.HDRval.get()
                if True == hdr:
                    headerflag = 1
                else:
                    headerflag = 0
            def WARsel(self):
                global warningMSG
                wrn = self.WRNval.get()
                if True == wrn:
                    warningMSG = 1
                else:
                    warningMSG = 0
            def close_window(self):
                global setting_win_flag
                global settings_windox_browse_flag
                settings_windox_browse_flag =0
                setting_win_flag = 1
                self.destroy()
                
            def browsepath(self):
                global settings_windox_browse_flag
                if 0 == settings_windox_browse_flag:
                     try:
                          settings_windox_browse_flag = 1
                          pathdir = os.getcwd()
                          pathdir = pathdir+"\\"
                          opensslpath = askopenfilename(initialdir=pathdir,
                                             filetypes =(("exe File", "*.exe"),("All Files","*.*")),
                                             title = "set path Openssl.exe"
                                             )
                          opensslpath = "\\".join(opensslpath.split('/'))                   
                          opensslpath = opensslpath.replace(pathdir,'')
                          self.opensslpath.set(opensslpath)     
                          with open("opensslcfg.ini","wt+") as conf_f:  
                              conf_f.write(opensslpath)
                          conf_f.close()
                          settings_windox_browse_flag = 0
                     except:
                          settings_windox_browse_flag =0
                          self.destroy()
            def chk_config_ini(self):    
                try:
                    conf_f = open("opensslcfg.ini","rt")   
                    for lines in conf_f:
                        if lines == "":
                            self.opensslpath.set("Choose OpenSSL path")
                            return
                        self.opensslpath.set(str(lines))
                except:
                    self.opensslpath.set("Choose OpenSSL path")        

        class sqtpHdrCfg(Frame):     
            def __init__(self):
                global message
                global msgidx
                global MaskVal
                global PatternVal
                global TypeVal
                new =Frame.__init__(self)
                new = Toplevel(self)
                self.sqtpmask=StringVar()
                self.sqtppattern=StringVar()
                self.sqtptype=StringVar()
                new.title("SQTP Header Config")
                rowidx = 0
                # new.lbl = Label(new, text="Mask").grid(row=rowidx, sticky=W, pady=0, padx=1)
                # self.sqtpmaskbar=Entry(new)
                # self.sqtpmaskbar.grid(row=rowidx, column=1,sticky=W+E)
                # self.sqtpmaskbar["textvariable"] = self.sqtpmask
                # if "" != MaskVal:   
                #     self.sqtpmask.set(MaskVal)
                # rowidx = rowidx + 1
                # new.lbl = Label(new, text="Pattern").grid(sticky=W, pady=0, padx=1)
                # self.sqtppatternbar=Entry(new)
                # self.sqtppatternbar.grid(row=rowidx, column=1,sticky=W+E)
                # self.sqtppatternbar["textvariable"] = self.sqtppattern
                # if "" != PatternVal:   
                #     self.sqtppattern.set(PatternVal)
                # rowidx = rowidx + 1
                new.lbl = Label(new, text="Type").grid(sticky=W, pady=0, padx=1)
                self.sqtptypebar=Entry(new)
                self.sqtptypebar.grid(row=rowidx, column=1,sticky=W+E)
                self.sqtptypebar["textvariable"] = self.sqtptype
                if ""==self.sqtptype.get():
                    self.sqtptype.set('s')
                    TypeVal = self.sqtptype.get()
                rowidx = rowidx + 1
                new.button = Button( new, text = "OK", width = 25,
                                         command = self.close_window )
                new.button.grid(row=rowidx, column=1,sticky=N+S)
            def close_window(self):
                global MaskVal
                global PatternVal
                global TypeVal
                MaskVal = self.sqtpmask.get()   
                PatternVal = self.sqtppattern.get()
                TypeVal = self.sqtptype.get()
                self.destroy()
                
        def get_screen_resolution(self, frameX, frameY):
            '''
            w = new.winfo_screenwidth()
            h = new.winfo_screenheight()
            size = tuple(int(_) for _ in new.geometry().split('+')[0].split('x'))
            x = w/2 - size[0]/2
            y = h/2 - size[1]/2
            toplevel.geometry("%dx%d+%d+%d" % (size + (x, y)))
            '''
            ScreenSizeX = self.winfo_screenwidth()  # Get screen width [pixels]
            ScreenSizeY = self.winfo_screenheight() # Get screen height [pixels]
            ScreenRatio = 1                            # Set the screen ratio for width and height
            FrameSizeX  = int(ScreenSizeX * ScreenRatio)/4+ frameX
            FrameSizeY  = int(ScreenSizeY * ScreenRatio)/2+ frameY
            FramePosX   = (ScreenSizeX - FrameSizeX)/2# Find left and up border of window
            FramePosY   = (ScreenSizeY - FrameSizeY)/2
            FramePosX   = str(FramePosX)
            FramePosY   = str(FramePosY)
            #geom = "%sx%s+%s+%s"%(FrameSizeX,FrameSizeY,FramePosX,FramePosY)
            FrameSizeX = "%s"%(FrameSizeX)
            lenx = len(FrameSizeX)
            FrameSizeX = FrameSizeX[:lenx-2]
            FrameSizeY = "%s"%(FrameSizeY)
            leny = len(FrameSizeY)
            FrameSizeY = FrameSizeY[:lenx-2]    
            FramePosX = "%s"%(FramePosX.split(".")[0])
            lenx = len(FramePosX)
            FramePosX = FramePosX#[:lenx-2]
            FramePosY = "%s"%(FramePosY.split(".")[0])
            lenx = len(FramePosY)
            FramePosY = FramePosY#[:lenx-2]
            return (FrameSizeX, FrameSizeY, FramePosX, FramePosY)

def folder_create():
        fldname = "";
        if fldname == "":
            cnt_time = datetime.datetime.now()
            upd_time = '{0:%Y}{0:%m}{0:%d}_{0:%w}{0:%H%M%S}'.format(cnt_time)
            if platform.system() =='Windows':
                fldname = "efuse\efuse_" + upd_time
                cmd = "IF NOT EXIST " + fldname + " MD " + fldname
                op = os.system(cmd)
            else:
                fldname = "efuse/efuse_"+upd_time
                cmd = "mkdir "+fldname  
                op = os.system(cmd) 
            # self.outdir.set(fldname)
        if platform.system() =='Windows':
            outkeydir = fldname + "\keys"
            cmd = "IF NOT EXIST " + outkeydir + " MD " + outkeydir
            op = os.system(cmd)
            buildbindir = fldname + "\out_binaries"
            cmd = "IF NOT EXIST " + buildbindir + " MD " + buildbindir
            op = os.system(cmd)
        else:
            outkeydir=fldname+"/keys"
            cmd = " mkdir "+outkeydir
            op = os.system(cmd) 
            buildbindir=fldname+"/out_binaries"
            cmd = " mkdir "+buildbindir
            op = os.system(cmd) 
        return fldname

def generatesqtpfile(fldloc):    
        global MaskVal
        global PatternVal
        global TypeVal    
        #fldloc = self.outdir.get()
        #fldloc = "/".join(fldloc.split('\\')) 
        dirpath=fldloc+"/out_binaries/efuse.bin" 
        sqtppath=fldloc+"/out_binaries/sqtpfile.txt" 
        efuse_file = open(dirpath,"rb")
        efuse_file.seek(0)
        efuse_data =efuse_file.read()
        with open(sqtppath,"wt+") as in_file:
            in_file.write("<header>\n")
            in_file.write("mask,"+MaskVal+"\n")
            in_file.write("pattern,"+PatternVal+"\n")
            in_file.write("type,"+TypeVal+"\n")
            in_file.write("</header>\n")
            in_file.write("<data>\n")
            cnt = idx = dat = incnt = outcnt = 0
            buffer = []
            for indx in range(0, 1024):
                dat = 0
                dat = hex(dat).zfill(2).split("x")[1].upper()
                buffer.append(dat)
                
            for items in efuse_data:
                if 0 == cnt:
                    idx = items
                if 1 == cnt:    
                    idx = idx + (items << 8)
                if 2 == cnt:  
                    dat = items
                    dat = hex(dat).zfill(2).split("x")[1].upper()
                #if 3 == cnt:  
                    if 57005 == idx:#DEAD
                        break
                    else:
                        if idx >= 0 and idx <= 1024:#512:
                            del buffer[idx]
                            buffer.insert(idx,dat ) 
                    cnt = 0
                else:
                    cnt = cnt + 1
            dat = ""
            for items in buffer:
                dat = dat + str(items).zfill(2)
                if 28 == outcnt:
                    if (15 == incnt):
                        dat =dat+"\n"
                        in_file.write(dat)
                        dat = ""
                        incnt = 0
                        outcnt = outcnt +1
                    else:
                        incnt = incnt +1

                else:
                    if (35 == incnt):
                        dat =dat+"\\"+"\n"
                        in_file.write(dat)
                        dat = ""
                        incnt = 0
                        outcnt = outcnt +1
                    else:
                        incnt = incnt +1
                            
                if 30 == outcnt:
                    in_file.write(dat)
                    break
       
            in_file.write("</data>\n")
        in_file.close    
        efuse_file.close
def otp_verifier(fldloc):    
        #global MaskVal
        #global PatternVal
        #global TypeVal    
        #fldloc = self.outdir.get()
        #fldloc = "/".join(fldloc.split('\\')) 
        cnt = idx = dat = incnt = outcnt = 0
        dirpath=fldloc+"/out_binaries/efuse.bin" 
        sqtppath=fldloc+"/out_binaries/otp_dump.log" 
        efuse_file = open(dirpath,"rb")
        efuse_file.seek(0)
        efuse_data =efuse_file.read()
        #print("efuse_data ",efuse_data)
        in_file = open(sqtppath,"wt+")
        print("******** OTP  DUMPT value and is available in the otp_dump.log ************\n")
        #in_file.write("******** OTP  DUMPT value ************")
        in_file.write("\n")    
        for items in efuse_data:
            if 0 == cnt:
                idx = items 
            if 1 == cnt:    
                idx = idx + (items << 8)
            if 2 == cnt:  
                dat = items
                if 57005 == idx:#DEAD
                    break
                incnt = incnt +1
                #if (idx ) 
                #print("OTP Offset  =0x",idx,"OTP Value  =0x",hex(dat))   
                cnt = "OTP Offset(dec)  = "+ str(idx) +" Offset(hex) =" +hex(idx)
                in_file.write(cnt)    
                cnt = "OTP Value  ="+hex(dat)
                in_file.write(cnt)    
                in_file.write(" \n")
                cnt =0 
                if ( 8== incnt):
                    outcnt = outcnt + incnt
                    incnt = 0
            else:
                cnt = cnt + 1            
        outcnt = outcnt + incnt 
           
        
        #in_file.write("</data>\n")
        in_file.close    
        efuse_file.close

def generateheader(fldloc):
    #fldloc = folder_create()
    #fldloc = "/".join(fldloc.split('\\'))
    dirpath = fldloc + "/out_binaries/efuse.bin"
    headpath = fldloc + "/out_binaries/otp_data.h"
    efuse_file = open(dirpath, "rb")
    efuse_file.seek(0)
    efuse_data = efuse_file.read()

    with open(headpath, "wt+") as in_file:

        cnt = idx = dat = incnt = outcnt = 0
        in_file.write("/***************************************************************************** \n")
        in_file.write("* Copyright 2018 Microchip Technology Inc. and its subsidiaries.               \n")
        in_file.write("* You may use this software and any derivatives exclusively with               \n")
        in_file.write("* Microchip products.                                                          \n")
        in_file.write("* THIS SOFTWARE IS SUPPLIED BY MICROCHIP 'AS IS'.                              \n")
        in_file.write("* NO WARRANTIES, WHETHER EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE,\n")
        in_file.write("* INCLUDING ANY IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY,       \n")
        in_file.write("* AND FITNESS FOR A PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP      \n")
        in_file.write("* PRODUCTS, COMBINATION WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.    \n")
        in_file.write("* IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,    \n")
        in_file.write("* INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND        \n")
        in_file.write("* WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS    \n")
        in_file.write("* BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.              \n")
        in_file.write("* TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL     \n")
        in_file.write("* CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF     \n")
        in_file.write("* FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.    \n")
        in_file.write("* MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE          \n")
        in_file.write("* OF THESE TERMS.                                                              \n")
        in_file.write("*****************************************************************************/ \n")
        in_file.write("                                                                               \n")
        in_file.write("/** @file efuse_data.h                                                         \n")
        in_file.write(" *EVERGLADES efuse_data                                                        \n")
        in_file.write(" */                                                                            \n")
        in_file.write("/** @defgroup EVERGLADES efuse_data                                            \n")
        in_file.write(" */                                                                            \n")
        in_file.write("#ifndef _EFUSE_DATA_H                                                          \n")
        in_file.write("#define _EFUSE_DATA_H                                                          \n")
        in_file.write("typedef unsigned          char uint8_t;                                        \n")
        in_file.write("typedef unsigned short    int uint16_t;                                       \n")
        in_file.write("                                                                               \n")
        in_file.write("typedef struct efuse_table_define {                                            \n")
        in_file.write("    uint16_t index;                                                            \n")
        in_file.write("    uint8_t value;                                                             \n")
        in_file.write("} _EFUSE_TBLE_DFE_;                                                            \n")
        in_file.write("                                                                               \n")
        in_file.write("const _EFUSE_TBLE_DFE_ device_efuse_table_ [] = {\n")

        message = ""
        in_file.write("    ")
        for items in efuse_data:
            if 0 == cnt:
                idx = items
            if 1 == cnt:
                idx = idx + (items << 8)
            if 2 == cnt:
                dat = items
                # if 3 == cnt:
                if 57005 == idx:  # DEAD
                    message = "{0xDEAD,0xFF}, "
                else:
                    if idx == 9 or idx == 8:
                        message = "{" + str(idx) + ", " + hex(dat).zfill(2) + "}, "
                    else:
                        message = "{" + str(idx).zfill(2) + ", " + hex(dat).zfill(2) + "}, "
                in_file.write(message)
                incnt = incnt + 1
                cnt = 0
                if (8 == incnt):
                    in_file.write("\n    ")
                    message = ""
                    outcnt = outcnt + incnt
                    incnt = 0
            else:
                cnt = cnt + 1
        outcnt = outcnt + incnt

        message = "{00, 0x00}, "
        for idx in range(outcnt, 1024):
            if (8 == incnt):
                in_file.write("\n    ")
                incnt = 0
            in_file.write(message)
            incnt = incnt + 1
        message = "{0xDEAD,0xFF}     //terminator\n"
        in_file.write(message)
        in_file.write("};                                                                             \n")
        in_file.write("                                                                               \n")
        in_file.write("#define TOTAL_SIZE sizeof(device_efuse_table_)/sizeof(device_efuse_table_[0]); \n")
        in_file.write("#endif                                                                         \n")
        in_file.write("/* end efuse_data.h */                                                         \n")
        in_file.write("/**   @}                                                                       \n")
        in_file.write(" */                                                                            \n")
    in_file.close
    efuse_file.close

def generateheader(fldloc):
    #fldloc = folder_create()
    #fldloc = "/".join(fldloc.split('\\'))
    dirpath = fldloc + "/out_binaries/efuse.bin"
    headpath = fldloc + "/out_binaries/otp_data.h"
    efuse_file = open(dirpath, "rb")
    efuse_file.seek(0)
    efuse_data = efuse_file.read()

    with open(headpath, "wt+") as in_file:

        cnt = idx = dat = incnt = outcnt = 0
        in_file.write("/***************************************************************************** \n")
        in_file.write("* Copyright 2018 Microchip Technology Inc. and its subsidiaries.               \n")
        in_file.write("* You may use this software and any derivatives exclusively with               \n")
        in_file.write("* Microchip products.                                                          \n")
        in_file.write("* THIS SOFTWARE IS SUPPLIED BY MICROCHIP 'AS IS'.                              \n")
        in_file.write("* NO WARRANTIES, WHETHER EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE,\n")
        in_file.write("* INCLUDING ANY IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY,       \n")
        in_file.write("* AND FITNESS FOR A PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP      \n")
        in_file.write("* PRODUCTS, COMBINATION WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.    \n")
        in_file.write("* IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,    \n")
        in_file.write("* INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND        \n")
        in_file.write("* WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS    \n")
        in_file.write("* BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.              \n")
        in_file.write("* TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL     \n")
        in_file.write("* CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF     \n")
        in_file.write("* FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.    \n")
        in_file.write("* MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE          \n")
        in_file.write("* OF THESE TERMS.                                                              \n")
        in_file.write("*****************************************************************************/ \n")
        in_file.write("                                                                               \n")
        in_file.write("/** @file efuse_data.h                                                         \n")
        in_file.write(" *EVERGLADES efuse_data                                                        \n")
        in_file.write(" */                                                                            \n")
        in_file.write("/** @defgroup EVERGLADES efuse_data                                            \n")
        in_file.write(" */                                                                            \n")
        in_file.write("#ifndef _EFUSE_DATA_H                                                          \n")
        in_file.write("#define _EFUSE_DATA_H                                                          \n")
        in_file.write("typedef unsigned          char uint8_t;                                        \n")
        in_file.write("typedef unsigned short    int uint16_t;                                       \n")
        in_file.write("                                                                               \n")
        in_file.write("typedef struct efuse_table_define {                                            \n")
        in_file.write("    uint16_t index;                                                            \n")
        in_file.write("    uint8_t value;                                                             \n")
        in_file.write("} _EFUSE_TBLE_DFE_;                                                            \n")
        in_file.write("                                                                               \n")
        in_file.write("const _EFUSE_TBLE_DFE_ device_efuse_table_ [] = {\n")

        message = ""
        in_file.write("    ")
        for items in efuse_data:
            if 0 == cnt:
                idx = items
            if 1 == cnt:
                idx = idx + (items << 8)
            if 2 == cnt:
                dat = items
                # if 3 == cnt:
                if 57005 == idx:  # DEAD
                    message = "{0xDEAD,0xFF}, "
                else:
                    if idx == 9 or idx == 8:
                        message = "{" + str(idx) + ", " + hex(dat).zfill(2) + "}, "
                    else:
                        message = "{" + str(idx).zfill(2) + ", " + hex(dat).zfill(2) + "}, "
                in_file.write(message)
                incnt = incnt + 1
                cnt = 0
                if (8 == incnt):
                    in_file.write("\n    ")
                    message = ""
                    outcnt = outcnt + incnt
                    incnt = 0
            else:
                cnt = cnt + 1
        outcnt = outcnt + incnt

        message = "{00, 0x00}, "
        for idx in range(outcnt, 1024):
            if (8 == incnt):
                in_file.write("\n    ")
                incnt = 0
            in_file.write(message)
            incnt = incnt + 1
        message = "{0xDEAD,0xFF}     //terminator\n"
        in_file.write(message)
        in_file.write("};                                                                             \n")
        in_file.write("                                                                               \n")
        in_file.write("#define TOTAL_SIZE sizeof(device_efuse_table_)/sizeof(device_efuse_table_[0]); \n")
        in_file.write("#endif                                                                         \n")
        in_file.write("/* end efuse_data.h */                                                         \n")
        in_file.write("/**   @}                                                                       \n")
        in_file.write(" */                                                                            \n")
    in_file.close
    efuse_file.close


def otp_extractor(from_file):
    cnt = idx = dat = incnt = outcnt = 0
    #from_file = sys.argv[1]
    #print("OTP binary  =",from_file)
    try:
        from_file_size = os.path.getsize(from_file)
    except:
        print("Error!! File ",from_file," doesn't exists")
        sys.exit()
    with open (from_file,"rb+") as in_file:
        in_file.seek(0)
        input_file_data = in_file.read()
        efuse_data = input_file_data[0xA00:]
        in_file.close()
    in_file = open("otp_dump.log","wt+")
    print("******** OTP  DUMPT value and is available in the otp_dumpt.log ************\n")
    in_file.write("******** OTP  DUMPT value ************")
    in_file.write("\n")    
    for items in efuse_data:
        if 0 == cnt:
            idx = items 
        if 1 == cnt:    
            idx = idx + (items << 8)
        if 2 == cnt:  
            dat = items
            if 57005 == idx:#DEAD
                break
            incnt = incnt +1 
            print("OTP Offset(hex)  =",hex(idx) ,"  OTP Value  =",hex(dat))   
            cnt = "OTP Offset  ="+ str(idx)
            in_file.write(cnt)    
            cnt = "OTP Value  ="+hex(dat)
            in_file.write(cnt)    
            in_file.write(" \n")
            cnt =0 
            if ( 8== incnt):
                outcnt = outcnt + incnt
                incnt = 0
        # #if 3 == cnt:  
        #     if 57005 == idx:#DEAD
        #         message = "{0xDEAD,0xFF}, "
        #         print("message = \n",message)
        #     else:
        #         if idx == 9 or idx == 8:
        #             message = "{"+str(idx)+", "+hex(dat).zfill(2)+"}, "
        #         else:    
        #             message = "{"+str(idx).zfill(2)+", "+hex(dat).zfill(2)+"}, "
        #     #print("message = \n",message)
        #     #in_file.write(message)
        #     incnt = incnt + 1
        #     cnt = 0
        #     if (8 == incnt):
        #         #in_file.write("\n    ")
        #         message = ""
        #         outcnt = outcnt + incnt
        #         incnt = 0
        else:
            cnt = cnt + 1            
    outcnt = outcnt + incnt       

    print("******Exit ****************************\n")
    in_file.write("******Exit ****************************")
    in_file.close()    
def bincreation(data):
    print("************* OTP Offset/Value Read from the Excel sheet otp_rules_sheet.xlsx ******\n")
    # loc = excel

    # wb = xlrd.open_workbook(loc)
    # sheet = wb.sheet_by_index(0)

    # # For row 0 and column 0
    # ##    sheet.cell_value(0, 0)

    # # for i in range(sheet.ncols):
    # #    print(sheet.cell_value(i, 2))

    # from openpyxl import load_workbook

    # # wb = load_workbook(filename = 'EEC1005UBMFRU_EEC1005.xlsx')

    # # ws = wb.get_sheet_by_name(name = 'CFG_ID_07')

    # # print(ws)
    # # book = xlrd.open_workbook(loc, formatting_info=True)
    # # sheet_names = book.sheet_names()
    # # xl_sheet = xl_workbook.sheet_by_name(sheet_names[0])
    # # print(xl_sheet)
    # workbook = xlrd.open_workbook(loc)  # ('EEC1005UBMFRU_EEC1005.xlsx')
    # sheet = workbook.sheet_by_index(0)  # ('CFG_ID_07')

    # ##file2 = open ("temp.txt","wt")
    # # file3 = open ("1.bin","wb")

    # data = []
    # efuse = []
    # hdr_check_sum_list = []
    # record_check_sum_list = []

    # num_rows = sheet.nrows

    # curr_row = 0
    # header_start = "H0"
    # record_start = "D0"
    # check_sum_rep = '0xXX'

    # start_row = 1
    # label_col = 0
    # byte_col = colum_number
    # curr_row = start_row

    # desc_col = 2
    # hdr_sts = 0
    # record_sts = 0

    # record_check_sum_avail_sts = 0
    # hdr_check_sum_avail_sts = 0
    # xsum = 0
    # index_xsum = 0
    # offset = []
    # #print("curr_row byte_col", curr_row, byte_col)

    # while curr_row < num_rows:
    #     value = sheet.cell_value(curr_row, byte_col)
    #     # value = correct_value(value)
    #     value = int(value, 16)
    #     value_1 = sheet.cell_value(curr_row, 1)
    #     value_1 = int(value_1, 16)  # correct_value(value_1)
    #     # if value_1 > 0xFF:
    #     #    offset_pos = value_1
    #     temp = ((value << 16) & 0xFF0000) | value_1
    #     temp = struct.pack('I', temp)
    #     data.append(temp)
    #     #print("data = ", data)
    #     #print("offset= value= ", value_1, value)
    #     # if value != '' or value_1 != '':
    #     #   data.append(value)
    #     #   offset.append(value_1)
    #     #   print("offset = data= ",offset,data)
    #     curr_row = curr_row + 1

    #temp = 0x00FFDEAD
    #temp = struct.pack('I', temp)
    #data.append(temp)

    fldloc = folder_create()
    #print("fldloc ",fldloc)
    fldloc = "/".join(fldloc.split('\\'))
    dirpath1 = fldloc + "/efuse_log.txt"

    # print(len(data))
#def efuse_hdr_data_file(efuse_data , hdr_file_name, data_file_name):
 
    # hdr_file_name = "ef_header_rule_sheet"
    # data_file_name = "ef_data_rule_sheet"
    # if hdr_file_name == '':
    #     hdr_file_name = 'default'
    # if data_file_name == '':
    #     data_file_name = 'default'

        

    # out_file = fldloc +"/out_binaries/"+str(data_file_name)+".txt"
    # hdr_file = fldloc+"/out_binaries/"+str(hdr_file_name) +".txt"

    # out_file_obj = open(out_file,'w')
    # hdr_file_obj = open(hdr_file,'w')

    # print(" writing into text file the efuse data \n"," data_file name :", data_file_name , " header file name :", hdr_file_name)
    # out_file_obj.write("EFUSE DATA LISTED BELOW FOR "+ str(data_file_name)+" \n\n\n")
    # hdr_file_obj.write("EFUSE DATA LISTED BELOW FOR "+ str(hdr_file_name) +" \n\n\n")
    # for i in range(max_efuse_bytes):


    #     out_file_obj.write("Efuse["+str(i)+"] = "+hex(data[i]).lower().zfill(2)+"\n")

    #     if i %8 == 0:
    #         hdr_file_obj.write("\n    ")
    #     hdr_file_obj.write("{"+str(i)+", "+hex(data[i])+"}, ")



    # hdr_file_obj.close()
    # out_file_obj.close()

    e_data = []
    temp =0
    for i in range(max_efuse_bytes):
        #print("Hex value %x ",hex(data[i]).lower().zfill(2))
        value = int(data[i])
        #print("Hex value ",value<<16)
        temp = ((value << 16) & 0xFF0000) | (i)
        #print("Hex value ",temp)
        temp = struct.pack('I', temp)
        e_data.append(temp)

    temp = 0x00FFDEAD
    temp = struct.pack('I', temp)
    e_data.append(temp)

    if platform.system() =='Windows':
        dirpath = fldloc + "/out_binaries/efuse.bin"
    else:
        dirpath = fldloc + "///out_binaries///efuse.bin"
    with open(dirpath, "wb+") as in_file:
        for lines in e_data:
            lines = (lines[:-1])
            in_file.write(bytes(lines))
    in_file.close()

    otp_verifier(fldloc)
    generateheader(fldloc)
    generatesqtpfile(fldloc)
    efuse_data_table = []
    if platform.system() =='Windows':
        binpath = fldloc + "/out_binaries"
    else:
        binpath = fldloc + "///out_binaries"
    file_name = '*.hex'
    with os.scandir(binpath) as entries:
        for entry in entries:
            if entry.is_file():
                extension = entry.name
                extension = extension.split(".")[-1]
                if extension == "hex":
                    cmd = binpath + "/otp_efuse*"
                    if platform.system() =='Windows':
                        cmd = "\\".join(cmd.split('/'))
                        cmd = "del /q /f " + cmd
                        op = os.system(cmd)
                    else:
                        cmd = "/".join(cmd.split('\\'))
                        cmd = "rm " + cmd
                        op = os.system(cmd)                        

    with open("otp/original_binary/otp_prog_original.bin", "rb") as in_file:
        in_file.seek(0)
        # read file as bytes
        file_data = in_file.read()
        with open(fldloc + "///out_binaries///otp_efuse.bin", "wb+") as out_file:
            efuse_file = open(dirpath, "rb")
            efuse_file.seek(0)
            efuse_data = efuse_file.read()
            bin_file_size = os.path.getsize(dirpath)
            endoffset = 0xA00 + bin_file_size
            datain = file_data[:0xA00] + efuse_data + file_data[endoffset:]
            out_file.write(datain)
    in_file.close()
    out_file.close()
    efuse_file.close()

    with open("otp/original_binary/otp_prog_original.elf", "rb") as in_file:
        in_file.seek(0)
        # read file as bytes
        file_data = in_file.read()
        with open(fldloc + "/out_binaries/otp_efuse.elf", "wb+") as out_file:
            efuse_file = open(dirpath, "rb")
            efuse_file.seek(0)
            efuse_data = efuse_file.read()
            bin_file_size = os.path.getsize(dirpath)
            endoffset = 0x10A00 + bin_file_size
            datain = file_data[:0x10A00] + efuse_data + file_data[endoffset:]
            out_file.write(datain)
    in_file.close()
    out_file.close()
    efuse_file.close()

    binpath = fldloc + "/out_binaries"
    cmd = "srec_cat " + binpath + "///otp_efuse.bin -binary -offset 0xE0000 -o " + binpath + "///otp_efuse1.hex -intel"
    cmd = "/".join(cmd.split('\\'))
    op = os.system(cmd)
    in_file = open(binpath + "///otp_efuse1.hex", "rt")
    out_file = open(binpath + "///otp_efuse.hex", "wt")
    org_file = open("otp/original_binary/otp_prog_original.hex", "rt")
    lineno = 0
    ListOfMismatch = []
    for org, new in zip(org_file, in_file):
        if new != org:
            ListOfMismatch.append(lineno)
            if 0 == lineno or 146 == lineno:  # starting or End terminator
                out_file.write(org)
            else:
                out_file.write(new)
        else:
            out_file.write(org)
        lineno = lineno + 1
    nooflines = 0
    org_file.seek(0)

    for lines in org_file:
        nooflines = nooflines + 1

    if (len(ListOfMismatch) > 0):
        if ListOfMismatch[-1] != nooflines:
            out_file.write(lines)

    org_file.close()
    in_file.close()
    out_file.close()

    binpath = fldloc + "/out_binaries"

    with open("otp/original_binary/otp_prog_original.bin", "rb") as in_file:
        table = in_file.read()
        offset = struct.unpack("<L", table[0x4:0x5] + table[0x5:0x6] + table[0x6:0x7] + table[0x7:0x8])[0]
        in_file.close()

    cmd = "srec_cat " + binpath + "///otp_efuse.hex -intel -execution-start-address=" + str(
        offset) + " -o " + binpath + "///otp_efuse_load.hex" + " -intel"
    cmd = "/".join(cmd.split('\\'))
    op = os.system(cmd)

    cmd = binpath + "/otp_efuse.hex"
    cmd = "/".join(cmd.split('\\'))
    cmd = "rm " + cmd
    op = os.system(cmd)

    cmd = binpath + "/otp_efuse_load.hex"
    cmd = "/".join(cmd.split('\\'))
    cmd1 = binpath + "/otp_efuse.hex"
    cmd1 = "/".join(cmd1.split('\\'))
    # cmd="rename "+cmd+ " "+cmd1
    # print("cmd cmd1 ",cmd,cmd1)
    # op = os.system(cmd)
    op = os.rename(cmd, cmd1)

    cmd = binpath + "/otp_efuse1.hex"
    cmd = "/".join(cmd.split('\\'))
    cmd = "rm " + cmd
    op = os.system(cmd)

    cmd = dirpath
    cmd = "/".join(cmd.split('\\'))
    cmd = "rm " + cmd
    op = os.system(cmd)
    buffer = open(binpath + "/otp_efuse.hex", "rb")
    a = bytearray(buffer.read())
    crc = 0xffffffff
    for x in a:
        crc ^= x << 24;
        for k in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc = crc << 1
    crc = ~crc
    crc &= 0xffffffff
    crc_value = hex(crc)
    hex_file_crc32 = crc_value
    buffer.close()
    # print("zlib %X" ,crc_value)
    cmd = binpath + "/otp_efuse.hex"
    cmd = "/".join(cmd.split('\\'))
    cmd1 = binpath + "/otp_efuse" + "_" + crc_value + ".hex"
    cmd1 = "/".join(cmd1.split('\\'))
    op = os.rename(cmd, cmd1)

    # prev =0
    # for eachLine in open(binpath+"/otp_efuse.bin","rb"):
    #     prev = zlib.crc32(eachLine, prev)
    # prev =0
    # for eachLine in open(binpath+"/otp_efuse.hex","rb"):
    #    prev = zlib.crc32(eachLine, prev)
    buffer = open(binpath + "/otp_efuse.bin", "rb")
    a = bytearray(buffer.read())
    crc = 0xffffffff
    for x in a:
        crc ^= x << 24;
        for k in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc = crc << 1
    crc = ~crc
    crc &= 0xffffffff
    crc_value = hex(crc)
    # crc_value = hex(prev & 0xFFFFFFFF)
    bin_file_crc32 = crc_value
    buffer.close()
    # print("zlib %X" ,crc_value)
    cmd = binpath + "/otp_efuse.bin"
    cmd = "/".join(cmd.split('\\'))
    cmd1 = binpath + "/otp_efuse" + "_" + crc_value + ".bin"
    cmd1 = "/".join(cmd1.split('\\'))
    op = os.rename(cmd, cmd1)
    text = "otp_efuse" + "_" + hex_file_crc32 + ".hex = " + hex_file_crc32 + "\n" + "otp_efuse" + "_" + bin_file_crc32 + ".bin  = " + bin_file_crc32
    print("Efuse generator CRC32 checksum ", text)
    print("Generated OTP binaries stored in the <efuse_generator>\efuse\efuse_<YYYYMMDD>_<WHHMMSS> ")
    print("************* Generated the OTP files  ******\n")
    print("****************************************************************\n")
    return


def rom_cfg_file(EFusePVTKeyEN,EFusePVTKey,EFusePVTKeyPassWord,ROMECDHPubKeyFile):
    rom_cfg = "rom_cfg.txt"
    keydata = open(rom_cfg,"wt")
    keydata.write("; CEC173xconfiguration file for key generation \n\n")
    keydata.write("[ROM]\n") 
    cnt = "EFusePVTKeyEN = "+EFusePVTKeyEN
    #cnt = "/".join(cnt.split('\\')) 
    keydata.write(cnt+"\n")    
    cnt = "EFusePVTKey = "+EFusePVTKey
    cnt = "/".join(cnt.split('\\')) 
    keydata.write(cnt+"\n")
    cnt = "EFusePVTKeyPassWord = "+EFusePVTKeyPassWord
    #cnt = "/".join(cnt.split('\\')) 
    keydata.write(cnt+"\n")    
    cnt = "ROMECDHPubKeyFile = "+ROMECDHPubKeyFile
    cnt = "/".join(cnt.split('\\')) 
    keydata.write(cnt+"\n")


    pass
def otp_fun():
    global otp_config
    global MaskVal
    global PatternVal
    global TypeVal    
    print("************* CEC173x OTP Generator Tool Ver: 8.00 ******\n")
    print("************* OTP Offset/Value Read from the otp_value.txt file ******\n")
    data = []
    #print("otp_value.txt file exist1")
    config = configparser.ConfigParser()
    #print("otp_value.txt file exist2")
    ini_file = otp_config
    ecdsa_bool = False
    ap_pub_bool = False
    custom_file_bool = False
    ec_priv_bool = False
    part_flag = False
    part_flag_value = ""
    i =0
    temp =0
    #print("otp_value.txt file exist3")
    config.read(ini_file)
    #print("otp_value.txt file exist")
    #if (os.path.exists(ini_file)):
    #    print("otp_value.txt file exist")
    #    config.read(ini_file)
    #fldloc = folder_create()
    #print("fldloc ",fldloc)
    try:
        fldloc = config['OUTPUT']['outdir']
        fldloc = "/".join(fldloc.split('\\'))
        dirpath1 = fldloc + "/otp_log.txt"
    except:
        print()
    try:
        part_flag_value = config['GLACIERPART']['Chipstr']
        if part_flag_value=="A0":
            part_flag = False
        if part_flag_value=="A1":
            part_flag = True
    except:
        part_flag = False
        print()
    try:
        EFusePVTKeyEN = config['EC_PRIV_FILE']['EFusePVTKeyEN']
        if EFusePVTKeyEN =='true':
            EFusePVTKey = config['EC_PRIV_FILE']['EFusePVTKey']
            EFusePVTKeyPassWord = config['EC_PRIV_FILE']['EFusePVTKeyPassWord']
            ROMECDHPubKeyFile = config['EC_PRIV_FILE']['ROMECDHPubKeyFile']
            #print("EFusePVTKeyEN ",EFusePVTKeyEN)
            #print("EFusePVTKey ",EFusePVTKey)
            rom_cfg_file(EFusePVTKeyEN,EFusePVTKey,EFusePVTKeyPassWord,ROMECDHPubKeyFile)
            cmd = "tools\CEC173x_sha384_ecdhkey.exe -i rom_cfg.txt"
            op = os.system(cmd) 
            #print("Generated the efuse_main.bin of OTP 0-47 \n\n")
            #print("Generated the SHA384Ecdh2PubKey.bin of OTP 128-175 \n\n")
            try:
                with open ("efuse_image.bin","rb") as key_in_file:
                    key_in_file.seek(0)
                    key_file_data = key_in_file.read()
                    idx = 0
                    for i in range(0,48):
                       temp= key_file_data[idx]<< 16 | (i)
                       temp = struct.pack('I',temp)       
                       data.append(temp) 
                       idx = idx+ 1
                with open ("SHA384Ecdh2PubKey.bin","rb") as key_file:
                    key_file.seek(0)
                    key_file = key_file.read()
                    idx = 0
                    for i in range(128,176):
                       temp= key_file[idx]<< 16 | (i)
                       #print("i idx ",i,idx)
                       temp = struct.pack('I',temp)       
                       data.append(temp) 
                       idx = idx+ 1
            except:
                pass
    except:
        pass
    try:
        if part_flag == False:
            SHA384_OWNER_1_PUB_KEY_ENABLE = config['ECDSA']['SHA384_OWNER_1_PUB_KEY_ENABLE']
            if SHA384_OWNER_1_PUB_KEY_ENABLE =='true':
                SHA384_OWNER_1_PUB_KEY = config['ECDSA']['SHA384_OWNER_1_PUB_KEY']
                #print("SHA384_OWNER_1_PUB_KEY ",SHA384_OWNER_1_PUB_KEY)
                bin_out_file = open("Owner1_hash384.bin","wb+")
                with open(SHA384_OWNER_1_PUB_KEY, 'rb') as plain_priv_key:
                    root_ca_priv_key_1 = serialization.load_pem_public_key(data=plain_priv_key.read(),backend=crypto_be) 
                    pub_nums = root_ca_priv_key_1.public_numbers()
                    sub_pubkey =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                    sub_pubkey += pub_nums.y.to_bytes(48, byteorder='big', signed=False)
                digest = hashes.Hash(
                        hashes.SHA384(),
                        crypto_be
                    )  
                pub_file = open("Owner_1_pub.bin","wb+")
                pub_file.write(sub_pubkey)
                digest.update(sub_pubkey)
                dgst = digest.finalize()
                bin_out_file.write(dgst)    
                bin_out_file.close()  
                #print("Generated the Owner1_hash384.bin of OTP 368-415 \n\n")    
                with open ("Owner1_hash384.bin","rb") as key_in_file:
                    key_in_file.seek(0)
                    key_file_data = key_in_file.read()
                    idx = 0
                    for i in range(368,416):
                       temp= key_file_data[idx]<< 16 | (i)
                       temp = struct.pack('I',temp)       
                       data.append(temp) 
                       idx = idx+ 1
        if part_flag == True:
                UseOWNERKHB = config['OWNERKHB']['UseOWNERKHB']
                if UseOWNERKHB =='true':
                    OWNERKHB_Bin = config['OWNERKHB']['OWNERKHB_Bin']
                    with open (OWNERKHB_Bin,"rb") as key_in_file:
                        key_in_file.seek(0)
                        key_file_data = key_in_file.read()
                        idx = 0
                        for i in range(368,416):
                            temp= key_file_data[idx]<< 16 | (i)
                            temp = struct.pack('I',temp)       
                            data.append(temp) 
                            idx = idx+ 1
    except:
        pass
    try:
        SHA384_PLATK_PUB_KEY_ENABLE = config['PLATKPUBLIC']['SHA384_PLATK_PUB_KEY_ENABLE']
        SHA384_PLATK_PUB_KEY = config['PLATKPUBLIC']['SHA384_PLATK_PUB_KEY']
        if SHA384_PLATK_PUB_KEY_ENABLE =='true':
            bin_out_file = open("platform_hash384.bin","wb+")
            with open(SHA384_PLATK_PUB_KEY, 'rb') as plain_priv_key:
                root_ca_priv_key_1 = serialization.load_pem_public_key(data=plain_priv_key.read(),backend=crypto_be) 
                pub_nums = root_ca_priv_key_1.public_numbers()
                sub_pubkey =  pub_nums.x.to_bytes(48, byteorder='big', signed=False)
                sub_pubkey += pub_nums.y.to_bytes(48, byteorder='big', signed=False)
            digest = hashes.Hash(
                    hashes.SHA384(),
                    crypto_be
                )  
            pub_file = open("platform_pub.bin","wb+")
            pub_file.write(sub_pubkey)
            digest.update(sub_pubkey)
            dgst = digest.finalize()
            bin_out_file.write(dgst)    
            bin_out_file.close()  
            #print("Generated the platform_hash384.bin of OTP 864-911 \n\n")        
            with open ("platform_hash384.bin","rb") as key_in_file:
                key_in_file.seek(0)
                key_file_data = key_in_file.read()
                idx = 0
                for i in range(864,912):
                   temp= key_file_data[idx]<< 16 | (i)
                   temp = struct.pack('I',temp)       
                   data.append(temp) 
                   idx = idx+ 1
    except:
        pass
    try:
        PUF_DEVIK_SIGN_ENABLE = config['PUF_DEVIK_SIGN']['PUF_DEVIK_SIGN_ENABLE']
        PUF_DEVIK_SIGN_FILE = config['PUF_DEVIK_SIGN']['PUF_DEVIK_SIGN_FILE']
        OTP_DEVIK_SIGN_ENABLE = config['OTP_DEVIK_SIGN']['OTP_DEVIK_SIGN_ENABLE']
        OTP_DEVIK_SIGN_FILE = config['OTP_DEVIK_SIGN']['OTP_DEVIK_SIGN_FILE']
        if PUF_DEVIK_SIGN_ENABLE =='true':
            with open (PUF_DEVIK_SIGN_FILE,"rb") as key_in_file:
                key_in_file.seek(0)
                key_file_data = key_in_file.read()
                idx = 0
                for i in range(576,672):
                   temp= key_file_data[idx]<< 16 | (i)
                   temp = struct.pack('I',temp)       
                   data.append(temp) 
                   idx = idx+ 1            
        if OTP_DEVIK_SIGN_ENABLE =='true':
            with open (OTP_DEVIK_SIGN_FILE,"rb") as key_in_file:
                key_in_file.seek(0)
                key_file_data = key_in_file.read()
                idx = 0
                for i in range(672,768):
                   temp= key_file_data[idx]<< 16 | (i)
                   temp = struct.pack('I',temp)       
                   data.append(temp) 
                   idx = idx+ 1            
    except:
        pass
    for each_section in config.sections():
        #print("each_section ",each_section)
        for (each_key, each_val) in config.items(each_section):
            if each_key == "customfileenabled":
                custom_file_bool = each_val  
                #print("custom_file_bool ",custom_file_bool)          
            if each_key == "customfileinput":
                print("customfileinput each_val ",each_key,each_val)
            if each_key == "mask":
                MaskVal = each_val
                #print(MaskVal)
            if each_key == "pattern":
                PatternVal = each_val
                #print(PatternVal)
            if each_key == "type":
                TypeVal = each_val
                #print(TypeVal)
            if each_key == "cus_file_enable":
                custom_file_bool = each_val
                custom_file_bool= custom_file_bool.lower()
                #print("True 1")
            if each_key =="custom_file_txt":
                idx = 576
                key_fileloc_3 = each_val
                #print("True 2",key_fileloc_1)
                #if ecdsa_bool == True:
                #print("True 13",ecdsa_bool)
                if custom_file_bool == "true":
                    CustFilekey = open(key_fileloc_3,"rt+")
                    for line in CustFilekey:
                        CUSTMDAT = list(line)
                        CUSTMDAT = CUSTMDAT[0:]
                        
                        endoff = len(CUSTMDAT)
                        cust_enter_var =1
                        key = []
                        for j in range(0,endoff-1,2):
                            key.append(CUSTMDAT[j]+CUSTMDAT[j+1])
                        endoff = 863+1#479+1
                    for item in key:
                        if (idx < endoff):
                             item = int(item,16)
                             temp= ((item<<16) & 0x00FF0000)| idx & 0xFFFF;#0x1FF;
                             temp = struct.pack('I',temp)
                             data.append(temp) 
                             once = True
                             idx = idx +1
            if each_key == "sha384_platk_pub_enable":
                ap_pub_bool = each_val
                ap_pub_bool= ap_pub_bool.lower()
                #print("True 1")
            if each_key =="sha384_platk_pub_hash_bin":
                key_fileloc_2 = each_val
                #print("True 2",key_fileloc_1)
                #if ecdsa_bool == True:
                #print("True 13",ecdsa_bool)
                if ap_pub_bool == "true":
                    with open (key_fileloc_2,"rb") as key_in_file:
                        key_in_file.seek(0)
                        key_file_data = key_in_file.read()
                        idx = 0
                        for i in range(864,912):
                           temp= key_file_data[idx]<< 16 | (i)
                           temp = struct.pack('I',temp)       
                           data.append(temp) 
                           idx = idx+ 1   
                    #key_in_file.close()                 
            if each_key == "ec_priv_file_enable":
                ec_priv_bool = each_val
                ec_priv_bool= ec_priv_bool.lower()
                #print("True 1")
            if each_key =="ec_priv_file":
                ec_key_fileloc = each_val
                #print("True 2",key_fileloc_1)
                #if ecdsa_bool == True:
                #print("True 13",ecdsa_bool)
                if ec_priv_bool == "true":
                    #print("IS it true")
                    with open (ec_key_fileloc,"rb") as key_in_file:
                        key_in_file.seek(0)
                        key_file_data = key_in_file.read()
                        idx = 0
                        for i in range(0,48):
                           temp= key_file_data[idx]<< 16 | (i)
                           temp = struct.pack('I',temp)       
                           data.append(temp) 
                           idx = idx+ 1
                    #key_in_file.close()                 
            if each_key == "ec_pub_file_enable":
                ec_pub_bool = each_val
                ec_pub_bool= ec_pub_bool.lower()
                #print("True 1")
            if each_key =="ec_pub_file":
                ec_pub_fileloc = each_val
                #print("True 2",key_fileloc_1)
                #if ecdsa_bool == True:
                #print("True 13",ecdsa_bool)
                if ec_pub_bool == "true":
                    #print("IS it true")
                    with open (ec_pub_fileloc,"rb") as key_file:
                        key_file.seek(0)
                        key_file = key_file.read()
                        idx = 0
                        for i in range(128,176):
                           temp= key_file[idx]<< 16 | (i)
                           #print("i idx ",i,idx)
                           temp = struct.pack('I',temp)       
                           data.append(temp) 
                           idx = idx+ 1
                    #key_file.Close()                 
            if each_key == "sha384_owner_1_pub_enable":
                ecdsa_bool = each_val
                ecdsa_bool= ecdsa_bool.lower()
                #print("True 1")
            if each_key =="sha384_owner_1_pub_hash_bin":
                key_fileloc_1 = each_val
                #print("True 2",key_fileloc_1)
                #if ecdsa_bool == True:
                #print("True 13",ecdsa_bool)
                if ecdsa_bool == "true":
                    #print("IS it true")
                    with open (key_fileloc_1,"rb") as key_in_file:
                        key_in_file.seek(0)
                        key_file_data = key_in_file.read()
                        idx = 0
                        for i in range(368,416):
                           temp= key_file_data[idx]<< 16 | (i)
                           temp = struct.pack('I',temp)       
                           data.append(temp) 
                           idx = idx+ 1
                #print("ecdsa_bool ",ecdsa_bool)
                #print("each_key  ",each_key)
                #print("each_key  ",each_val)
    i =0
    otp_offset_358 = 0
    otp_offset_366 = 0
    while i < 1025:
        if (os.path.exists(ini_file)):
            config.read(ini_file)
        #for each_section in config.sections():
            #print("each_section ",each_section)
        #    for (each_key, each_val) in config.items(each_section):
        #        if each_key == "authenticationenabled":
        #            print("each_key  ",each_key)
        for each_section in config.sections():
            #print("each_section ",each_section)
            for (each_key, each_val) in config.items(each_section):
                #if each_key == "authenticationenabled":
                #	print("each_key  ",each_key)
                #print("i value ",i)
                if each_key == "otp["+str(i)+"]":
                    #print("index value %x ",i)
                    value = (i)
                    #print("index ",i)
                    value_1 = int(each_val,16)
                    if (value ==358) and (value_1 & 0x80):
                        otp_offset_358 =1
                        # value = 348
                        # value_1 = value_1 | 0x80
                        # print(" value_1 ",value_1)
                        # print("Default Fully Provisioned Bit is set OTP offset 348 =0x80 (Bit 7 is set)")
                    if value ==366 and (value_1 & 0x40):
                        otp_offset_366 =1
                        #value =366
                        #value_1 = value_1 | 0x40
                        #print("Default Enable Fallback Image Status Reporting Feature is enabled OTP offset 366 =0x40 (Bit 6 is set)")
                    #print("value = %x ",value)
                    #print("value_1 = %x ",value_1)
                    #print("type ",type(each_val),type(i))
                    from_file = each_val
                    #print("  ",from_file)
                    temp = ((value_1 << 16) & 0xFF0000) | value
                    temp = struct.pack('I', temp)
                    data.append(temp)
                    #print("data = ", data)
                #if each_key == "from_offset":
                #    from_offset =int(each_val,16)
        i = i+1


    if otp_offset_358 ==0:
        value =358
        value_1 =  0x80
        temp = ((value_1 << 16) & 0xFF0000) | value
        temp = struct.pack('I', temp)
        data.append(temp)
        print("Default : Fully Provisioned Bit is set OTP offset 358 =0x80 (Bit 7 is set)")
    if otp_offset_366 ==0:
        value =366
        value_1 =  0x40
        temp = ((value_1 << 16) & 0xFF0000) | value
        temp = struct.pack('I', temp)
        data.append(temp)
        print("Default : Enable Fallback Image Status Reporting Feature is enabled OTP offset 366 =0x40 (Bit 6 is set)")
    temp = 0x00FFDEAD
    temp = struct.pack('I', temp)
    data.append(temp)
    # print(" data ", data)
    #fldloc = folder_create()
    #print("fldloc ",fldloc)
    #fldloc = "/".join(fldloc.split('\\'))
    #dirpath1 = fldloc + "/efuse_log.txt"

    try:
        fldloc = config['OUTPUT']['outdir']
        #fldloc = "/".join(fldloc.split('\\'))
        #cmd = "IF NOT EXIST "+fldloc+" MD "+fldloc  
        #op = os.system(cmd)         
        #buildbindir=fldloc+"\out_binaries"
        #cmd = "IF NOT EXIST "+buildbindir+" MD "+buildbindir  
        #op = os.system(cmd)         
        #outkeydir=fldloc+"\keys"
        #cmd = "IF NOT EXIST "+outkeydir+" MD "+outkeydir 
        #op = os.system(cmd)
        fldloc = "/".join(fldloc.split('\\')) 
        #print("Del1") 
        #cmd = fldloc +"/out_binaries"
        #cmd = "/".join(cmd.split('\\'))
        #cmd = "rm " + cmd
        #op = os.system(cmd)
        #cmd = fldloc +"/keys"
        #cmd = "/".join(cmd.split('\\'))
        #cmd = "rm " + cmd
        #op = os.system(cmd)
        #print("Del2") 
    except:
        print()
    # print(len(data))
    dirpath = fldloc + "/out_binaries/efuse.bin"
    with open(dirpath, "wb+") as in_file:
        for lines in data:
            lines = (lines[:-1])
            in_file.write(lines)
    in_file.close()

    otp_verifier(fldloc)
    generateheader(fldloc)
    generatesqtpfile(fldloc)
    efuse_data_table = []
    binpath = fldloc + "///out_binaries"
    file_name = '*.hex'
    try:
        with os.scandir(binpath) as entries:
            for entry in entries:
                if entry.is_file():
                    extension = entry.name
                    extension = extension.split(".")[-1]
                    if extension == "hex":
                        cmd = binpath + "/otp*"
                        cmd = "\\".join(cmd.split('/'))
                        cmd = "del /q /f " + cmd
                        op = os.system(cmd)
    except:
        pass

    with open("otp/original_binary/otp_prog_original.bin", "rb") as in_file:
        in_file.seek(0)
        # read file as bytes
        file_data = in_file.read()
        with open(fldloc + "///out_binaries///otp.bin", "wb+") as out_file:
            efuse_file = open(dirpath, "rb")
            efuse_file.seek(0)
            efuse_data = efuse_file.read()
            bin_file_size = os.path.getsize(dirpath)
            endoffset = 0xA00 + bin_file_size
            datain = file_data[:0xA00] + efuse_data + file_data[endoffset:]
            out_file.write(datain)
    in_file.close()
    out_file.close()
    efuse_file.close()

    with open("otp/original_binary/otp_prog_original.elf", "rb") as in_file:
        in_file.seek(0)
        # read file as bytes
        file_data = in_file.read()
        with open(fldloc + "/out_binaries/otp.elf", "wb+") as out_file:
            efuse_file = open(dirpath, "rb")
            efuse_file.seek(0)
            efuse_data = efuse_file.read()
            bin_file_size = os.path.getsize(dirpath)
            endoffset = 0x10A00 + bin_file_size
            datain = file_data[:0x10A00] + efuse_data + file_data[endoffset:]
            out_file.write(datain)
    in_file.close()
    out_file.close()
    efuse_file.close()

    binpath = fldloc + "/out_binaries"
    cmd = "srec_cat " + binpath + "///otp.bin -binary -offset 0xE0000 -o " + binpath + "///otp_otp1.hex -intel"
    cmd = "/".join(cmd.split('\\'))
    op = os.system(cmd)
    in_file = open(binpath + "///otp_otp1.hex", "rt")
    out_file = open(binpath + "///otp.hex", "wt")
    org_file = open("otp/original_binary/otp_prog_original.hex", "rt")
    lineno = 0
    ListOfMismatch = []
    for org, new in zip(org_file, in_file):
        if new != org:
            ListOfMismatch.append(lineno)
            if 0 == lineno or 146 == lineno:  # starting or End terminator
                out_file.write(org)
            else:
                out_file.write(new)
        else:
            out_file.write(org)
        lineno = lineno + 1
    nooflines = 0
    org_file.seek(0)

    for lines in org_file:
        nooflines = nooflines + 1

    if (len(ListOfMismatch) > 0):
        if ListOfMismatch[-1] != nooflines:
            out_file.write(lines)

    org_file.close()
    in_file.close()
    out_file.close()

    binpath = fldloc + "/out_binaries"

    with open("otp/original_binary/otp_prog_original.bin", "rb") as in_file:
        table = in_file.read()
        offset = struct.unpack("<L", table[0x4:0x5] + table[0x5:0x6] + table[0x6:0x7] + table[0x7:0x8])[0]
        in_file.close()

    cmd = "srec_cat " + binpath + "///otp.hex -intel -execution-start-address=" + str(
        offset) + " -o " + binpath + "///otp_load.hex" + " -intel"
    cmd = "/".join(cmd.split('\\'))
    op = os.system(cmd)

    cmd = binpath + "/otp.hex"
    cmd = "/".join(cmd.split('\\'))
    cmd = "rm " + cmd
    op = os.system(cmd)

    cmd = binpath + "/otp_load.hex"
    cmd = "/".join(cmd.split('\\'))
    cmd1 = binpath + "/otp.hex"
    cmd1 = "/".join(cmd1.split('\\'))
    # cmd="rename "+cmd+ " "+cmd1
    # print("cmd cmd1 ",cmd,cmd1)
    # op = os.system(cmd)
    op = os.rename(cmd, cmd1)

    cmd = binpath + "/otp_otp1.hex"
    cmd = "/".join(cmd.split('\\'))
    cmd = "rm " + cmd
    op = os.system(cmd)

    cmd = dirpath
    cmd = "/".join(cmd.split('\\'))
    cmd = "rm " + cmd
    op = os.system(cmd)
    buffer = open(binpath + "/otp.hex", "rb")
    a = bytearray(buffer.read())
    crc = 0xffffffff
    for x in a:
        crc ^= x << 24;
        for k in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc = crc << 1
    crc = ~crc
    crc &= 0xffffffff
    crc_value = hex(crc)
    hex_file_crc32 = crc_value
    buffer.close()
    # print("zlib %X" ,crc_value)
    cmd = binpath + "/otp.hex"
    cmd = "/".join(cmd.split('\\'))
    cmd1 = binpath + "/otp" + "_" + crc_value + ".hex"
    cmd1 = "/".join(cmd1.split('\\'))
    op = os.rename(cmd, cmd1)

    # prev =0
    # for eachLine in open(binpath+"/otp_efuse.bin","rb"):
    #     prev = zlib.crc32(eachLine, prev)
    # prev =0
    # for eachLine in open(binpath+"/otp_efuse.hex","rb"):
    #    prev = zlib.crc32(eachLine, prev)
    buffer = open(binpath + "/otp.bin", "rb")
    a = bytearray(buffer.read())
    crc = 0xffffffff
    for x in a:
        crc ^= x << 24;
        for k in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc = crc << 1
    crc = ~crc
    crc &= 0xffffffff
    crc_value = hex(crc)
    # crc_value = hex(prev & 0xFFFFFFFF)
    bin_file_crc32 = crc_value
    buffer.close()
    # print("zlib %X" ,crc_value)
    cmd = binpath + "/otp.bin"
    cmd = "/".join(cmd.split('\\'))
    cmd1 = binpath + "/otp" + "_" + crc_value + ".bin"
    cmd1 = "/".join(cmd1.split('\\'))
    op = os.rename(cmd, cmd1)
    text = "otp" + "_" + hex_file_crc32 + ".hex = " + hex_file_crc32 + "\n" + "otp" + "_" + bin_file_crc32 + ".bin  = " + bin_file_crc32
    print("OTP generator CRC32 checksum ", text)

    buffer = open(binpath + "/sqtpfile.txt", "rb")
    a = bytearray(buffer.read())
    crc = 0xffffffff
    for x in a:
        crc ^= x << 24;
        for k in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc = crc << 1
    crc = ~crc
    crc &= 0xffffffff
    crc_value = hex(crc)
    # crc_value = hex(prev & 0xFFFFFFFF)
    bin_file_crc32 = crc_value
    buffer.close()
    # print("zlib %X" ,crc_value)
    cmd = binpath + "/sqtpfile.txt"
    cmd = "/".join(cmd.split('\\'))
    cmd1 = binpath + "/sqtpfile" + "_" + crc_value + ".txt"
    cmd1 = "/".join(cmd1.split('\\'))
    op = os.rename(cmd, cmd1)
    text = "sqptfile" + "_" + bin_file_crc32 + ".txt" 
    print("OTP generator CRC32 checksum sqptfile =", text)
    print("Generated OTP binaries stored in the <otp_generator>\otp\otp_<YYYYMMDD>_<WHHMMSS> ")
    print("************* Generated the OTP files  ******\n")
    print("****************************************************************\n")
    return

def parse(rule):

    derive_val = 0
##    print("rule ",rule)
    skip_char = "_"
    show_char = "S"
    hide_char = "H"
    merg_char = "M"
    idx = 0

    #reversing it because the string start index is at left
    rule = rule[::-1]
    for i in range(len(rule)):
##        print(" before if ", i,"\n")
##        print(" rule[i] ", rule[i], "\n")
        if (rule[i] != skip_char):
            if((rule[i] == show_char) or (rule[i] == merg_char)):

                derive_val = (derive_val | (1<<idx))



##                print("i ",i)
            idx= idx + 1

        
    derive_val = derive_val & 0xFF
    #print("derive val ",derive_val)

    return derive_val

def main():
    global soteria_flag
    global soteria_cus_flag
    global write_flag
    global DSW_flag
    global MOB_flag
    global COMP_flag
    global tool_config_file
    global warningMSG
    global display_done
    global headerflag
    global tool_config
    global otp_config

    global otp_lock_15
    global otp_lock_16
    global otp_lock_17
    global otp_lock_18
    global otp_lock_19
    global otp_lock_20
    global otp_lock_21
    global otp_lock_22
    global otp_lock_23
    global otp_lock_24
    global otp_lock_25
    global otp_lock_26
    global otp_lock_27
    global otp_lock_28
    global otp_lock_29
    global otp_lock_30
    global otp_write_lock_en
    global write_lock_flag_15
    global write_lock_flag_16
    global write_lock_flag_17
    global write_lock_flag_18
    global write_lock_flag_19
    global write_lock_flag_20
    global write_lock_flag_21
    global write_lock_flag_22
    global write_lock_flag_23
    global write_lock_flag_24
    global write_lock_flag_25
    global write_lock_flag_26
    global write_lock_flag_27
    global write_lock_flag_28
    global write_lock_flag_29
    global write_lock_flag_30
    global setting_win_flag
    global cust_enter_var

    show_val = "SHOW"
    hide_val = "HIDE"
    merg_val = "MERGE"
    start_row = 4
    start_col = 6
    
    parser = argparse.ArgumentParser(add_help=False)
    #parser.add_argument("-i", "- ini_file", dest="ini_file", type=str,
    #                    required=False, help="Input config file")
    # parser.add_argument("-gc", "- General & Comparator", dest="GC", 
    #                 required=False, help="General & Comparator features - Only available in selected packages")
    # parser.add_argument("-g", "- General", dest="G", 
    #                 required=False, help="General features - Only available in selected packages")
    # parser.add_argument("-d", "- Desktop", dest="D", 
    #                 required=False, help="Desktop features - Only available in selected packages")
    # parser.add_argument("-m", "- Mobile", dest="M", 
    #                 required=False, help="Mobile features - Only available in selected packages")
    # #parser.add_argument("-mc", "- Mobile & Comparator", dest="MC", 
    # #                required=False, help="Mobile & Comparator features - Only available in selected packages")
    # parser.add_argument("-c", "- Comparator Bit", dest="C", 
    #                 required=False, help="Comparator specific bit features - Only available in selected packages") 
    # parser.add_argument("-s2", "- Soteria-G3", dest="S2", 
    #                 required=False, help="Soteria-G3 Features - Only available in selected packages") 
    # parser.add_argument("-s2c", "- Soteria-G3", dest="S2C", 
    #                 required=False, help="Soteria-G3 Features - Only available in selected packages") 
    parser.add_argument("-t", "- otp text file ", dest="otp_value",type=str,
                    required=False, help="OTP offset and values are feed  - Only available in selected packages")
    parser.add_argument("-x", dest = 'input_excel', default= 'None')
    parser.add_argument("-row", dest = 'input_row' , default = 'None')
    parser.add_argument("-column", dest = 'input_col' , default = 'None')
    parser.add_argument("-o", dest = 'otp_binary', default= 'None')
                    
    #parser.add_argument("-x", "- otp Excel sheet ", dest="X",
    #                required=False, help="OTP offset and values are feed  - Only available in selected packages")

    args = parser.parse_args()  # outputs

    try:
        text_file = os.path.normpath(args.T)
        otp_text_flag = True
    except:
        otp_text_flag = False

    try:
        otp_config = os.path.normpath(args.otp_value)    
        print(otp_config)
        otp_text_flag = True
        if not os.path.exists(otp_config):
            otp_config_file = False        
    except:
        tool_config_file = False

    if otp_text_flag == True:
        otp_fun()
        sys.exit(2)


    try:
        otp_file_gen_flag = False
        if args.otp_binary !='None':
            otp_file_gen_bin = str(args.otp_binary)
            otp_file_gen_flag = True
    except:
        otp_file_gen_flag = False

    if otp_file_gen_flag == True:
        print(" Input OTP Bin file =%s ", otp_file_gen_bin)
        otp_extractor(otp_file_gen_bin)
        sys.exit(2)
    
    try:
        #sheet_file = os.path.normpath(args.X)
        #print("sheet file ")
        otp_sheet_flag = False
        if args.input_excel !='None':
            rule_sheet = str(args.input_excel)
            otp_sheet_flag = True
        if args.input_row != 'None':
            start_row = int(args.input_row)
            otp_sheet_flag = True
        if args.input_col != 'None':
            start_col = int(args.input_col)
            otp_sheet_flag = True
    except:
        otp_sheet_flag = False
    
    if otp_sheet_flag == True:
        print(" Input Excel sheet ", rule_sheet)
        print(" Input start row ", start_row)
        print(" Input start col ", start_col)
        wb = xlrd.open_workbook(rule_sheet)
        sheet = wb.sheet_by_index(1)
        #print("wb %s sheet %s ",wb,sheet)
        efuse_data = []
        row = start_row
        col = start_col
        for i in range(max_efuse_bytes):
            efuse_data.append(0)

        tot_row = sheet.nrows
        tot_col = sheet.ncols

        for i in range(max_efuse_bytes):
            if row > tot_row or col > tot_col:
                #print(" Total row/col reached \n")
                break
            #print("i ",i)
            rule = sheet.cell_value(row,col)
            value = 0
            float_type = type(1.0)
            if type(rule) == float_type:
                continue
            # if the full byte can be shown:
            if (rule == show_val):
                value = 0xFF
            # Full byte has to be hidden
            elif (rule == hide_val):
                value = 0x00
            # Full byte has to be merged
            elif (rule == merg_val):
                value = 0xFF
            else:
                #print("valye ",value)
                value = parse(rule)
        ##    print("  value ", value)
            efuse_data[i] = value
            #print("efuse data %x ",efuse_data[i])
            row = row+1
        #excel_file = "otp_rules_sheet.xlsx"
        #excel = excel_file.split(".")[-1]

        bincreation(efuse_data)
        sys.exit(2)

    try:
        DSW = os.path.normpath(args.D)
        DSW_flag = True
    except:
        DSW_flag = False 

    try:
        MOB = os.path.normpath(args.M)
        MOB_flag = True
    except:
        MOB_flag = False

    try:
        soteria = os.path.normpath(args.S2)
        soteria_flag = True
    except:
        soteria_flag = False

    try:
        soteria_cus = os.path.normpath(args.S2C)
        soteria_cus_flag = True
        write_flag = True 
    except:
        soteria_cus_flag = False
        write_flag = False

    try:
        COMP = os.path.normpath(args.C)
        COMP_flag = True
    except:
        COMP_flag = False

    try:
        ini_file = os.path.normpath(args.ini_file)    
        tool_config_file = True
        if not os.path.exists(ini_file):
            tool_config_file = False        
    except:
        tool_config_file = False
    
    if (True == tool_config_file):
        headerflag = 0
        warningMSG = 1
        display_done = 0
        tool_config = ini_file

    if ((True == DSW_flag) and  (True == MOB_flag)):
        print("CAUTION: Feature may not be available in all packages")
        print("Please refer the datasheet for the features available for the given package")
        print("Desktop & Mobile is not to be enable at same time ")
        print("Please refer the efuseconfig.ini file for the usage of Desktop & Mobile to be enable which is based on the package available")
        sys.exit(2)

    if ((True == DSW_flag) and  (True == COMP_flag)):
        print("CAUTION: Feature may not be available in all packages")
        print("Please refer the datasheet for the features available for the given package")
        print("Desktop & Comparator strap  is not to be enable at same time ")
        print("Please refer the efuseconfig.ini file for the usage of Desktop & Comparator to be enable which is based on the package available")
        sys.exit(2)

    if( (True == DSW_flag) or (True == COMP_flag) or (True == MOB_flag) or (True == soteria_flag) or (True == soteria_cus_flag) or (True == tool_config_file)):
        root = Tk()
        (FrameSizeX, FrameSizeY, FramePosX, FramePosY) = get_screen_resolution(root, 30, 130)
        root.resizable(width=False, height=False)
        #geom1 =FrameSizeX+"x"+FrameSizeY+"+"+FramePosX+"+"+FramePosY
        geom1 ="450x480+"+FramePosX+"+"+FramePosY
        root.geometry()
        #root.geometry("450x410+750+300")
        app = Key_gen(root)
        root.mainloop()
    else:
        #ini_file_1 = os.path.normpath("efuseconfig.ini")
        #if not os.path.exists(ini_file_1):
        #   sys.exit(2)
        #config_1 = configparser.ConfigParser()
        #config_1.read(ini_file_1)
        #tool_name = config_1['DEVICE_PACKAGE']['ExeName']
        #feature_sel = config_1['DEVICE_PACKAGE']['Feature']
        #if tool_name == "" or feature_sel =="":
        root =Tk()
        root.resizable(width=False, height=False)
        app = Root(root)
        root.mainloop()
        # else:
        #     message[0] = tool_name + " Efuse Generator Tool Ver: 36.00"
        #     if feature_sel != "":
        #        if feature_sel == 'M' or feature_sel =='m':
        #           MOB_flag = True
        #           DSW_flag = False
        #           COMP_flag = False
        #           soteria_flag = False
        #           soteria_cus_flag = True
        #        elif feature_sel == 'MC' or feature_sel =='mc':
        #           MOB_flag = True
        #           COMP_flag = True
        #           DSW_flag = False
        #           soteria_flag = False
        #           soteria_cus_flag = True
        #        elif feature_sel == 'G' or feature_sel =='g':
        #           MOB_flag = False
        #           COMP_flag = False
        #           DSW_flag = False
        #           soteria_flag = False
        #           soteria_cus_flag = True
        #        elif feature_sel == 'GC' or feature_sel =='gc':
        #           MOB_flag = False
        #           COMP_flag = True
        #           DSW_flag = False
        #           soteria_flag = False
        #           soteria_cus_flag = True
        #        elif feature_sel == 'D' or feature_sel =='d':
        #           MOB_flag = False
        #           COMP_flag = False
        #           DSW_flag = True
        #           soteria_flag = False
        #           soteria_cus_flag = True
        #        elif feature_sel == 'S2':
        #           MOB_flag = False
        #           COMP_flag = False
        #           DSW_flag = False
        #           soteria_flag = True
        #           soteria_cus_flag = False
        #        elif feature_sel == 'S2C':
        #           MOB_flag = False
        #           COMP_flag = False
        #           DSW_flag = False
        #           soteria_flag = False
        #           soteria_cus_flag = True
        #           write_flag = True
        #        else:
        #            root = Tk()
        #            root.resizable(width=False, height=False)
        #            messagebox.showinfo(message[0], 'Please provide the option of ExeName name or Feature available for the package  ,which is provided in the efuseconfig.ini')
        #            sys.exit(2)
        #            return;

        #        root = Tk()
        #        root.resizable(width=False, height=False)
        #        (FrameSizeX, FrameSizeY, FramePosX, FramePosY) = get_screen_resolution(root, 30, 130)
        #        #geom1 =FrameSizeX+"x"+FrameSizeY+"+"+FramePosX+"+"+FramePosY
        #        geom1 ="450x480+"+FramePosX+"+"+FramePosY
        #        root.geometry()
        #        #root.geometry("450x410+750+300")
        #        app = Key_gen(root)

               #root = Tk()
        #       root.mainloop()

      


if __name__ == '__main__':
    main()
