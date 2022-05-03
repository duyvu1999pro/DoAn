import tkinter
from tkinter import messagebox
from tkinter import *
from tkinter.ttk import *
import customtkinter
from pygments.console import dark_colors
from scapy.all import *
import function
from astroid.node_classes import If

# Set dark appearance mode:
customtkinter.set_appearance_mode("Dark")  # Other: "Light", "System"                     

        
class Redirect():
    
    def __init__(self, widget, autoscroll=True):
        self.widget = widget
        self.autoscroll = autoscroll

    def write(self, text):
        self.widget.insert('end', text)
        if self.autoscroll:
            self.widget.see("end")  # autoscroll

                     
class App(customtkinter.CTk):

    APP_NAME = "Traffic Genarator Attack"
    WIDTH = 830
    HEIGHT = 600
    MAIN_COLOR = "#5EA880"
    MAIN_COLOR_DARK = "#2D5862"
    MAIN_HOVER = "#458577"
    
   
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title(App.APP_NAME)
        self.geometry(str(App.WIDTH) + "x" + str(App.HEIGHT))
        self.minsize(App.WIDTH, App.HEIGHT)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.resizable(False, False)
        
        #region menu
        menubar = Menu(self)
        filemenu = Menu(menubar, tearoff=0)
        filemenu.add_command(label="Save As...", command=lambda : function.saveToPcap(self))
        filemenu.add_command(label="Gen Report", command=lambda : function.genReport(self))
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.quit)
        
        helpmenu = Menu(menubar, tearoff=0)
        helpmenu.add_command(label="Guide", command=lambda : function.guide())
        helpmenu.add_command(label="About", command=lambda : function.about())
        
        menubar.add_cascade(label="Menu", menu=filemenu)
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.config(menu=menubar)
        #endregion
        
        #region style   
        style = Style()
        style.configure("W.TRadiobutton", background = "#505050",
                foreground = "white", font = ("Century Gothic", 10))
        style.configure("A.TRadiobutton", background = "#5E5E5E",
                foreground = "white", font = ("Century Gothic", 10))
        style.configure("A.TCheckbutton", background = "#505050",
                foreground = "white", font = ("Century Gothic", 10))
        style.configure("W.TCheckbutton", background = "#505050",
                foreground = "white", font = ("Century Gothic", 11))
        style.configure("W.TEntry", selectbackground = "#505050", font = ("Century Gothic", 10))
        style.configure("A.TEntry", selectbackground = "#505050", font = ("Century Gothic", 11))
        style.configure("A.TLabel", background = "#3F3F3F",foreground="white", font=("Arial", 12,"italic"))
        style.configure("B.TLabel", background = "#505050",foreground="white", font=("Arial", 12,"italic"))
        style.configure("C.TLabel", background = "#505050",foreground="gray", font=("Century Gothic", 10))
        #endregion
        #region global var 
        self.malware_gift= ""
        
        #endregion
        #region ============ create CTkFrames ============    
        self.frame_main = customtkinter.CTkFrame(master=self,
                                                 width=800,
                                                 height=400,
                                                 corner_radius=5)
        self.frame_main.place(relx=0.5, rely=0.35, anchor=tkinter.CENTER)
        self.frame_cmd = customtkinter.CTkFrame(master=self,
                                                  width=420,
                                                  height=App.HEIGHT-40,
                                                  corner_radius=5)
        self.frame_cmd.place(relx=0.25, rely=0.85, anchor=tkinter.CENTER)

        self.frame_right = customtkinter.CTkFrame(master=self,
                                                  width=300,
                                                  height=150,
                                                  corner_radius=5)
        self.frame_right.place(relx=0.55, rely=0.84, anchor=tkinter.W)
        #endregion
        
        #region ============ frame_main ============
        customtkinter.CTkLabel(self.frame_main, text = "Target",height=20,text_font=("Century Gothic", 13,"bold")).place(relx=0.07, rely=0.05, anchor=tkinter.CENTER)
        #customtkinter.CTkLabel(self.frame_main, text = "Ex: 142.250.204.110 , mta.edu.vn",height=16,width=500,text_font=("Century Gothic", 9,"italic")).place(relx=0.7, rely=0.05, anchor=tkinter.CENTER)    
        self.target_entry = StringVar()
        self.target_entry_gui= Entry(self.frame_main, textvariable =self.target_entry,style="A.TEntry",width=20)
        self.target_entry_gui.insert(0,"142.250.204.110")
        self.target_entry_gui.place(relx=0.2, rely=0.05, anchor=tkinter.CENTER)
        customtkinter.CTkLabel(self.frame_main, text = "Network Interface",height=20,width=300,text_font=("Century Gothic", 13,"bold")).place(relx=0.57, rely=0.05, anchor=tkinter.CENTER)
        self.network_adapter= StringVar()
        self.network_adapter_gui = Combobox(self.frame_main, width = 27,state="readonly", 
                            textvariable = self.network_adapter)
        self.network_adapter_gui.bind("<<ComboboxSelected>>",lambda e: self.frame_main.focus())
        self.network_adapter_gui['values'] = function.getNetworkAdapterName()
        self.network_adapter_gui.current(0)
        self.network_adapter_gui.place(relx=0.79, rely=0.05, anchor=tkinter.CENTER)
        #region frame arp
       
        self.checkbox_arp = customtkinter.CTkCheckBox(master=self.frame_main,
                                              width=15,
                                              height=15,
                                              fg_color="#D8554D",
                                              border_color="white",
                                              hover_color="#7F7F7F",
                                              text_font=("Century Gothic", 11),
                                              border_width=1.5,command=self.check_arp_event,
                                     text="ARP Attack")
        self.checkbox_arp.place(relx=0.09, rely=0.15, anchor=tkinter.CENTER) 
        
        self.frame_arp = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=120,
                                                 height=90,
                                                 corner_radius=5)
        self.frame_arp.place(relx=0.085, rely=0.19, anchor=tkinter.N)
        self.arp_check = StringVar(self,"1")
        self.arp_lan = Radiobutton(self.frame_arp, text ="LAN Spoof", style="W.TRadiobutton",
                    variable =self.arp_check,value ="2",state='disabled',command=self.arp_lan_event)
        self.arp_lan.place(relx=0.37, y=35, anchor=tkinter.N)
        self.arp_wan = Radiobutton(self.frame_arp, text ="Broadcast", style="W.TRadiobutton",
                    variable =self.arp_check,value = "1",state='disabled',command=self.arp_lan_event)
        self.arp_wan.place(relx=0.37, y=10, anchor=tkinter.N)
        self.arp_entry = StringVar()
        self.arp_entry_gui= Entry(self.frame_arp, textvariable =self.arp_entry,style="W.TEntry",width=16)
        self.arp_entry_gui.insert(0,"IP Host")
        self.arp_entry_gui.config(state='disabled')
        self.arp_entry_gui.place(relx=0.47, rely=0.65, anchor=tkinter.N)
        #endregion
     
        #region frame icmp
        customtkinter.CTkLabel(self.frame_main, text = "ICMP Attack",text_font=("Century Gothic", 11)).place(relx=0.16, rely=0.12) 
        self.frame_icmp = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=120,
                                                 height=90,
                                                 corner_radius=5)
        
        
        self.frame_icmp.place(relx=0.245, rely=0.19, anchor=tkinter.N)
        self.icmp_check = StringVar(self,"1")
        Radiobutton(self.frame_icmp, text ="None", style="W.TRadiobutton",
                    variable =self.icmp_check,value ="1").place(relx=0.3, y=5, anchor=tkinter.N)        
        Radiobutton(self.frame_icmp, text ="Normal", style="W.TRadiobutton",
                    variable =self.icmp_check,value = "2").place(relx=0.35, y=30, anchor=tkinter.N)
        Radiobutton(self.frame_icmp, text ="Malformed", style="W.TRadiobutton",
                    variable =self.icmp_check,value = "3").place(relx=0.43, y=55, anchor=tkinter.N)
        #endregion
                 
        #region frame_udp
        self.checkbox_udp = customtkinter.CTkCheckBox(master=self.frame_main,
                                              width=15,
                                              height=15,
                                              fg_color="#D8554D",
                                              border_color="white",
                                              hover_color="#7F7F7F",
                                              text_font=("Century Gothic", 11),
                                              border_width=1.5,command=self.check_udp_event,
                                     text="Layer 4 Attack using UDP")
        self.checkbox_udp.place(relx=0.17, rely=0.46, anchor=tkinter.CENTER) 
        self.frame_udp = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=250,
                                                 height=150,
                                                 corner_radius=5)
        self.frame_udp.place(relx=0.165, y=205, anchor=tkinter.N)
        self.UDP_port = IntVar(value=0)  
        self.UDP_port_gui= Checkbutton(self.frame_udp,text='Random Port',variable =self.UDP_port,
                                               style="A.TCheckbutton",state='disabled',command=self.udp_port_event)
        self.UDP_port_gui.place(relx=0.26, rely=0.12, anchor=tkinter.CENTER)
        customtkinter.CTkLabel(self.frame_udp, text = "Specific Port",height=16,text_font=("Century Gothic", 10)).place(x = 1,y =35)       
        self.udp_entry_port = StringVar()
        self.udp_entry_port_gui= Entry(self.frame_udp, textvariable =self.udp_entry_port,style="W.TEntry",width=4)
        self.udp_entry_port_gui.insert(0,"80")
        self.udp_entry_port_gui.config(state='disabled')
        self.udp_entry_port_gui.place(relx=0.5, rely=0.27, anchor=tkinter.CENTER)
        
        self.UDP_data = IntVar(value=0)  
        self.UDP_data_gui= Checkbutton(self.frame_udp,text='Random data',variable =self.UDP_data,
                                               style="A.TCheckbutton",state='disabled',command=self.udp_data_event)
        self.UDP_data_gui.place(relx=0.26, rely=0.57, anchor=tkinter.CENTER)
        customtkinter.CTkLabel(self.frame_udp, text = "Craft Data ",height=15,text_font=("Century Gothic", 10)).place(x = 1,y =99)       
    
        self.udp_entry_data = StringVar()
        self.udp_entry_data_gui= Entry(self.frame_udp, textvariable =self.udp_entry_data,style="W.TEntry",width=18)
        self.udp_entry_data_gui.insert(0,"duyvu")
        self.udp_entry_data_gui.config(state='disabled')
        self.udp_entry_data_gui.place(relx=0.67, rely=0.715, anchor=tkinter.CENTER)
        #endregion
        
        #region frame_tcp
        self.checkbox_tcp = customtkinter.CTkCheckBox(master=self.frame_main,
                                              width=15,
                                              height=15,
                                              fg_color="#D8554D",
                                              border_color="white",
                                              hover_color="#7F7F7F",
                                              text_font=("Century Gothic", 11),
                                              border_width=1.5,command=self.check_tcp_event,
                                     text="Layer 4 Attack using TCP")
        self.checkbox_tcp.place(relx=0.52, rely=0.14, anchor=tkinter.CENTER)         
        self.frame_tcp = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=300,
                                                 height=300,
                                                 corner_radius=5)
        self.frame_tcp.place(relx=0.34, rely=0.18, anchor=tkinter.NW)
        self.frame_tcp_kid = customtkinter.CTkFrame(master=self.frame_tcp,
                                                 width=280,
                                                 height=80,
                                                 fg_color="#5E5E5E",
                                                 corner_radius=5)
        self.frame_tcp_kid.place(relx=0.02, rely=0.02, anchor=tkinter.NW)
        self.tcp_type = StringVar(self,"1")
        self.tcp_ex = StringVar(self,"1")
        self.tcp_ex_gui1 = Radiobutton(self.frame_tcp_kid, text ="Syn Flood", style="A.TRadiobutton",state='disabled',
                    variable =self.tcp_ex,value = "1")
        self.tcp_ex_gui1.place(relx=0.61, y=55, anchor=tkinter.N)
        self.tcp_ex_gui2 = Radiobutton(self.frame_tcp_kid, text ="Xmas Flood", style="A.TRadiobutton",state='disabled',
                    variable =self.tcp_ex,value = "2")
        self.tcp_ex_gui2.place(relx=0.64, y=30, anchor=tkinter.N)
        self.tcp_ex_gui3 = Radiobutton(self.frame_tcp_kid, text ="STREAM Flood (★)", style="A.TRadiobutton",state='disabled',
                    variable =self.tcp_ex,value = "3")
        self.tcp_ex_gui3.place(relx=0.70, y=5, anchor=tkinter.N)
        
        self.tcp_type_gui1 = Radiobutton(self.frame_tcp_kid, text ="Default Types", style="A.TRadiobutton",state='disabled',
                    variable =self.tcp_type,value = "1",command=self.check_tcp_event)
        self.tcp_type_gui1.place(relx=0.2, y=35, anchor=tkinter.N)
        self.tcp_type_gui2 = Radiobutton(self.frame_tcp, text ="TCP Craft", style="W.TRadiobutton",state='disabled',
                    variable =self.tcp_type,value = "2",command=self.check_tcp_event)
        self.tcp_type_gui2.place(relx=0.18, y=90, anchor=tkinter.N)
       
        customtkinter.CTkLabel(self.frame_tcp, text = "Flag",height=19,text_font=("Century Gothic", 11)).place(relx=0.09 ,y =120, anchor=tkinter.N)
        self.Flag_F = IntVar(value=1)
        self.Flag_S = IntVar(value=0)
        self.Flag_R = IntVar(value=0)
        self.Flag_P = IntVar(value=0)
        self.Flag_A = IntVar(value=0)
        self.Flag_U = IntVar(value=0)
        self.Flag_E = IntVar(value=0)
        self.Flag_C = IntVar(value=0)
        self.Flag_F_gui = Checkbutton(self.frame_tcp,text='F',state='disabled',variable =self.Flag_F,style="A.TCheckbutton")
        self.Flag_S_gui = Checkbutton(self.frame_tcp,text='S',state='disabled',variable =self.Flag_S,style="A.TCheckbutton")
        self.Flag_R_gui = Checkbutton(self.frame_tcp,text='R',state='disabled',variable =self.Flag_R,style="A.TCheckbutton")
        self.Flag_P_gui = Checkbutton(self.frame_tcp,text='P',state='disabled',variable =self.Flag_P,style="A.TCheckbutton")
        self.Flag_A_gui = Checkbutton(self.frame_tcp,text='A',state='disabled',variable =self.Flag_A,style="A.TCheckbutton")
        self.Flag_U_gui = Checkbutton(self.frame_tcp,text='U',state='disabled',variable =self.Flag_U,style="A.TCheckbutton")
        self.Flag_E_gui = Checkbutton(self.frame_tcp,text='E',state='disabled',variable =self.Flag_E,style="A.TCheckbutton")
        self.Flag_C_gui = Checkbutton(self.frame_tcp,text='C',state='disabled',variable =self.Flag_C,style="A.TCheckbutton")
        self.Flag_F_gui.place(relx=0.22, y=121, anchor=tkinter.N)
        self.Flag_S_gui.place(relx=0.32, y=121, anchor=tkinter.N)
        self.Flag_R_gui.place(relx=0.42, y=121, anchor=tkinter.N)
        self.Flag_P_gui.place(relx=0.52, y=121, anchor=tkinter.N)
        self.Flag_A_gui.place(relx=0.62, y=121, anchor=tkinter.N)
        self.Flag_U_gui.place(relx=0.72, y=121, anchor=tkinter.N)
        self.Flag_E_gui.place(relx=0.82, y=121, anchor=tkinter.N)
        self.Flag_C_gui.place(relx=0.92, y=121, anchor=tkinter.N)
        self.TCP_port = IntVar(value=0)  
        self.TCP_port_gui = Checkbutton(self.frame_tcp,text='Random Port',variable =self.TCP_port,state='disabled',
                                               style="A.TCheckbutton",command=self.tcp_port_event)
        self.TCP_port_gui.place(relx=0.26, y=170, anchor=tkinter.CENTER)
        customtkinter.CTkLabel(self.frame_tcp, text = "Specific Port",height=16,text_font=("Century Gothic", 10)).place(x = 1,y =187)       
        self.tcp_entry_port = StringVar()
        self.tcp_entry_port_gui= Entry(self.frame_tcp, textvariable =self.tcp_entry_port,style="W.TEntry",width=4)
        self.tcp_entry_port_gui.insert(0,"80")
        self.tcp_entry_port_gui.config(state='disabled')
        self.tcp_entry_port_gui.place(relx=0.42, y=194, anchor=tkinter.CENTER)
        self.TCP_data = IntVar(value=0)  
        self.TCP_data_gui= Checkbutton(self.frame_tcp,text='Random data',variable =self.TCP_data,state='disabled',
                                               style="A.TCheckbutton",command=self.tcp_data_event)
        self.TCP_data_gui.place(relx=0.26, y=235, anchor=tkinter.CENTER)
        customtkinter.CTkLabel(self.frame_tcp, text = "Craft Data ",height=16,text_font=("Century Gothic", 10)).place(x = 1,y =255)       
        self.tcp_entry_data = StringVar()
        self.tcp_entry_data_gui = Entry(self.frame_tcp, textvariable =self.tcp_entry_data,style="W.TEntry",width=18)
        self.tcp_entry_data_gui.insert(0,"duyvu")
        self.tcp_entry_data_gui.config(state='disabled')
        self.tcp_entry_data_gui.place(relx=0.56, y=262, anchor=tkinter.CENTER)
        #endregion
        
        #region frame_layer7
        self.frame_layer7 = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=200,
                                                 height=130,
                                                 corner_radius=5)
        self.frame_layer7.place(relx=0.73, rely=0.17, anchor=tkinter.NW)
        customtkinter.CTkLabel(self.frame_main, text = "Layer7 Attack Types",width=200,text_font=("Century Gothic", 11)).place(relx=0.72, rely=0.1) 
        self.CheckSNMP = IntVar(value=0)
        self.CheckNTP = IntVar(value=0)
        self.CheckHTTP = IntVar(value=0)
        self.CheckHTTP_2 = IntVar(value=0)  
        Checkbutton(self.frame_layer7,text='SNMP Flood ',variable =self.CheckSNMP,style="W.TCheckbutton").place(relx=0.34, y=5, anchor=tkinter.N)
        Checkbutton(self.frame_layer7,text='NTP Flood ',variable =self.CheckNTP,style="W.TCheckbutton").place(relx=0.30, y=35, anchor=tkinter.N)
        Checkbutton(self.frame_layer7,text='HTTP Get Flood (★)',variable =self.CheckHTTP,style="W.TCheckbutton").place(relx=0.45, y=65, anchor=tkinter.N)
        Checkbutton(self.frame_layer7,text='HTTP Post Flood (★)',variable =self.CheckHTTP_2,style="W.TCheckbutton").place(relx=0.45, y=95, anchor=tkinter.N)
        #endregion
        
        #region frame_options 
        customtkinter.CTkLabel(self.frame_main, text = "Options",width=100,text_font=("Century Gothic", 11)).place(relx=0.72, rely=0.5) 
        self.frame_options  = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=200,
                                                 height=143,
                                                 corner_radius=5)
        self.frame_options.place(relx=0.73, rely=0.57, anchor=tkinter.NW)
        customtkinter.CTkLabel(self.frame_options, text = "Capture Time: ",height=16,text_font=("Century Gothic", 10)).place(relx=0.3, y=5, anchor=tkinter.N) 
        customtkinter.CTkLabel(self.frame_options, text = "Speed: ",height=16,text_font=("Century Gothic", 10)).place(relx=0.2, y=40, anchor=tkinter.N) 
        customtkinter.CTkLabel(self.frame_options, text = "Attach Malware File ",height=16,width=130,text_font=("Century Gothic", 10)).place(relx=0.35, y=75, anchor=tkinter.N) 
        self.label_slider = Label(self.frame_options, text = "1 second",font=("Century Gothic", 10,"italic"),style="B.TLabel")
        self.label_slider.place(relx=0.75, y=3, anchor=tkinter.N) 
        self.label_slider_2 = Label(self.frame_options, text = "1 thread",font=("Century Gothic", 10,"italic"),style="B.TLabel")
        self.label_slider_2.place(relx=0.7, y=37, anchor=tkinter.N) 
        self.time_slider = customtkinter.CTkSlider(master=self.frame_options,
                                                width=160,
                                                height=16,
                                                from_=1,
                                                to=50,
                                                border_width=5,
                                                command=self.time_slider_event)
        self.time_slider.place(relx=0.45, y=20, anchor=tkinter.N) 
        self.time_slider.set(3)
        
        self.speed_slider = customtkinter.CTkSlider(master=self.frame_options,
                                                width=160,
                                                height=16,
                                                from_=1,
                                                to=10,
                                                border_width=5,
                                                command=self.speed_slider_event)
        self.speed_slider.place(relx=0.45, y=56, anchor=tkinter.N) 
        self.speed_slider.set(1)
        
        self.malware_yes = IntVar(value=0)  
        self.malware_yes_gui = Checkbutton(self.frame_options,text='(★)',variable =self.malware_yes,
                                               style="A.TCheckbutton",command=self.malware_yes_event)
        self.malware_yes_gui.place(relx=0.85, y=72, anchor=tkinter.N) 
        self.Mal_TCP = IntVar(value=0)
        self.Mal_HTTP = IntVar(value=0)
        self.Mal_TCP_gui = Checkbutton(self.frame_options,text='TCP',state='disabled',variable =self.Mal_TCP,style="A.TCheckbutton")
        self.Mal_HTTP_gui = Checkbutton(self.frame_options,text='HTTP',state='disabled',variable =self.Mal_HTTP,style="A.TCheckbutton")
        self.Mal_TCP_gui.place(relx=0.20, y=90, anchor=tkinter.N)
        
        self.Mal_HTTP_gui.place(relx=0.55, y=90, anchor=tkinter.N)
        self.mal_file_name = Label(self.frame_options, text = "Choose File -->",style="C.TLabel")
        self.mal_file_name.place(relx=0.35, y=117, anchor=tkinter.N) 
        self.mal_button = tkinter.Button(self.frame_options, text ="...",height= 1, width=2,state='disabled',command =lambda: function.select_malware_file(self))
        self.mal_button.place(relx=0.75, y=111, anchor=tkinter.N)
        #endregion 
        
        #endregion
       
        #region ============ frame_cmd ============

        
        text = tkinter.Text(self.frame_cmd,height=10,width=40) 
        text.pack( side = LEFT, fill = BOTH )      
        #text.config(state=DISABLED)   
        
        scrollbar = tkinter.Scrollbar(self.frame_cmd)    
        scrollbar.pack(side='right', fill='y')

        text['yscrollcommand'] = scrollbar.set
        scrollbar['command'] = text.yview

        sys.stdout = Redirect(text)
        #endregion
        
        #region ============ frame_right ============
               
        customtkinter.CTkLabel(self.frame_right, text = "Bandwidth",width=90,text_font=("Arial", 12,"bold")).place(x = 10,y =17)
        customtkinter.CTkLabel(self.frame_right, text = "Data",width=40,text_font=("Arial", 12,"bold")).place(x = 120,y =17)
        customtkinter.CTkLabel(self.frame_right, text = "Packets",width=70,text_font=("Arial", 12,"bold")).place(x = 200,y =17)
        
        self.label_bandwidth = Label(self.frame_right, text = "0 Bps",font=("Arial", 11,"italic"),style="A.TLabel")
        self.label_bandwidth.place(x = 12,y =37) 
        
        self.label_size = Label(self.frame_right, text = "0 KB",font=("Arial", 11,"italic"),style="A.TLabel")
        self.label_size.place(x = 122,y =37)      
        
        self.label_count = Label(self.frame_right, text = "0",font=("Arial", 11,"italic"),style="A.TLabel")
        self.label_count.place(x = 212,y =37)     
              
        self.button_start = customtkinter.CTkButton(master=self.frame_right,
                                                    width=80,
                                                    height=40,
                                                border_color="#007455",
                                                bg_color="#00AF80",
                                                fg_color=None,
                                                hover_color="#007455",
                                                text="Start",
                                                command=self.start_button_event,
                                                border_width=3,
                                                corner_radius=8)
        self.button_start.place(relx=0.25, y=85, anchor=tkinter.N)
      
        self.button_stop = customtkinter.CTkButton(master=self.frame_right,
                                                border_color="#C12020",
                                                bg_color="#C12020",
                                                fg_color=None,
                                                hover_color="red",
                                                 width=80,
                                                    height=40,
                                                text="Stop",state="disabled",
                                                hover=False,
                                                command=self.stop_button_event,
                                                border_width=3,
                                                corner_radius=8)
        self.button_stop.place(relx=0.75, y=85, anchor=tkinter.N) 
        #endregion
    
    def check_arp_event(self):
        if self.checkbox_arp.get()==1:
            if self.arp_check.get()=="2":
                self.arp_entry_gui.config(state='enabled')
            self.arp_lan.config(state='enabled')
            self.arp_wan.config(state='enabled')
        else:
            self.arp_entry_gui.config(state='disabled')
            self.arp_lan.config(state='disabled')
            self.arp_wan.config(state='disabled')

    def arp_lan_event(self):
        if self.arp_check.get()=="2":
            self.arp_entry_gui.config(state='enabled')
        else:
            self.arp_entry_gui.config(state='disabled')    
                                  
    def check_udp_event(self):
        if self.checkbox_udp.get()==1:
            if self.UDP_port.get()==0:
                self.udp_entry_port_gui.config(state='enabled')
            if self.UDP_data.get()==0:
                self.udp_entry_data_gui.config(state='enabled')
            
            self.UDP_data_gui.config(state='enabled')
            self.UDP_port_gui.config(state='enabled')
        else:
            self.udp_entry_port_gui.config(state='disabled')    
            self.udp_entry_data_gui.config(state='disabled')  
            self.UDP_data_gui.config(state='disabled')  
            self.UDP_port_gui.config(state='disabled')  

    def udp_port_event(self):
        if self.UDP_port.get()==1:
            self.udp_entry_port_gui.config(state='disabled')
        else:
            self.udp_entry_port_gui.config(state='enabled')

    def udp_data_event(self):
        if self.UDP_data.get()==1:
            self.udp_entry_data_gui.config(state='disabled')
        else:
            self.udp_entry_data_gui.config(state='enabled')
                          
    def check_tcp_event(self):
        if self.checkbox_tcp.get()==1:
            self.tcp_type_gui1.config(state='enabled')
            self.tcp_type_gui2.config(state='enabled')
            if str(self.tcp_type.get())=="1":#default
                self.tcp_ex_gui1.config(state='enabled')
                self.tcp_ex_gui2.config(state='enabled')
                self.tcp_ex_gui3.config(state='enabled')
                self.Flag_F_gui.config(state='disabled')
                self.Flag_S_gui.config(state='disabled')
                self.Flag_R_gui.config(state='disabled')
                self.Flag_P_gui.config(state='disabled')
                self.Flag_A_gui.config(state='disabled')
                self.Flag_U_gui.config(state='disabled')
                self.Flag_E_gui.config(state='disabled')
                self.Flag_C_gui.config(state='disabled')
                self.tcp_entry_port_gui.config(state='disabled')
                self.tcp_entry_data_gui.config(state='disabled')
                self.TCP_port_gui.config(state='disabled')
                self.TCP_data_gui.config(state='disabled')
            else :
                self.tcp_ex_gui1.config(state='disabled')
                self.tcp_ex_gui2.config(state='disabled')
                self.tcp_ex_gui3.config(state='disabled')
                self.Flag_F_gui.config(state='enabled')
                self.Flag_S_gui.config(state='enabled')
                self.Flag_R_gui.config(state='enabled')
                self.Flag_P_gui.config(state='enabled')
                self.Flag_A_gui.config(state='enabled')
                self.Flag_U_gui.config(state='enabled')
                self.Flag_E_gui.config(state='enabled')
                self.Flag_C_gui.config(state='enabled')
                if self.TCP_port.get()==0:
                    self.tcp_entry_port_gui.config(state='enabled')
                if self.TCP_data.get()==0:
                    self.tcp_entry_data_gui.config(state='enabled')
                self.TCP_port_gui.config(state='enabled')
                self.TCP_data_gui.config(state='enabled')
        else:
            self.tcp_type_gui1.config(state='disabled')
            self.tcp_type_gui2.config(state='disabled')
            if str(self.tcp_type.get())=="1":#default
                self.tcp_ex_gui1.config(state='disabled')
                self.tcp_ex_gui2.config(state='disabled')
                self.tcp_ex_gui3.config(state='disabled')
            else :
                self.Flag_F_gui.config(state='disabled')
                self.Flag_S_gui.config(state='disabled')
                self.Flag_R_gui.config(state='disabled')
                self.Flag_P_gui.config(state='disabled')
                self.Flag_A_gui.config(state='disabled')
                self.Flag_U_gui.config(state='disabled')
                self.Flag_E_gui.config(state='disabled')
                self.Flag_C_gui.config(state='disabled')
                self.tcp_entry_port_gui.config(state='disabled')
                self.tcp_entry_data_gui.config(state='disabled')
                self.TCP_port_gui.config(state='disabled')
                self.TCP_data_gui.config(state='disabled')

    def tcp_port_event(self):
        if self.TCP_port.get()==1:
            self.tcp_entry_port_gui.config(state='disabled')
        else:
            self.tcp_entry_port_gui.config(state='enabled')

    def tcp_data_event(self):
        if self.TCP_data.get()==1:
            self.tcp_entry_data_gui.config(state='disabled')
        else:
            self.tcp_entry_data_gui.config(state='enabled')        
    
    def time_slider_event(self,event):
        self.label_slider["text"] = str(int(self.time_slider.get())) + " second"
    def speed_slider_event(self,event):
        self.label_slider_2["text"] = str(int(self.speed_slider.get())) + " thread"   
    def malware_yes_event(self):
        if self.malware_yes.get()==1:
            self.Mal_TCP_gui.config(state='enabled')
            self.Mal_HTTP_gui.config(state='enabled')
            self.mal_file_name.configure(foreground = "white")
            self.mal_button.config(state='active')

        else:
            self.Mal_TCP_gui.config(state='disabled')
            self.Mal_HTTP_gui.config(state='disabled')
            self.mal_file_name.configure(foreground = "gray")
            self.mal_button.config(state='disabled')
        
        
                
    def start_button_event(self):
        ip_target = str(self.target_entry.get())
        if function.is_fqdn(ip_target)==False:
            messagebox.showinfo("Thông báo", "IP không hợp lệ")
        elif self.checkbox_udp.get() == 1 and self.UDP_port.get() != 1 and function.portValid(self.udp_entry_port.get())== False:
            messagebox.showinfo("Thông báo", "UDP port không đúng định dạng, không thể thực hiện tấn công UDP")
        elif self.checkbox_tcp.get() == 1 and str(self.tcp_type.get())=="2" and self.TCP_port.get() != 1 and function.portValid(self.tcp_entry_port.get())== False:
            messagebox.showinfo("Thông báo", "TCP port không đúng định dạng, không thể thực hiện tấn công TCP")
        elif self.checkbox_arp.get()==1 and self.arp_check.get()=="2":
            if str(function.get_mac(ip_target))=="None":
                messagebox.showinfo("Thông báo", "Target IP không thuộc mạng LAN, không thể thực hiện tấn công LAN Spoof")
            else:
                if function.IPvalid(str(self.arp_entry.get()))==False:
                    messagebox.showinfo("Thông báo", "IP host không đúng định dạng IP, vui lòng nhập lại IP host")
        elif function.checkTrueInterface(self)==False:
            messagebox.showinfo("Thông báo", "Dữ liệu sinh không qua Interface này, vui lòng chọn đúng Interface")
        elif self.malware_yes.get()==1 and (self.Mal_TCP.get()==1 or self.Mal_HTTP.get()==1) and function.has_mal_file(self)==False:
                messagebox.showinfo("Thông báo", "Chưa chọn file Mã độc")
        else:
            if function.Beginable(self)== True : 
                
                self.TrafficLog = sniff(iface=str(self.network_adapter.get()), prn=lambda x: x.summary(),count=1)
                self.BeginTime = function.getDatetimeNow()
                self.threads = []
                ip_target=function.fqdn_to_ip(ip_target)                       
                self.button_start.config(state='disabled')
                self.button_start.hover=False
                self.button_start.configure(text_color = "black")
                
                
                t = function.thread_with_trace(target = function.capture,args=(ip_target,self,str(self.network_adapter.get()),int(self.time_slider.get()), ))
                t.start()
                self.threads.append(t)
                speed = int(self.speed_slider.get())
                if self.checkbox_arp.get()==1:
                    if  self.arp_check.get()=="1":
                        for i in range(0,speed):
                            t = function.thread_with_trace(target = function.broastcast,args=(ip_target, )  )
                            t.start()
                            self.threads.append(t)  
                    else:
                        t = function.thread_with_trace(target = function.spoof,args=(ip_target,ip_target,True,)  )
                        t.start()
                        self.threads.append(t)  
                if self.icmp_check.get() =="2":
                    for i in range(0,speed):
                        t = function.thread_with_trace(target = function.icmp,args=(ip_target, )  )
                        t.start()
                        self.threads.append(t) 
                if self.icmp_check.get() =="3":
                    for i in range(0,speed):
                        t = function.thread_with_trace(target = function.malform_icmp,args=(ip_target, )  )
                        t.start()
                        self.threads.append(t)                 
                if self.checkbox_udp.get() == 1:
                        udp_des_port= 1
                        if self.UDP_port.get() == 1:
                            udp_des_port= RandShort()
                        else:
                            udp_des_port= int(self.udp_entry_port.get())
                            
                        udp_data = ""
                        if self.UDP_data.get() == 1 :
                            udp_data= function.randData()
                        else:
                            udp_data = str(self.udp_entry_data.get())
                        
                        for i in range(0,speed):          
                            t = function.thread_with_trace(target = function.udp,args=(ip_target,udp_des_port,udp_data )  )
                            t.start()
                            self.threads.append(t)                 
                if self.checkbox_tcp.get() == 1:
                    flag = "" 
                    if str(self.tcp_type.get())=="1":    #normal
                        if str(self.tcp_ex.get())=="1":  #syn
                            flag = "S" 
                            for i in range(0,speed): 
                                t = function.thread_with_trace(target = function.tcp,args=(ip_target,RandShort(),flag,function.randData() )  )
                                t.start()
                                self.threads.append(t)   
                        if str(self.tcp_ex.get())=="2":  #xmas
                            flag = "FSRPAUEC"
                            for i in range(0,speed): 
                                t = function.thread_with_trace(target = function.tcp,args=(ip_target,RandShort(),flag,function.randData() )  )
                                t.start()
                                self.threads.append(t)   
                        if str(self.tcp_ex.get())=="3":
                                tcp_data = function.randData()
                                if self.malware_yes.get()==1 and self.Mal_TCP.get()==1:
                                    tcp_data = self.malware_gift  
                               
                                t = function.thread_with_trace(target = function.tcp_stream,args=(ip_target,tcp_data,1 )  )
                                t.start()
                                self.threads.append(t)  
                                if speed > 1:
                                    for i in range(1,speed): 
                                        t = function.thread_with_trace(target = function.tcp_stream,args=(ip_target,tcp_data,0 )  )
                                        t.start()
                                        self.threads.append(t)       
                         
                        
                    else:  
                            if self.Flag_F.get()==1:
                                flag += "F"     
                            if self.Flag_S.get()==1:
                                flag += "S" 
                            if self.Flag_R.get()==1:
                                flag += "R" 
                            if self.Flag_P.get()==1:
                                flag += "P" 
                            if self.Flag_A.get()==1:
                                flag += "A" 
                            if self.Flag_U.get()==1:
                                flag += "U" 
                            if self.Flag_E.get()==1:
                                flag += "E" 
                            if self.Flag_C.get()==1:
                                flag += "C"
                            
                            tcp_data= str(self.tcp_entry_data.get()) 
                            tcp_des_port= 1
                            
                            if self.TCP_port.get() == 1:
                                tcp_des_port= RandShort()   
                            else:
                                tcp_des_port= int(self.tcp_entry_port.get())
                            if self.TCP_data.get() == 1:
                                tcp_data= function.randData()  
                            for i in range(0,speed):
                                t = function.thread_with_trace(target = function.tcp,args=(ip_target,tcp_des_port,flag,tcp_data )  )
                                t.start()
                                self.threads.append(t)                                                           
                if self.CheckNTP.get() == 1:
                    for i in range(0,speed):
                        t = function.thread_with_trace(target = function.ntp,args=(ip_target, )  )
                        t.start()
                        self.threads.append(t)
                if self.CheckSNMP.get() == 1:
                    for i in range(0,speed):
                        t = function.thread_with_trace(target = function.snmp,args=(ip_target, )  )
                        t.start()
                        self.threads.append(t)
                if self.CheckHTTP.get() == 1:
                    check=False
                    if self.malware_yes.get()==1 and self.Mal_HTTP.get()==1:
                        check=True
                    for i in range(0,speed):
                        t = function.thread_with_trace(target = function.http,args=(ip_target,80,1,self,check, )  )
                        t.start()
                        self.threads.append(t)
                if self.CheckHTTP_2.get() == 1:
                    check=False
                    if self.malware_yes.get()==1 and self.Mal_HTTP.get()==1:
                        check=True
                    for i in range(0,speed):
                        t = function.thread_with_trace(target = function.http,args=(ip_target,80,2,self,check, )  )
                        t.start()
                        self.threads.append(t)
             
               
            else:
                messagebox.showinfo("Thông báo", "chưa chọn chức năng")        
                      
    def stop_button_event(self): 
        self.button_start.config(state='enabled')
        self.button_start.hover=True
        self.button_start.configure(text_color = "white")
        self.button_stop.configure(text_color = "black")
        self.button_stop.configure(bg_color = "red")
        self.button_stop.configure(hover_color = "#C12020")
        self.button_stop.config(state='disabled')
        self.button_stop.hover=False
        for t in self.threads:
            t.kill()
        print("\nTERMINATE   !!!")
        
    def on_closing(self, event=0):
        if self.button_start.state=='disabled':
            for t in self.threads:
                t.kill()
        self.destroy()
        #sys.exit()
        #quit()

    def start(self):
        self.mainloop()



if __name__ == "__main__":
    app = App()
    app.start()