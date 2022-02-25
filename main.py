import tkinter
from tkinter import messagebox
from tkinter import *
from tkinter.ttk import *
import customtkinter
from pygments.console import dark_colors
import function

# Set dark appearance mode:
customtkinter.set_appearance_mode("Dark")  # Other: "Light", "System" 
                     
def donothing():
         filewin = Toplevel(self)
         button = Button(filewin, text="Do nothing button")
         button.pack()
         
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
        # if sys.platform == "darwin":
        #     self.bind("<Command-q>", self.on_closing)
        #     self.bind("<Command-w>", self.on_closing)
        #     self.createcommand('tk::mac::Quit', self.on_closing)
        
        #region menu
        menubar = Menu(self)
        filemenu = Menu(menubar, tearoff=0)
        filemenu.add_command(label="Save", command=donothing)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.quit)
        
        helpmenu = Menu(menubar, tearoff=0)
        helpmenu.add_command(label="Help Index", command=donothing)
        helpmenu.add_command(label="About...", command=donothing)
        
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
        entry = customtkinter.CTkEntry(master=self.frame_main,    
                               width=150,
                               height=25,
                               corner_radius=10)
        entry.place(relx=0.1, rely=0.05, anchor=tkinter.CENTER)
        entry.insert(0,"IP Target")
          
        
        #region frame arp
       
        self.checkbox_arp = customtkinter.CTkCheckBox(master=self.frame_main,
                                              width=15,
                                              height=15,
                                              fg_color="#D8554D",
                                              border_color="#D60C42",
                                              hover_color="#7F7F7F",
                                              text_font=("Century Gothic", 11),
                                              border_width=1.5,command=self.check_arp_event,
                                     text="ARP Spoof")
        self.checkbox_arp.place(relx=0.08, rely=0.12, anchor=tkinter.CENTER) 
        
        self.frame_arp = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=120,
                                                 height=90,
                                                 corner_radius=5)
        self.frame_arp.place(relx=0.085, rely=0.16, anchor=tkinter.N)
        # self.arp_entry = customtkinter.CTkEntry(master=self.frame_arp,    
        #                        width=90,
        #                        height=25,
        #                        corner_radius=10)
        # self.arp_entry.place(relx=0.47, rely=0.3, anchor=tkinter.N)
        # self.arp_entry.insert(0,"IP Host")
        self.arp_entry = StringVar()
        self.arp_entry_gui= Entry(self.frame_arp, textvariable =self.arp_entry,style="W.TEntry",width=16)
        self.arp_entry_gui.insert(0,"IP Host")
        self.arp_entry_gui.config(state='disabled')
        self.arp_entry_gui.place(relx=0.47, rely=0.3, anchor=tkinter.N)
        #endregion
     
        #region frame icmp
        customtkinter.CTkLabel(self.frame_main, text = "ICMP",text_font=("Century Gothic", 11)).place(relx=0.15, rely=0.09) 
        self.frame_icmp = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=120,
                                                 height=90,
                                                 corner_radius=5)
        
        
        self.frame_icmp.place(relx=0.245, rely=0.16, anchor=tkinter.N)
        self.icmp_check = StringVar(self,"1")
        Radiobutton(self.frame_icmp, text ="None", style="W.TRadiobutton",
                    variable =self.icmp_check,value ="1").place(relx=0.3, y=5, anchor=tkinter.N)        
        Radiobutton(self.frame_icmp, text ="Normal", style="W.TRadiobutton",
                    variable =self.icmp_check,value = "2").place(relx=0.35, y=30, anchor=tkinter.N)
        Radiobutton(self.frame_icmp, text ="Malformed", style="W.TRadiobutton",
                    variable =self.icmp_check,value = "3").place(relx=0.4, y=55, anchor=tkinter.N)
        #endregion
          
        
        #region frame_udp
        self.checkbox_udp = customtkinter.CTkCheckBox(master=self.frame_main,
                                              width=15,
                                              height=15,
                                              fg_color="#D8554D",
                                              border_color="#D60C42",
                                              hover_color="#7F7F7F",
                                              text_font=("Century Gothic", 11),
                                              border_width=1.5,command=self.check_udp_event,
                                     text="UDP")
        self.checkbox_udp.place(relx=0.05, rely=0.43, anchor=tkinter.CENTER) 
        self.frame_udp = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=250,
                                                 height=150,
                                                 corner_radius=5)
        self.frame_udp.place(relx=0.165, y=190, anchor=tkinter.N)
        self.UDP_port = IntVar(value=0)  
        self.UDP_port_gui= Checkbutton(self.frame_udp,text='Random Port',variable =self.UDP_port,
                                               style="A.TCheckbutton",state='disabled')
        self.UDP_port_gui.place(relx=0.26, rely=0.12, anchor=tkinter.CENTER)
        customtkinter.CTkLabel(self.frame_udp, text = "Specific Port",height=16,text_font=("Century Gothic", 10)).place(x = 1,y =35)       
        # self.entry_port_udp = customtkinter.CTkEntry(master=self.frame_udp,    
        #                        width=37,
        #                        height=20,
        #                        corner_radius=10)
        # self.entry_port_udp.place(relx=0.5, rely=0.27, anchor=tkinter.CENTER)
        # self.entry_port_udp.insert(0,"80")
        self.udp_entry_port = StringVar()
        self.udp_entry_port_gui= Entry(self.frame_udp, textvariable =self.udp_entry_port,style="W.TEntry",width=4)
        self.udp_entry_port_gui.insert(0,"80")
        self.udp_entry_port_gui.config(state='disabled')
        self.udp_entry_port_gui.place(relx=0.5, rely=0.27, anchor=tkinter.CENTER)
        
        self.UDP_data = IntVar(value=0)  
        self.UDP_data_gui= Checkbutton(self.frame_udp,text='Random data',variable =self.UDP_data,
                                               style="A.TCheckbutton",state='disabled')
        self.UDP_data_gui.place(relx=0.26, rely=0.57, anchor=tkinter.CENTER)
        customtkinter.CTkLabel(self.frame_udp, text = "Craft Data ",height=15,text_font=("Century Gothic", 10)).place(x = 1,y =99)       
        # self.entry_data_udp = customtkinter.CTkEntry(master=self.frame_udp,    
        #                        width=130,
        #                        height=20,
        #                        corner_radius=10)
        # self.entry_data_udp.place(relx=0.67, rely=0.715, anchor=tkinter.CENTER)
        # self.entry_data_udp.insert(0,"duyvu")
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
                                              border_color="#D60C42",
                                              hover_color="#7F7F7F",
                                              text_font=("Century Gothic", 11),
                                              border_width=1.5,command=self.check_tcp_event,
                                     text="TCP")
        self.checkbox_tcp.place(relx=0.42, rely=0.12, anchor=tkinter.CENTER)         
        self.frame_tcp = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=300,
                                                 height=300,
                                                 corner_radius=5)
        self.frame_tcp.place(relx=0.34, rely=0.16, anchor=tkinter.NW)
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
        self.tcp_ex_gui1.place(relx=0.65, y=5, anchor=tkinter.N)
        self.tcp_ex_gui2 = Radiobutton(self.frame_tcp_kid, text ="Xmas Flood", style="A.TRadiobutton",state='disabled',
                    variable =self.tcp_ex,value = "2")
        self.tcp_ex_gui2.place(relx=0.68, y=30, anchor=tkinter.N)
        
        self.tcp_type_gui1 = Radiobutton(self.frame_tcp_kid, text ="Default", style="A.TRadiobutton",state='disabled',
                    variable =self.tcp_type,value = "1",command=self.check_tcp_event)
        self.tcp_type_gui1.place(relx=0.2, y=5, anchor=tkinter.N)
        self.tcp_type_gui2 = Radiobutton(self.frame_tcp, text ="Craft", style="W.TRadiobutton",state='disabled',
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
                                               style="A.TCheckbutton")
        self.TCP_port_gui.place(relx=0.26, y=170, anchor=tkinter.CENTER)
        customtkinter.CTkLabel(self.frame_tcp, text = "Specific Port",height=16,text_font=("Century Gothic", 10)).place(x = 1,y =187)       
        # self.entry_port_tcp = customtkinter.CTkEntry(master=self.frame_tcp,    
        #                        width=37,
        #                        height=20,
        #                        corner_radius=10)
        # self.entry_port_tcp.place(relx=0.42, y=194, anchor=tkinter.CENTER)
        # self.entry_port_tcp.insert(0,"80") 
        self.tcp_entry_port = StringVar()
        self.tcp_entry_port_gui= Entry(self.frame_tcp, textvariable =self.tcp_entry_port,style="W.TEntry",width=4)
        self.tcp_entry_port_gui.insert(0,"80")
        self.tcp_entry_port_gui.config(state='disabled')
        self.tcp_entry_port_gui.place(relx=0.42, y=194, anchor=tkinter.CENTER)
        self.TCP_data = IntVar(value=0)  
        self.TCP_data_gui= Checkbutton(self.frame_tcp,text='Random data',variable =self.TCP_data,state='disabled',
                                               style="A.TCheckbutton")
        self.TCP_data_gui.place(relx=0.26, y=235, anchor=tkinter.CENTER)
        customtkinter.CTkLabel(self.frame_tcp, text = "Craft Data ",height=16,text_font=("Century Gothic", 10)).place(x = 1,y =255)       
        # self.entry_data_tcp = customtkinter.CTkEntry(master=self.frame_tcp,    
        #                        width=130,
        #                        height=20,
        #                        corner_radius=10)
        # self.entry_data_tcp.place(relx=0.56, y=262, anchor=tkinter.CENTER)
        # self.entry_data_tcp.insert(0,"duyvu")
        self.tcp_entry_data = StringVar()
        self.tcp_entry_data_gui = Entry(self.frame_tcp, textvariable =self.tcp_entry_data,style="W.TEntry",width=18)
        self.tcp_entry_data_gui.insert(0,"duyvu")
        self.tcp_entry_data_gui.config(state='disabled')
        self.tcp_entry_data_gui.place(relx=0.56, y=262, anchor=tkinter.CENTER)
        #endregion
        
        #region frame_layer7
        self.frame_layer7 = customtkinter.CTkFrame(master=self.frame_main,
                                                 width=200,
                                                 height=100,
                                                 corner_radius=5)
        self.frame_layer7.place(relx=0.73, rely=0.16, anchor=tkinter.NW)
        customtkinter.CTkLabel(self.frame_main, text = "Layer7",text_font=("Century Gothic", 11)).place(relx=0.72, rely=0.09) 
        self.CheckSNMP = IntVar(value=0)
        self.CheckNTP = IntVar(value=0)
        self.CheckHTTP = IntVar(value=0) 
        Checkbutton(self.frame_layer7,text='SNMP',variable =self.CheckSNMP,style="W.TCheckbutton").place(relx=0.2, y=10, anchor=tkinter.N)
        Checkbutton(self.frame_layer7,text='NTP',variable =self.CheckNTP,style="W.TCheckbutton").place(relx=0.6, y=10, anchor=tkinter.N)
        Checkbutton(self.frame_layer7,text='HTTP',variable =self.CheckHTTP,style="W.TCheckbutton").place(relx=0.2, y=45, anchor=tkinter.N)
        #endregion
        
        #endregion
       
        #region ============ frame_cmd ============

        
        text = tkinter.Text(self.frame_cmd,height=10,width=40) 
        text.pack( side = LEFT, fill = BOTH )      
        text.config(state=DISABLED)   
        
        scrollbar = tkinter.Scrollbar(self.frame_cmd)    
        scrollbar.pack(side='right', fill='y')

        text['yscrollcommand'] = scrollbar.set
        scrollbar['command'] = text.yview

        #old_stdout = sys.stdout    
        #sys.stdout = Redirect(text)
        #endregion
        
        #region ============ frame_right ============
               
        self.label_bandwidth= customtkinter.CTkLabel(self.frame_right, text = "Bandwidth",text_font=("Arial", 12)).place(x = -12,y =17)
        self.label_bandwidth= customtkinter.CTkLabel(self.frame_right, text = "Size",text_font=("Arial", 12)).place(x = -12,y =67)   
        self.button_start = customtkinter.CTkButton(master=self.frame_right,
                                                    width=80,
                                                    height=40,
                                                border_color="#007455",
                                                bg_color="#007455",
                                                fg_color=None,
                                                hover_color="#00AF80",
                                                text="Start",
                                                command=self.start_button_event,
                                                border_width=3,
                                                corner_radius=8)
        self.button_start.place(relx=0.75, y=25, anchor=tkinter.N)

        
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
        #if str(self.arp_entry_gui["state"])=="disabled":
        if self.checkbox_arp.get()==1:
            self.arp_entry_gui.config(state='enabled')
        else:
            self.arp_entry_gui.config(state='disabled')
            
    def check_udp_event(self):
        if self.checkbox_udp.get()==1:
            self.udp_entry_port_gui.config(state='enabled')
            self.udp_entry_data_gui.config(state='enabled')
            self.UDP_data_gui.config(state='enabled')
            self.UDP_port_gui.config(state='enabled')
        else:
            self.udp_entry_port_gui.config(state='disabled')    
            self.udp_entry_data_gui.config(state='disabled')  
            self.UDP_data_gui.config(state='disabled')  
            self.UDP_port_gui.config(state='disabled')  
                       
    def check_tcp_event(self):
        if self.checkbox_tcp.get()==1:
            self.tcp_type_gui1.config(state='enabled')
            self.tcp_type_gui2.config(state='enabled')
            if str(self.tcp_type.get())=="1":#default
                self.tcp_ex_gui1.config(state='enabled')
                self.tcp_ex_gui2.config(state='enabled')
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
                self.Flag_F_gui.config(state='enabled')
                self.Flag_S_gui.config(state='enabled')
                self.Flag_R_gui.config(state='enabled')
                self.Flag_P_gui.config(state='enabled')
                self.Flag_A_gui.config(state='enabled')
                self.Flag_U_gui.config(state='enabled')
                self.Flag_E_gui.config(state='enabled')
                self.Flag_C_gui.config(state='enabled')
                self.tcp_entry_port_gui.config(state='enabled')
                self.tcp_entry_data_gui.config(state='enabled')
                self.TCP_port_gui.config(state='enabled')
                self.TCP_data_gui.config(state='enabled')
        else:
            self.tcp_type_gui1.config(state='disabled')
            self.tcp_type_gui2.config(state='disabled')
            if str(self.tcp_type.get())=="1":#default
                self.tcp_ex_gui1.config(state='disabled')
                self.tcp_ex_gui2.config(state='disabled')
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
            
            
    def start_button_event(self):
        self.button_start.config(state='disabled')
        self.button_start.hover=False
        self.button_stop.config(state='enabled')
        self.button_stop.hover=True
       # messagebox.showinfo("showinfo", function.test())
              
    def stop_button_event(self):
        self.button_start.config(state='enabled')
        self.button_start.hover=True
        self.button_stop.config(state='disabled')
        self.button_stop.hover=False

    def on_closing(self, event=0):
        self.destroy()

    def start(self):
        self.mainloop()


if __name__ == "__main__":
    app = App()
    app.start()