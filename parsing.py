#!/usr/bin/python3
#coding: utf-8

import json
import inspect
from os import popen
from sys import exit

class JSON_PARSING:
    def __init__(self,filename,verbose):
        self.verbose = verbose
        self.getJSON(filename)
    def getJSON(self,filename):
        # command = ['python3','peframe-cli.py',filename,'-j']
        command = "python3 peframe-cli.py "+filename+" -j"
        text = popen(command,'r')
        self.parsing(text.read())

    def parsing(self,text):
        try:
            self.text = json.loads(text)
        except:
            print("[-] Erreur ouverture du fichier")
            exit()
        self.extract()
    def extract(self):
        #self.filename = self.text['filename']
        self.md5hash = self.text['hashes']['md5']
        self.sha1hash = self.text['hashes']['sha1']
        self.sha2hash = self.text['hashes']['sha256']
        self.numberBreakpoint = len(self.text['peinfo']['breakpoint'])
        self.socketIsPresent = 1 if "socket" in self.text['peinfo']['breakpoint'] else 0
        self.numberBehavior = len(self.text['peinfo']['behavior'])
        count = 0
        if "network_tcp_socket" in self.text['peinfo']['behavior']:
            count+=1
        if "win_mutex" in self.text['peinfo']['behavior']:
            count+=1
        if "win_files_operation" in self.text['peinfo']['behavior']:
            count+=1
        self.suspectBehavior = count
        count = 0
        self.antidbg = len(self.text['peinfo']['features']['antidbg'])
        self.antivm = len(self.text['peinfo']['features']['antivm'])
        self.crypto = len(self.text['peinfo']['features']['crypto'])
        self.mutex = len(self.text['peinfo']['features']['mutex'])
        self.xornumber = len(self.text['peinfo']['features']['xor'])
        self.imphash = self.text['peinfo']['imphash']
        self.size_of_raw_data = 0
        self.virtual_address = 0
        self.virtual_size = 0
        try:
            self.debug = self.text['peinfo']['directories']['debug']['size']
        except:
            if self.verbose:
                print('Error debug size')
        try:
            self.size_of_raw_data = self.text['peinfo']['sections']['details'][0]['size_of_raw_data']
            self.virtual_address = self.text['peinfo']['sections']['details'][0]['virtual_address']
            self.virtual_size = self.text['peinfo']['sections']['details'][0]['virtual_size']
        except:
            if self.verbose:
                print('peinfo -> sections -> details ERROR')
        # self.nbfile = len(self.text['strings']['file'])
        # self.nbip = len(self.text['strings']['ip'])
        # self.nburl = len(self.text['strings']['url'])
    def get(self):
        l = []
        attributes = inspect.getmembers(self, lambda a:not(inspect.isroutine(a)))
        for i in [a for a in attributes if not(a[0].startswith('__') and a[0].endswith('__'))]:
            if i[0] != "text":
                l.append(i[1])
        return l


if __name__ == "__main__":
    a = JSON_PARSING("meterpreter.exe",1)
    liste = a.get()
    for i in range(len(liste)):
        if type(liste[i]) == str:
            liste[i] = int(liste[i],16)

    print(liste)
