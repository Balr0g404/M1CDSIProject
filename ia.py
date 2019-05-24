#!/usr/bin/python3
#coding: utf-8

from random import randint
import tensorflow as tf
import numpy as np
import sys
import os
import parsing #Algorithme d'extraction des attributs

def Help():
    print("="*25+" HELP "+"="*25)
    print("# -v          Rend le programmes plus parlant")
    print("# -s          Analyse statique")
    print("# -d          Analyse dynamique")
    print("# -bdd        Dataset de malware pour entrainement")
    print("# -f          Fichier à analyser")
    print("="*(50+(len(" HELP "))))


# VARIABLE
dynamique = False
statique = False
verbose = False
dataset_path = ""
file = ""
###
def arg_gestion(arg):
    global dynamique
    global statique
    global verbose
    global dataset_path
    global file
    if len(arg) <= 1:
        Help()
        sys.exit()
    if "-v" in arg:
        verbose = True
    if "-h" in arg:
        Help()
        sys.exit()
    if "-s" in arg:
        if verbose:
            print("[+] Analyse statique demandée")
        statique = True
    if "-d" in arg:
        if verbose:
            print("[+] Analyse dynamique demandée")
        dynamique = True
        print("[x] Analyse dynamique non implementée ! ")
    if "-bdd" in arg:
        try:
            if arg[arg.index("-bdd")+1][0] != "-":
                if verbose:
                    print("[+] Dataset fournis - Utilisation de "+arg[arg.index("-bdd")+1])
                dataset = arg[arg.index("-bdd")+1]
            else:
                if verbose:
                    print("[-] Erreur sur la dataset fournis")
                    sys.exit()
        except:
            if verbose:
                print("[-] Erreur paramètre dataset présent mais non fourni")
                sys.exit()
    else:
        if verbose:
            print ("[+] Dataset non fournis - Utilisation de celle par défaut")
            print ("[-] On en a pas encore alors sorry :'(")
    if "-f" in arg:
        try:
            if arg[arg.index("-f")+1][0] != "-":
                if verbose:
                    print("[+] Fichier à tester : "+arg[arg.index("-f")+1])
                file = arg[arg.index("-f")+1]
                try:
                    if file.split('.')[1] != "exe":
                        print("[-] Le fichier fournis est non executable")
                        sys.exit()
                except:
                    sys.exit()
            else:
                if verbose:
                    print("[-] Erreur sur le fichier d'entrée fournis")
        except:
            if verbose:
                print("[-] Erreur paramètre fichier présent mais non fourni")


arg_gestion(sys.argv)
print("\n")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' #Sert à cacher les warnings de tensorflow 2.0 alpha
assert hasattr(tf, "function") # Pour être sûr d'utiliser tensorflow 2.0

if file != "":
    path_to_file = file
else:
    path_to_file = input("Merci de renseigner le chemin vers le malware \n")
    try:
        if path_to_file.split('.')[1] != "exe":
            print("[-] Le fichier fournis est non executable")
            sys.exit()
    except:
        sys.exit()

features = parsing.JSON_PARSING(path_to_file, 1) #On extrait les attributs d'un malware
features_list = features.get()

for i in range(len(features_list)): #On convertit tous les hash en entier pour pouvoir
    if type(features_list[i]) == str: # les donner en entrée au réseau
        features_list[i] = int(features_list[i],16)

input = np.array([features_list])
input = input.astype('float32')
model = tf.keras.models.Sequential()

model.add(tf.keras.layers.Dense(256, activation="tanh"))
model.add(tf.keras.layers.Dense(126, activation="tanh"))
model.add(tf.keras.layers.Dense(2, activation="softmax"))

model.compile(loss="sparse_categorical_crossentropy",optimizer="sgd",metrics=["accuracy"])

output = model.predict(input)
# print(output)
# if output[0][0] > 0.5:
#     print("Ce fichier est un malware !")
# else:
#     print("Ce fichier est sain.")

listeoui = ['oui','C\'est un malware','En effet nous avons affaire a un malware','WARNING MALWARE DETECTED','Cachez vous ! un malware !','Alerte Rouge !!']
listenon = ['non','On est safe c\'est pas un malware','Fausse Alerte','On remballe, pas de malware ici','Aboard the mission','RAS']
print("Verdict : \n")
if output[0][0] > 0.5:
  print(listeoui[randint(0,len(listeoui)-1)])
else:
  print(listenon[randint(0,len(listenon)-1)])
