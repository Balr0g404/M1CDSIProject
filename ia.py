#!/usr/bin/python3
#coding: utf-8

from random import randint
import tensorflow as tf
import numpy as np
import sys
import os
import parsing #Algorithme d'extraction des attributs

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' #Sert à cacher les warnings de tensorflow 2.0 alpha
assert hasattr(tf, "function") # Pour être sûr d'utiliser tensorflow 2.0

try:
    path_to_file = sys.argv[1]
except:
    path_to_file = input("Merci de renseigner le chemin vers le malware \n")

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

if output[0][0] > 0.5:
  print(listeoui[randint(0,len(listeoui)-1)])
else:
  print(listenon[randint(0,len(listenon)-1)])
