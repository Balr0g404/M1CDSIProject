# Projet détéction de malware

Ce code consiste en une intelligence artificielle capable de détécter si un fichier qu'on lui passe en paramètre est un malware ou non.

Pour l'instant, seule une analyse statique est implémentée. De plus, à cause d'un problème d'accès à une base de données, le réseau n'est pas entrainé.

Pour installer les dépendances, on tape :

```Bash
pip3 install -r requirements.txt
pip install tensorflow==2.0.0-alpha0 
```

 

Pour lancer l'algorithme, on fait 

```bash
./ia.py [chemin_du_fichier_à_analyser]
```

