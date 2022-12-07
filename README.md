# Projet Sniffer + IDS 5A Polytech Nancy # 

## Lancement de l'applications ##
Afin de lancer le projet vous dezv :
- Posséder Visual studio
- Installer le packahe ShapPcap.Core avec NuGet.
- Installer Npcap depuis le lien suivant : https://nmap.org/npcap/dist/npcap-0.991.exe (les version postérieurs à la 0.991 ne fonctionne pas)

Le projet peut maintenant être lancé.

## Sniffer ##

### présentation ###
Nous avons choisis de faire une applications C# pour le partie logique et wpf pour la partie IHM. Le fichier MainWondows.xaml Contient le code xaml de l'IHM tandiq que le fichier MainWindows.xaml.cs contiens la partie logique.  

### Filtres ###
la syntaxe de filtrages de paquets est tirée de la syntaxe de la librairie Winpcap.

#### Protocoles ####
* **tcp**: packet en protocole TCP
* **udp**: packet en protocole UDP
* **icmp**: packet en protocole ICMP
* **arp**: packet en protocole ARP

#### hotes ####

* **host _addresse_de_l'hote_**: hote en fonctions de son addresse IP (v6 ou v4)
* **host _nom_de_l'hote_**: hote en fonction de son nom 
* **dst hote _addresse_ou_nom_de_l'hote_**: uniquement si l'hote indiqué est l'hote de destination
* **src hote _addresse_ou_nom_de_l'hote_**: uniquement si l'hote indiqué est l'hote de source

#### port ####

* **port _port_**: filtre en fonction du port
* **src port _port_** filtre en fonction du port source
* **dst port _port_** filtre en fonction du port destination

#### autres filtrage ####

on peut combiner des filtres: 
ex: _tcp hote 192.168.1.1_

on peut également filtrer des adresses spétiales comme brodcat ou multicast:
* **ip brodcast**
* **ip multicast**

plus d'informations: https://www.winpcap.org/docs/docs_40_2/html/group__language.html



