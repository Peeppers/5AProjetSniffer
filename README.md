# Projet Sniffer + IDS 5A Polytech Nancy # 

## Lancement de l'applications ##
Afin de lancer le projet vous dezv :
- Posséder Visual studio
- Installer le packahe ShapPcap.Core avec NuGet.
- Installer Npcap depuis le lien suivant : https://nmap.org/npcap/dist/npcap-0.991.exe (les version postérieurs à la 0.991 ne fonctionne pas)

Le projet peut maintenant être lancé.

## Sniffer ##
### Filtres ###
la syntaxe de filtrages de paquets est tirée de la syntaxe de la librairie Winpcap.

#### Protocoles ####
* *tcp*
* *udp*
* *icmp*
* *arp*

#### hotes ####

* *host _addresse_de_l'hote_*
* *host _nom_de_l'hote_*
* *dst _hote_* 


