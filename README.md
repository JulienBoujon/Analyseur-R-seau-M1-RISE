La fonction est compilée entièrement par un appel à make.

L'exécution s'effectue en appelant l'exécutable "analyse".

Par défaut, l'exécution lancera le mode en ligne sur l'interface active avec un nombre infini de paquets, en mode non promiscious et avec la verbosité 1.

Aucun filtre n'est implémenté.

Les options suivantes sont disponibles:

-p : active le mode promiscious
-t : suivie d'un entier indique le nombre de paquets à capturer
-v : suivi de 1, 2 ou 3 indique la verbosité désirée
-o : suivi d'un nom de fichier active le mode hors-ligne avec le fichier indiqué
-i : suivi d'un nom d'interface activera le mode en ligne en écoute sur l'interface indiquée

Les protocoles supportés sont :
	- ARP
	- BOOTP
	- DHCP
	- DNS
	- ETHERNET
	- IP
	- TCP
	- HTTP
	- SMTP
	- FTP
	- UDP