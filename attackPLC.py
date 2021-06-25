import os
import sys
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

    if(single_plc == False):
      addr_range = "0-8"
    else:
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
    
    if(single_plc == False):
      addr_range = "0-10"
    else:
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

    if(single_plc == False):
      starting_addr = 0
    else:
      starting_addr = input("Address to read (0-99): ")

      while (int(starting_addr) > 99):
        print("Invalid address!")
        starting_addr = input("Address to read (0-99): ")

    starting_addr = int(starting_addr)
    starting_addr_dec = starting_addr * 8

    print(f"Reading Coils from %QX{starting_addr}.0 to %QX{starting_addr}.7")
    coils = mb.read_coils(starting_addr_dec, 8)

    reg_num = 0

    for coil in coils:
      registri['%QX'+ str(starting_addr) +'.'+str(reg_num)] = str(coil)
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
    print("2 - Scan PLCs registers")
    print("3 - Scan single PLC")
    print("4 - Change register value (single PLC)")
    print("5 - DoS attack (single PLC)")
    print("6 - Exit\n")
    choice = input("Enter your choice: ")

    if(choice == "1"):
      ap.find_PLCs()
    elif(choice == "2"):
      ap.scan_all_plcs()
    elif(choice == "3"):
      ap.scan_single_plc()
    elif(choice == "4"):
      pass
    elif(choice == "5"):
      pass
    elif(choice == "6"):
      quit()
    else:
      print("Invalid choice\n")

if __name__ == '__main__':
  main()
