import os
import sys
import nmap3 # Per lo scan della rete
import json # Per gestire i file json
import threading # Per fare poi il loop dell'attacco
from easymodbus.modbusClient import ModbusClient

class AttackPLC:

  """
  Inizializzo la classe
  """
  def __init__(self):
    self.plc_list = {}
    self.plc_registers = {}
    self.single_plc_registers = {}

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
    # Verifico se già esiste una scansione precedente. Se non esiste,
    # chiedo all'utente di effettuarne una
    if not os.path.exists('plc_list.json'):
      req = input("PLC list not present. Perform a new search? [y/n] ")
      if(req == "y"):
        self.find_PLCs()
      else:
        return

    # Leggo da file la lista delle PLC trovate in precedenza
    with open('plc_list.json', 'r') as f:
      file = f.read()

    # Converto l'elenco da JSON a dict
    plc_list = json.loads(file)

    # Analizzo le PLC una a una
    for plc in plc_list:
      # Dictionnaries per i vari registri
      disInReg = {}
      InReg = {}
      HolReg = {}
      Coils = {}

      # Mi connetto alla PLC
      print(f'connecting to {plc_list[plc]}')
      mb = ModbusClient(plc_list[plc], 502)
      mb.connect()

      # Leggo i Discrete Input Registers
      print("Reading Discrete Input Registers (0-8)")
      discreteIn = mb.read_discreteinputs(0, 8)
    
      # Ricavo il dict dall'output della lettura dei
      # registri
      di_num = 0
      for di in discreteIn:
        disInReg['%IX0.'+str(di_num)] = str(di)
        di_num = di_num + 1

      # Stampo il dict
      print(disInReg) # Debug (?)

      """
      Come prima, ma per tutti gli altri registri!
      """
      print("Reading Input Registers (%IW0-7)")
      inputRegisters = mb.read_inputregisters(0,8)
      ir_num = 0
      for ir in inputRegisters:
        InReg['%IX'+str(ir_num)] = str(ir)
        ir_num = ir_num + 1
      print(InReg)

      print("Reading Output/Holding Registers (%QW0-9)")
      holdingRegisters = mb.read_holdingregisters(0, 10)
      hr_num = 0
      for hr in holdingRegisters:
        HolReg['%QW'+str(hr_num)] = str(hr)
        hr_num = hr_num + 1
      print(HolReg)

      print("Reading Coils (%QX0.0-7)")
      coils = mb.read_coils(0, 8)
      coil_num = 0
      for cl in coils:
        Coils['%QX0.'+str(coil_num)] = str(cl)
        coil_num = coil_num + 1
      print(Coils)

      # Qui dovrei aggiornare il dict, in teoria...
      self.plc_registers[plc_list[plc]] = {}

      #print(plcs[plc])

    # Stampo il dict totale (quando riuscirò a farlo!)
    print(self.plc_registers)
    mb.close()


"""
Definisco il main. Che poi è il menu da cui richiamo
le varie funzioni del generatore di attacchi...
"""
def main():
  ap = AttackPLC()

  while(True):
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
      pass
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
