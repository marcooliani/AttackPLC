import os
import sys
import nmap3
import json
import threading
from easymodbus.modbusClient import ModbusClient

class AttackPLC:

  def __init__(self):
    self.plc_list = {}
    self.plc_registers = {}
    self.single_plc_registers = {}

  def find_PLCs(self):
    net = input("Network to scan [<ip_addr>/<mask>]: ")

    print(f"Scanning {net}\n")
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_tcp_scan(net, args='-p 502')

    with open('network_scan.json', 'w') as f:
      f.write(json.dumps(results, indent=4, sort_keys=True))

    print("Active PLCs found: ")

    plc_num = 1

    for address in results:
      if(address == "runtime" or address == "stats"):
        continue

      for port in results[address]['ports']:
        if(port['state'] != "open"):
          continue

        #self.plc_list[f"plc{plc_num}"] = address
        self.plc_list[plc_num] = address
        plc_num = plc_num + 1
        print(address)

    #print(self.plc_list) #debug
    print("\n")

    with open('plc_list.json', 'w') as p:
      p.write(json.dumps(self.plc_list, indent=4))


  def scan_all_plcs(self):
    if not os.path.exists('plc_list.json'):
      req = input("PLC list not present. Perform a new search? [y/n] ")
      if(req == "y"):
        self.find_PLCs()
      else:
        return

    with open('plc_list.json', 'r') as f:
      file = f.read()

    plc_list = json.loads(file)

    for plc in plc_list:
    
      print(f'connecting to {plc_list[plc]}')
      mb = ModbusClient(plc_list[plc], 502)
      mb.connect()

      print("Reading Discrete Input registers (0-8)")
      discreteIn = mb.read_discreteinputs(0, 8)
      print("DI: " + str(discreteIn))

      print("Reading Input Registers (%IW0-7)")
      inputRegisters = mb.read_inputregisters(0,8)
      print("IR: " + str(inputRegisters))

      print("Reading Output/Holding Registers (%QW0-9)")
      holdingRegisters = mb.read_holdingregisters(0, 10)
      print("HOR: " + str(holdingRegisters))

      print("Reading Coils (%QX0.0-7)")
      coils = mb.read_coils(0, 8)
      print("Coils: " + str(coils))

      self.plc_registers[plc_list[plc]] = {}

      #print("Bau")
      #print(plcs[plc])

    print(self.plc_registers)
    mb.close()

    
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
