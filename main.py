from scapy.all import *
import subprocess
import csv
import datetime
import time
import threading
interface = "wlp2s0"

connections = []
#packets = []
# getting connections
def get_connections():

    netstat = subprocess.run(args=["""netstat -ntu"""],shell=True, stdout=subprocess.PIPE) # run a bash code to get connections' attributes
    output = netstat.stdout
    if output :
        spltOut = output.decode().split('\n')
        for i in range(len(spltOut)): # list lines
            line = spltOut[i]
            if(len(line)>0): # remove empty lines
                spltLine = line.split(' ')
                line = []
                for i in spltLine: # list attributes
                    if i != '' : # remove empties
                        line.append(i)
                if line[len(line) - 1] == 'ESTABLISHED' :
                    l = [line[0], line[3], line[4]]
                    local = l[1].split(':')
                    foreign = l[2].split(':')
                    # make a dictionary to store connection attributes
                    conn = {
                            "localIP": local[0],
                            "localPort": local[1],
                            "foreignIP": foreign[0],
                            "foreignPort": foreign[1],
                            ""
                            "protocol": l[0],
                            "sentBytes": 0,
                            "recievedBytes": 0,
                            "forwardHeadersBytes": 0,
                            "packets" : []
                        }
                    if conn not in connections:
                        connections.append(conn)
#getting packets
def print_packet(packet):
    ip_layer = packet.getlayer('IP')
    if ip_layer :
        length = ip_layer['IP'].len
        header_length = ip_layer['IP'].ihl * 4
        sport = None
        dport = None
        if TCP in ip_layer :
            sport = ip_layer['TCP'].sport
            dport = ip_layer['TCP'].dport
        elif UDP in ip_layer :
            sport = ip_layer['UDP'].sport
            dport = ip_layer['UDP'].dport
        packet = {
            "length": length,
            "header_length": header_length,
            "sport": sport,
            "dport": dport,
            "sIP": ip_layer.src,
            "dIP": ip_layer.dst
        }
        #packets.append(packet)
        if (TCP in ip_layer) or (UDP in ip_layer) :
            for conn in connections :
                print('here')
                print(conn["localPort"] , packet["sport"])
                if (conn["localIP"]) == (packet["sIP"]) :
                    print("+++++++++++++++++++++++++++++++++++++++++")
                # sending packets
                if (conn["localIP"] == packet["sIP"]) and (conn["foreignIP"] == packet["dIP"]) and (int(conn["localPort"]) == int(packet["sport"])) and (int(conn["foreignPort"]) == int(packet["dport"])) :
                    packet["SorR"] = "SENT"
                    conn["packets"].append(packet)
                    conn["sentBytes"] += packet["length"]
                    conn["forwardHeadersBytes"] += packet["header_length"]
                # recieving packets
                elif (conn["localIP"] == packet["dIP"]) and (conn["foreignIP"] == packet["sIP"]) and (int(conn["localPort"]) == int(packet["dport"])) and (int(conn["foreignPort"]) == int(packet["sport"])) :
                    packet["SorR"] = "RECIEVED"
                    conn["packets"].append(packet)
                    conn["recievedBytes"] += packet["length"]
    
start_time = time.time()
time_duration = int(input("please enter time duration : "))
csv_file = input("please enter log file name : ")
def my_sniff():
    print('ss')
    sniff(iface=interface, prn=print_packet, stop_filter=lambda p: (time.time() - start_time) > (time_duration * 60))
def main() :
    t1 = threading.Thread(target=my_sniff)
    t1.start()
    while (time.time() - start_time) <= (time_duration * 60):
        print("true")
        get_connections()
    
        

#while True:
#get_connections()
'''t1 = threading.Thread(target=main)
t1.start()
t1.join()'''
main()

try:
    with open(csv_file, 'w') as csvFile:
        writer = csv.DictWriter(csvFile, fieldnames=["localIP", "localPort", "foreignIP", "foreignPort", "protocol", "sentBytes", "recievedBytes", "forwardHeadersBytes", "packets"])
        writer.writeheader()

        for conn in connections :
            writer.writerow(conn)
except IOError:
    print("IOError")
#for conn in connections :
#   print(conn)

print("=================================")
