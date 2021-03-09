import socket
import struct
import time

#creating socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

IPdict = {}

print("Monitoring for threats")

#time variable to measure elapsed time between requests
start = time.time()
while True:
    #receiving UDP packet
    packet = s.recvfrom(2048)

    #getting source IP address
    ipheader = packet[0][14:34]
    ip_header = struct.unpack("!12s4s4s", ipheader)
    sourceIP = socket.inet_ntoa(ip_header[1])

    #updating dictionary with number of requests from source IP
    if sourceIP in IPdict:
        IPdict[sourceIP] +=1

        #current time
        end = time.time()

        #if the IP has made more than 50 requests in the past second
        if IPdict[sourceIP] > 100 and end-start<2:
            print("Potential DOS attack from source IP:", sourceIP)
            #remove from dictinary after alerting user
            IPdict.pop(sourceIP)
            #wait for user input before continuing
            input("Press Enter to continue")
    else:
        IPdict[sourceIP] = 1

    #resetting start time
    start = time.time()

