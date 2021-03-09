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
    else:
        IPdict[sourceIP] = 1

    # current time
    end = time.time()

    #if 1 second has passed
    if (end-start)>10:
        for i in IPdict:
            #if there has been more than 100 requests in the previous second
            if IPdict[i] > 100:
                print("Potential DOS attack from source IP:", sourceIP)
                print("{} packets received in the past 10 seconds".format(IPdict[i]))
                print("\n")
            #set back to 0
            IPdict[i] = 0

        #resetting start time
        start = time.time()

