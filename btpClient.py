import socket
import rsa
from bitarray import bitarray
import time
import packetFormat


print("""
#-------------------#
|       BAR MENU    |
#-------------------#
| ID  NAME    PRICE |
#-------------------#
| 01  Beer    £1.65 |
| 02  Cider   £1.40 |
| 03  Wine    £4.99 |
| 04  Vodka   £2.49 |
| 05  Whisky  £3.00 |
| 06  Cola    £1.20 |
#-------------------#
-> enter 1-6 to chose drink
-> then enter quantity
-> or enter 0 to close the tab
""")

#######################
#   SOCKET METADATA   #
#######################

UDP_IP_ADDRESS = "127.0.0.1"
UDP_PORT_NO = 12000
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
CLIENT_PUBLIC_KEY, CLIENT_PRIVATE_KEY = rsa.newkeys(512, accurate=True)
TIMEOUT = 5
BUFFER = 4096

CLIENT_ID = None
SERVER_PUBLIC_KEY = None

#################
#  CLIENT CODE  #
#################


def decodePacket(packet):
    sequence = int.from_bytes(packet[0:4], byteorder='big')
    flags = bitarray(endian='big')
    flags.frombytes(packet[4:6])
    length = int.from_bytes(packet[6:8], byteorder='big')
    payload = packet[8:]
    return sequence, flags, length, payload      


# Method to send a simple Empty ACK message to a address
def sendEmptyACK(s):
    print(f'  [{s}] Sending empty ACK to Server')
    p= packetFormat.packetFormat(s, True, False, False, None, None, None)
    clientSocket.sendto(p.getEncryptedBytes(), (UDP_IP_ADDRESS, UDP_PORT_NO))

# Method to send a empty FIN ACK message to a address
def sendEmptyFinAck(s):
    print(f'  [{s}] Sending FIN ACK to Server')
    p = packetFormat.packetFormat(s, True, False, True, None, None, None)
    clientSocket.sendto(p.getEncryptedBytes(), (UDP_IP_ADDRESS, UDP_PORT_NO))

# Method to recive an empty ACK message
def recvEmptyACK(type, s):
    packet, address = clientSocket.recvfrom(BUFFER)
    inSequence, inFlags, inLength, inPayload = decodePacket(packet)
    if inFlags[0] == 1 and inSequence == s:
        print(f'  [{s}] {type} EMPTY ACK recieved from Server')
        return True
    else:
        print(f'  [{s}] ERROR, Invalid FIN ACK recieved from Server')
        return False

# Method to revive an empty FIN ACK message
def recvEmptyFinAck(s):
    packet, address = clientSocket.recvfrom(BUFFER)
    inSequence, inFlags, inLength, inPayload = decodePacket(packet)

    if inFlags[0] == 1 & inFlags[2] == 1:
        print(f'  [{s}] FIN ACK recieved from Server')
        return True
    else:
        print(f'  [{s}] ERROR, Invalid FIN ACK recieved from Server')
        return False


def rsaExchange():
    global SERVER_PUBLIC_KEY
    sequence = 0
    completed = False
    clientSocket.settimeout(TIMEOUT)
    while not completed:
        try:
            print(f"  [{sequence}] Sending RSA Client Public Key")
            p = packetFormat.packetFormat(sequence, False, True, False, None, None, CLIENT_PUBLIC_KEY.save_pkcs1())
            clientSocket.sendto(p.getEncryptedBytes(), (UDP_IP_ADDRESS, UDP_PORT_NO))

            recvEmptyACK('', sequence)

            sequence += 1
            packet, address = clientSocket.recvfrom(BUFFER)
            inSequence, inFlags, inLength, inPayload = decodePacket(packet)
            if inFlags[0] == 1 & inFlags[1] == 1:
                SERVER_PUBLIC_KEY = rsa.PublicKey.load_pkcs1(inPayload)

                sendEmptyACK(sequence)

                sequence += 1

                sendEmptyFinAck(sequence)             
                recvEmptyACK('',sequence)

                sequence += 1
                completed = recvEmptyFinAck(sequence)
                sendEmptyACK(sequence)
        except socket.timeout:
            print('  Error, Socket Timeout, resending...')

    print('RSA exchange with server completed')


def openTab():
    global CLIENT_ID
    sequence = 0
    try:
        print("  Sending OPEN message to SERVER")
        p = packetFormat.packetFormat(sequence, False, False, False, None, SERVER_PUBLIC_KEY, "OPEN")
        clientSocket.sendto(p.getEncryptedBytes(), (UDP_IP_ADDRESS, UDP_PORT_NO))
        
        recvEmptyACK('', sequence)
        sequence += 1

        # ID Recieve
        packet, address = clientSocket.recvfrom(BUFFER)
        inSequence, inFlags, inLength, inPayload = decodePacket(packet)
        plainText = rsa.decrypt(inPayload, CLIENT_PRIVATE_KEY)
        plainText = plainText.decode('ASCII')
        CLIENT_ID = plainText[6:].zfill(4)
        print(f'  [{sequence}] Client ID is {CLIENT_ID}')

        completed= False
        while not completed:
            sequence = 1
            sendEmptyACK(sequence)
            sequence += 1
            sendEmptyFinAck(sequence)

            if inFlags[0] == 1:
                print(f'  [{sequence}] Empty ACK recvived from Server')
            else:
                print(f'  [{sequence}] ERROR, no empty ACK recvived from Server')

            sequence += 1
            completed = recvEmptyFinAck(sequence)
            if completed == True:
                    sendEmptyACK(sequence)
            else:
                # Sending invalid packet
                print(f"  {sequence} Failed sending invalid Packet")
                p = packetFormat.packetFormat(sequence, False, False, False, None, None, None)
                clientSocket.sendto(p.getEncryptedBytes(), (UDP_IP_ADDRESS, UDP_PORT_NO))
   

    except socket.timeout:
        print('  Error, Socket Timeout, resending...')
        openTab()

    print(f'Client {CLIENT_ID} successfully added to the bar')
    clientSocket.settimeout(None)

def closeTab():
    print(f'Closing {CLIENT_ID} tab')
    payload = "ID " + CLIENT_ID + "\r\nCLOSE"
    sequence = 0
    plainText = ''

    print(f"  [{sequence}] Sending closing message to Server")
    p = packetFormat.packetFormat(sequence, False, False, False, None, SERVER_PUBLIC_KEY, payload)
    clientSocket.sendto(p.getEncryptedBytes(), (UDP_IP_ADDRESS, UDP_PORT_NO))

    clientSocket.settimeout(TIMEOUT)
    completed = False
    while not completed:
        try:
            recvEmptyACK('', sequence)
            sequence += 1
            recvEmptyACK('', sequence)
            packet, address = clientSocket.recvfrom(BUFFER)
            inSequence, inFlags, inLength, inPayload = decodePacket(packet)

            plainText = rsa.decrypt(inPayload, CLIENT_PRIVATE_KEY)
            plainText = plainText.decode('ASCII')

            sendEmptyACK(sequence)
            sequence = sequence + 1
            sendEmptyFinAck(sequence)
            recvEmptyACK('', sequence)
            sequence = sequence + 1
            completed = recvEmptyFinAck(sequence)

            if completed == True:
                sendEmptyACK(sequence)
            else:
                # Sending invalid packet
                p = packetFormat.packetFormat(sequence, False, False, False, None, None, None)
                clientSocket.sendto(p.getEncryptedBytes(), (UDP_IP_ADDRESS, UDP_PORT_NO))

        except socket.timeout:
            print('  Error, Socket Timeout, resending...')

    print(f'\nFinal {plainText}\nPlease pay at the bar on your way out\nHave a nice evening :)')
    clientSocket.close()

    


def addDrink(drink_name, drink_id, quantity):
    print(f"  [0] Adding {quantity} {drink_name}(s)")
    payload = 'ID '  + CLIENT_ID + '\r\nADD ' + drink_id.zfill(2)  + ' ' +  quantity
    
    print(f"  [0] Sending drink order to the Server")
    p = packetFormat.packetFormat(0, False, False, False, None, SERVER_PUBLIC_KEY, payload)
    clientSocket.sendto(p.getEncryptedBytes(), (UDP_IP_ADDRESS, UDP_PORT_NO))

    recvEmptyACK('', 0)

    plainText = 'TOTAL 0'
    clientSocket.settimeout(TIMEOUT)
    completed = False
    while not completed: 
        try: 
            sequence = 1
            clientSocket.settimeout(None)
            packet, address = clientSocket.recvfrom(BUFFER)
            inSequence, inFlags, inLength, inPayload = decodePacket(packet)
            if(inPayload != b''):
                plainText = rsa.decrypt(inPayload, CLIENT_PRIVATE_KEY)
                
                if(plainText == False):
                    print("Corrupted packet please try again")

                else:
                    plainText = plainText.decode('ASCII')
                    print(f"  [{sequence}] {plainText}")
                    sendEmptyACK(sequence)
                    sequence = sequence + 1
                    sendEmptyFinAck(sequence)
                    recvEmptyACK('', sequence)
                    sequence = sequence + 1
                    completed = recvEmptyFinAck(sequence)

                    if completed == True:
                        sendEmptyACK(sequence)
                    else:
                        # Sending invalid packet
                        p = packetFormat.packetFormat(sequence, False, False, False, None, None, None)
                        clientSocket.sendto(p.getEncryptedBytes(), (UDP_IP_ADDRESS, UDP_PORT_NO))
            else:
                print(f"  [{sequence}] Corrupted Packet restarting...")
   
        except socket.timeout:
            print('  Error, Socket Timeout, resending...')
    print(f"New {plainText} on the tab")


def addToTab():
    while True:
            drink = str(input("\nEnter drink ID: "))
            if(drink == '0'):
                    closeTab()
                    break

            quantity = str(input("Enter Quantity: "))

            if(drink == '1'):
                addDrink('Beer', drink, quantity)

            elif(drink =='2'):
                addDrink('Cider', drink, quantity)

            elif(drink =='3'):
                addDrink('Wine', drink, quantity)

            elif(drink =='4'):
                addDrink('Vodka', drink, quantity)

            elif(drink =='5'):
                addDrink('Whisky', drink, quantity)

            elif(drink =='6'):
                addDrink('Cola', drink, quantity)

            else:
                print("Unkown drink")

print("RSA Exchange with Server")     
rsaExchange()
print("\nOPEN Tab for new Client")
openTab()
addToTab()
