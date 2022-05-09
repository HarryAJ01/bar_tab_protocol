import socket
import random
import rsa
from bitarray import bitarray
import time
import packetFormat

activeClients = []
DRINKS = [['Beer', 1.65], ['Cider', 1.40], ['Wine', 4.99], ['Vodka', 2.49], ['Whisky', 3.00] ,['Cola', 1.20]]

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False

def decodePacket(packet):
    sequence = int.from_bytes(packet[0:4], byteorder='big')
    flags = bitarray(endian='big')
    flags.frombytes(packet[4:6])
    length = int.from_bytes(packet[6:8], byteorder='big')
    payload = packet[8:]
    return sequence, flags, length, payload


serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSocket.bind(('', 12000))
print("\nServer Running...")
SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY = rsa.newkeys(512, accurate=True)
TIMEOUT = 5
BUFFER = 4096

# Method to send a simple Empty ACK message to a address
def sendEmptyACK(s, address):
    print(f'  [{s}] Sending empty ACK to Client')
    p= packetFormat.packetFormat(s, True, False, False, None, None, None)
    serverSocket.sendto(p.getEncryptedBytes(), address)

# Method to send a empty FIN ACK message to a address
def sendEmptyFinAck(s, address):
    print(f'  [{s}] Sending FIN ACK to Client')
    p = packetFormat.packetFormat(s, True, False, True,  None, None, None)
    serverSocket.sendto(p.getEncryptedBytes(), address)

# Method to recive an empty ACK message
def recvEmptyACK(type, s):
    packet, address = serverSocket.recvfrom(BUFFER)
    inSequence, inFlags, inLength, inPayload = decodePacket(packet)
    if inFlags[0] == 1:
        print(f'  [{s}] {type}Empty ACK recieved from Client')
        return True
    else:
        print(f'  [{s}] {type}ERROR, Invalid ACK recieved from Client')
        return False

# Method to revive an empty FIN ACK message
def recvEmptyFinAck(s):
    packet, address = serverSocket.recvfrom(BUFFER)
    inSequence, inFlags, inLength, inPayload = decodePacket(packet)
    if inFlags[2] == 1:
        print(f'  [{s}] FIN ACK recieved from Client')
        return True
    else:
        print(f'  [{s}] ERROR, Invalid FIN ACK recieved from Client')
        return False


def rsaExchange(payload, address):
    # Recieving Public Key from Clinet
    print("  [0] Client Public Key Recieved")
    print(payload)
    client_public_key = rsa.PublicKey.load_pkcs1(payload)

    complete = False
    while not complete:
        try:
            # Sending ACK for Reciving Client Public Key
            sequence = 0
            sendEmptyACK(sequence, address)

            # Sending Server Public Key to Client
            sequence = sequence + 1
            print(f"  [{sequence}] Sending Server Public Key to Client")
            server_public_key_bytes = SERVER_PUBLIC_KEY.save_pkcs1()
            p = packetFormat.packetFormat(sequence, True, True, False, None, None, server_public_key_bytes)
            serverSocket.sendto(p.getEncryptedBytes(), address)

            # ACKS for stop wait
            recvEmptyACK("Server Public Key", sequence)
            sequence = sequence + 1
            recvEmptyFinAck(sequence)
            sendEmptyACK(sequence, address)
            sequence = sequence + 1
            sendEmptyFinAck(sequence, address)
            complete = recvEmptyACK('',sequence)

        except socket.timeout:
            print('  Socket Timeout, resending...')

    socket.timeout(None)
    return client_public_key

def newClient(client_id, address):

    sequence = 0
    sendEmptyACK(sequence, address)
    print(f"  [{sequence}] Sending ID:{client_id[6:]} to the Client")
    sequence = sequence + 1
    p = packetFormat.packetFormat(sequence, True, False, False, None, CLIENT_PUBLIC_KEY, client_id)
    serverSocket.sendto(p.getEncryptedBytes(), address)
   
    completed  = False
    while not completed:
        try:
            recvEmptyACK("Clinet ID", sequence)
            sequence = sequence + 1
            recvEmptyFinAck(sequence)
            sendEmptyACK(sequence, address)
            sequence = sequence + 1
            sendEmptyFinAck(sequence, address)
            completed = recvEmptyACK('', sequence)
            print('Client ID successfully Sent to Client')

        except socket.timeout:
            print('  Socket Timeout, resending...')

    socket.timeout(None)
   
def addOrder(clientID, drink, quantity, address):
    print(f"\nAdding {quantity} to {DRINKS[drink][0]}(s) to {clientID}'s order")
    for i in range(len(activeClients)):
        if activeClients[i][0] == int(clientID):
            total = activeClients[i][1]
            print(f"  [0] Previous Total {total} for Client {client_id}")
            total = total + (DRINKS[drink][1] * float(quantity))
            activeClients[i][1] = total

            str_total = "{:.2f}".format(total)
            print(f"  [0] {clientID}'s new total is £{str_total}")

            print(f"  [0] Sending TOTAL {str_total} to the Client")
            message = 'TOTAL ' + str(str_total)
            socket.timeout(TIMEOUT)
            sendOrder(message, address)
            

def sendOrder(message, address):
    socket.timeout(TIMEOUT)
    completed = False
    while not completed:
        try:
            sequence = 0

            sendEmptyACK(sequence, address)
            sequence = sequence + 1

            # Send Drink Total to Client
            p = packetFormat.packetFormat(sequence, False, False, False, None, CLIENT_PUBLIC_KEY, message)
            serverSocket.sendto(p.getEncryptedBytes(), address)

            recvEmptyACK('New Total ', sequence)
            sequence = sequence + 1
            recvEmptyFinAck(sequence)
            sendEmptyACK(sequence, address)
            sequence = sequence + 1
            sendEmptyFinAck(sequence, address)

            completed = recvEmptyACK('',sequence)
            if completed == True:
                sendEmptyACK(sequence, address)
            else:
                # Sending invalid packet
                p = packetFormat.packetFormat(sequence, False, False, False, None, None, None)
                serverSocket.sendto(p.getEncryptedBytes(), address)

        except socket.timeout:
            print('  Socket Timeout, resending...')
            
    socket.timeout(None)
    print("Order Successfully added to tab")


def closeClinet(message, address):
    socket.timeout(TIMEOUT)
    sequence = 0
    completed = False@
    while not completed:
        try:
            sendEmptyACK(sequence, address)
            sequence = sequence + 1
            p = packetFormat.packetFormat(sequence, True, False, False, None, CLIENT_PUBLIC_KEY, message)
            serverSocket.sendto(p.getEncryptedBytes(), address)

            recvEmptyACK('',sequence)
            sequence = sequence + 1
            recvEmptyFinAck(sequence)
            sendEmptyACK(sequence, address)
            sequence = sequence + 1
            sendEmptyFinAck(sequence, address)

            completed = recvEmptyACK('',sequence)
            if(completed == True):
                sendEmptyACK(sequence, address)
            else:
                # Send Imvalid ACK
                p = packetFormat.packetFormat(sequence, False, False, False, None, None, None)
                serverSocket.sendto(p.getEncryptedBytes(), address)

        except socket.timeout:
            print('  Error, Socket Timeout, resending...')
    socket.timeout(None)


while True:
    # Assigns a random amount of time to simulate packet loss
    waitTime = random.randint(0,3)

    packet, address = serverSocket.recvfrom(BUFFER)
    sequence, flags, length, payload = decodePacket(packet)

    time.sleep(waitTime)
    # RSA KEY EXCHAGE
    if flags[1] == 1:
        print("RSA Exchange with Client")
        CLIENT_PUBLIC_KEY = rsaExchange(payload, address)
        print('RSA exchange completed')
    else:
        payload = decrypt(payload, SERVER_PRIVATE_KEY)

        if(payload != False):
            split_payload = payload.split('\r\n')

            if payload == 'OPEN':
                print(f"\nRecived packet OPEN from {address}")
                client_id = random.randint(1000,9999)
                activeClients.append([client_id, 0])
                client_id_str ='SETID ' + str(client_id)
                print(f"  [0] {client_id_str}")
                newClient(client_id_str, address)

            elif split_payload[1] == 'CLOSE':
                client_id_full = split_payload[0]
                client_id_full_split = client_id_full.split(" ")
                cID = client_id_full_split[1]

                
                print(cID)
                print(f"\nClosing Client {cID}")
                for i in range(len(activeClients)):
                    if(activeClients[i][0] == int(cID)):
                        total = activeClients[i][1]
                        message = 'TOTAL ' + str(total)
                        closeClinet(message, address)
                        print(f"{cID} successfully removed from Server")

            else:
                data = payload.split('\r\n')
                cID = data[0][3:]
                drinkData = data[1].split(' ')
                drink = str(drinkData[1].lstrip())
                drink = int(drink) - 1
                quantity = drinkData[2]
                addOrder(cID, drink, quantity, address)
