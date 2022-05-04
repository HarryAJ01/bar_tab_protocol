import socket
import random
import rsa
from bitarray import bitarray
import time
import random

activeClients = []
DRINKS = [['Beer', 1.65], ['Cider', 1.40], ['Wine', 4.99], ['Vodka', 2.49], ['Whisky', 3.00] ,['Cola', 1.20]]

####################
#  RSA ENCRYPTION  #
####################

def generate_keys():
    (pubKey, privKey) = rsa.newkeys(512, accurate=True)
    with open('keys/pubkey.pem', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))

    with open('keys/privkey.pem', 'wb') as f:
        f.write(privKey.save_pkcs1('PEM'))

def load_keys():
    with open('keys/pubkey.pem', 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())

    with open('keys/privkey.pem', 'rb') as f:
        privKey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubKey, privKey

def encrypt(msg, key):
    return rsa.encrypt(msg.encode('ascii'), key)

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False

def sign_sha1(msg, key):
    return rsa.sign(msg.encode('ascii'), key, 'SHA-1')

def verify_sha1(msg, signature, key):
    try:
        return rsa.verify(msg.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return False

#################
#  SERVER CODE  #
#################


def decodeHeader(header):
    seq = header[0:4].lstrip()
    if(seq != '0000'):
        length = header[5:]
        f1 = ("%08d" % (int(bin(ord(header[4]))[2:]), ))
        f2 = ("%08d" % (int(bin(ord(header[5]))[2:]), ))
        flags = bitarray(f1+f2)
        return seq, flags, length
    else:
        return '0000', bitarray('00000000'), 4

def decodePayload(ibPaylaod):
    client_ID = int(ibPaylaod[:4])
    data = ibPaylaod[4:]
    return client_ID, data

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSocket.bind(('', 1234))
print("\nServer Running...")
generate_keys()
SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY = load_keys()

def finishRequest(address):
    time.sleep(waitTime)
    acknowledged = False
    while not acknowledged:
        ack, address = serverSocket.recvfrom(4096)
        acknowledged = True
        # Bytes form 5 -> 101 Flags
        packet = ack[:4] + b'501 '
        serverSocket.sendto(packet, address)
        print("Finish ACK recieved from client")


def rsaExchange(header, address):
    print("\nRSA Exchange with Client\nClient Public Key Recieved")
    client_public_key = rsa.PublicKey.load_pkcs1(packet[9:])
    server_public_key_bytes = SERVER_PUBLIC_KEY.save_pkcs1()
    
    print(f"Sending...\n\t{header} [Server Public Key]")
    header_bytes = bytes(header, 'ascii')
    outPacket = header_bytes + server_public_key_bytes

    time.sleep(waitTime)
    serverSocket.sendto(outPacket, address)

    # RECIEVE ACK
    serverSocket.settimeout(2)
    acknowledged = False
    while not acknowledged:
        try:
            ack, address = serverSocket.recvfrom(4096)
            ack = ack.decode('ascii')
            sequence = ack[:3]
            # TEMP BIT ARRAY IS BEING A BITCH SO ONLY WAY IT WILL WORK
            if(ack[4] == '3'):
                flags = str(bin(int(ack[4])))
                flags = flags[2:]
            else:
                f1 = ("%08d" % (int(bin(ord(header[4]))[2:]), ))
                f2 = ("%08d" % (int(bin(ord(header[5]))[2:]), ))
                flags = bitarray(f1+f2)

            if(flags[0] == '1' or flags[0] == 1):
                print("ack recieved from client")
                acknowledged = True
                break
            else:
                print("Error, no ack recieved from client")
                equence = str(int(sequence) + 1)
                sequenceStr = str(sequence)
                sequenceStr = sequenceStr.zfill(4)
                header = bytes(sequenceStr, 'ascii') + bytes(str(flags), 'ascii') + bytes(length, 'ascii')
                outPacket = header + bytes('err', 'ascii')

        except socket.timeout:
            print("Error, not ack recieved from client")
            sequence = str(int(sequence) + 1)
            sequenceStr = str(sequence)
            sequenceStr = sequenceStr.zfill(4)
            header = bytes(sequenceStr, 'ascii') +  bytes(str(flags), 'ascii')+ bytes(length, 'ascii')
            outPacket = header + bytes('err', 'ascii')
   
        print("RSA exchange completed")
        break

    serverSocket.settimeout(None)
    finishRequest(address)
    return client_public_key

def newClient(address):
    time.sleep(waitTime)
    print("\nOPENING TAB")
    client_id = random.randint(1000,9999)
    activeClients.append([client_id, 0])

    seq = b'0001'
    flags = bitarray()
    flags.extend([0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0])
    flags = flags.tobytes()
    length = b'4'
    header = seq + flags + length    

    client_id_str ='SETID ' + str(client_id)
    print(client_id_str)
    
    cipherText = encrypt(client_id_str, CLIENT_PUBLIC_KEY)
    serverSocket.sendto(header + cipherText, address)

    
def addOrder(clientID, drink, quantity, address):
    for i in range(len(activeClients)):
        if activeClients[i][0] == int(clientID):
            total = activeClients[i][1]
            total = total + (DRINKS[drink][1] * float(quantity))
            activeClients[i][1] = total

            str_total = "{:.2f}".format(total)
            print(f"  Adding {quantity} to {DRINKS[drink][0]}(s) to {clientID}'s order")
            print(f"  {clientID}'s new total is £{str_total}")

            message = 'TOTAL ' + str(str_total)
            cipherText = encrypt('00000000' + message, CLIENT_PUBLIC_KEY)
            serverSocket.sendto(cipherText, address)

def closeClinet(clientID, address):
    for i in range(len(activeClients)):
        if(activeClients[i][0] == int(clientID)):
            
            total = activeClients[i][1]
            print(f"{clientID} final bill is: £{total}")
            
            message = 'TOTAL ' + str(total)
            cipherText = encrypt('00000000' + message, CLIENT_PUBLIC_KEY)
            serverSocket.sendto(cipherText, address)
            #activeClients.remove(activeClients[i].index)

while True:
    # Assigns a random amount of time to simulate packet loss
    waitTime = random.randint(0,3)

    packet, address = serverSocket.recvfrom(4096)
    header = packet[0:8]
    header = header.decode("ascii")
    sequnce, flags, length = decodeHeader(header)

    # RSA KEY EXCHAGE
    if flags[1] == 1:
        CLIENT_PUBLIC_KEY = rsaExchange(header, address)
    else:
        payload = decrypt(packet[8:], SERVER_PRIVATE_KEY)
        
        if(payload != False):
            if payload == 'OPEN':
                print(f"\nRecived packet OPEN from {address}")
                newClient(address)

            else:
                if(payload[4:] == "CLOSE"):
                    print(f"\nRecived packet CLOSE from {address}")
                    closeClinet(payload[:4], address)
                else:
                    print(f"\nRecieved packet {payload[3:6]} {payload[10:]} from {address}")
                    data = payload.split('\r\n')
                    cID = data[0][3:]
                    drinkData = data[1].split(' ')
                    drink = str(drinkData[1].lstrip())
                    drink = int(drink) - 1
                    quantity = drinkData[2]
                    addOrder(cID, drink, quantity, address)