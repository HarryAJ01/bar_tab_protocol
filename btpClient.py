from msilib import sequence
from re import L
import socket
import rsa
from bitarray import bitarray
import time

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

#####################
# SOCKET METADATA   #
#####################

UDP_IP_ADDRESS = "127.0.0.1"
UDP_PORT_NO = 1234
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
generate_keys()
CLIENT_PUBLIC_KEY, CLIENT_PRIVATE_KEY = load_keys()


#################
#  CLIENT CODE  #
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

def decodePayload(inPaylaod):
    client_ID = int(inPaylaod[:4])
    data = inPaylaod[4:]
    return client_ID, data


# STOP WAIT PROTOCOL to perform finishing actions
def finishRequest(sequnece):
    sequence = bytes(sequnece, 'ascii')
    flags = bitarray()
    flags.append(False)
    flags.append(False)
    flags.append(True)
    flags.extend([0,0,0,0,0,0,0,0,0,0,0,0,0])
    flags_bytes = flags.tobytes()
    length = b'1'
    header = sequence + flags_bytes + length
    packet = header + b' '

    clientSocket.sendto(packet, (UDP_IP_ADDRESS, UDP_PORT_NO))

    clientSocket.settimeout(2)
    acknowledged = False
    while not acknowledged:
        try:
            ack, address = clientSocket.recvfrom(4096)
            acknowledged = True
            data = ack.decode('ascii')
            # TEMP BIT ARRAY IS BEING A BITCH SO ONLY WAY IT WILL WORK
            
            if(data[4] == '5'):
                flags = str(bin(5))
                flags = flags[2:]
            else:
                f1 = ("%08d" % (int(bin(ord(data[4]))[2:]), ))
                f2 = ("%08d" % (int(bin(ord(data[5]))[2:]), ))
                flags = bitarray(f1+f2)

            if(flags[0] == '1' or flags[0] == 1):
                acknowledged = True
                break
            else:
                print("Error, no ack recieved from server")
                sequnece = str(int(sequence) + 1).zfill(4)
                finishRequest(sequnece)            

        except socket.timeout:
            sequnece = str(int(sequence) + 1).zfill(4)
            finishRequest(sequnece)
    socket.timeout(None)
    print(f"Finish ACK recieved from server")
            

# Method to perform RSA Key exhange
# 1. Client Public Key generated
# 2. Header created with RSA Bit = True
# 3. Message sent to server in stop wait
# 4. Once ack client saves public key
def rsaExchange():
    print('RSA Exchange with Server')
    # RSA Exchange Header
    sequence = '0001'
    flags = bitarray()
    flags.append(False)
    flags.append(True)
    flags.extend([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
    length = '64' #512 Bit key so 64 bytes always

    sequence_bytes = bytes(sequence, 'ascii')
    flags_bytes = flags.tobytes()
    length_bytes = bytes(length, 'ascii')

    header = sequence_bytes + flags_bytes + length_bytes
    payload = CLIENT_PUBLIC_KEY.save_pkcs1()
    packet = header + payload

    clientSocket.sendto(packet, (UDP_IP_ADDRESS, UDP_PORT_NO))
    print(f"Sending...\n\t[{sequence} {flags} {length}] [CLIENT PUBLIC KEY]")
    clientSocket.settimeout(2)
    acknowledged = False   
    while not acknowledged:
        try:
            data, address = clientSocket.recvfrom(4096)
            acknowledged = True
            server_public_key = rsa.PublicKey.load_pkcs1(data[8:])

            data = packet.decode('ascii')
            sequence, flags, length = decodeHeader(data[:8])
            

        except socket.timeout:
            sequence = str(int(sequence) + 1)
            sequenceStr = str(sequence)
            sequenceStr = sequenceStr.zfill(4)
            header = bytes(sequenceStr, 'ascii') + flags_bytes + length_bytes
            packet = header + payload

            print(f"Socket Tineout, resending...\n\t[{sequenceStr} {flags} {length}] [CLIENT PUBLIC KEY]")
            clientSocket.sendto(packet, (UDP_IP_ADDRESS, UDP_PORT_NO))   
    print(f"Server Public Key recieved")#[{sequence} {flags} {length}] [{server_public_key}] from : {address}")

    socket.timeout(None)
    # Sending Completion ACK
    #SEQ = 0001 Flags = 30 (converts to 11000000 00000000) length = 1 message = ' '
    ackMessage = b'0001301 '    
    #print(f"ackMessage: {ackMessage}")
    #Sending Acknowledment
    clientSocket.sendto(ackMessage, (UDP_IP_ADDRESS, UDP_PORT_NO))

    # Allow time for ack to processed serverside, if no response then completed successfully
    timeout = time.time() + 3
    while time.time() < timeout:
        try:
            data, address = clientSocket.recvfrom(4096)
            if data.decode('ascii') != '':
                rsaExchange()
        except socket.timeout:
            break

    finishRequest('0001')
    print('RSA Exchange completed')
    return server_public_key

##################
#   OPENING TAB  #
###################

# Send Open Message 
# 1. Sends empty header with OPEN payload (ENCRYPTED)
# 2. Recieves client ID and sends an ACK
def openTab():
    print(f"\nOpening new tab")
    header = b'00000000'
    plaintext = 'OPEN'
    cipherText = encrypt(plaintext, SERVER_PUBLIC_KEY)
    clientSocket.sendto(header + cipherText, (UDP_IP_ADDRESS, UDP_PORT_NO))

    clientSocket.settimeout(2)
    acknowledged = False
    while not acknowledged:
        try:
            packet, address = clientSocket.recvfrom(4096)
            acknowledged = True
            plaintext = decrypt(packet[7:], CLIENT_PRIVATE_KEY)
            clientID = plaintext[6:]
            print(f"Client ID: {clientID}")
        except socket.timeout:
            clientSocket.sendto(header + cipherText, (UDP_IP_ADDRESS, UDP_PORT_NO))
    socket.timeout(None)    
    return clientID

def closeTab():
    print(f'Closing {CLIENT_ID} tab')
    cipher = encrypt(CLIENT_ID + 'CLOSE', SERVER_PUBLIC_KEY)
    message = b'00000000' + cipher 
    clientSocket.sendto(message, (UDP_IP_ADDRESS, UDP_PORT_NO))
    packet, address = clientSocket.recvfrom(4096)
    packet = decrypt(packet, CLIENT_PRIVATE_KEY)
    print(f'\nFinal {packet[8:]}\nPlease pay at the bar on your way out\nHave a nice evening :)')
    clientSocket.close()


def addDrink(drink_name, drink_id, quantity):
    sequence = b'0001'
    flags = bitarray()
    flags.extend([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
    flags = flags.tobytes()

    print(f"  Adding {quantity} {drink_name}(s)")
    payload = 'ID '  + CLIENT_ID + '\r\nADD ' + drink_id.zfill(2)  + ' ' +  quantity
    cipherText = encrypt(payload, SERVER_PUBLIC_KEY)
    length = bytes(str(len(payload)), 'ascii')
    header = sequence + flags + length
    packet = header + cipherText
    clientSocket.sendto(packet, (UDP_IP_ADDRESS, UDP_PORT_NO))

    socket.timeout(None)
    packet, address = clientSocket.recvfrom(4096)
    packet = decrypt(packet, CLIENT_PRIVATE_KEY)
    if(packet == False):
        print("Corrupted packet please try again")
    else:
        print(f'  {packet[8:]}')


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
        
SERVER_PUBLIC_KEY = rsaExchange()
CLIENT_ID = openTab()
addToTab()