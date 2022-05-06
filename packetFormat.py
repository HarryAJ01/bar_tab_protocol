from bitarray import bitarray
import rsa

class packetFormat:
   
    def __init__(self,sequence, ackFlag, rsaFlag, finFlag, extraFlags, key, payload):
        header = None

        # Sequence
        header = sequence.to_bytes(4, byteorder = 'big')
        
        # Flags 
        flags = bitarray()
        if(ackFlag == True):
            flags.append(True)
        else:
            flags.append(False)

        if(rsaFlag == True):
            flags.append(True)
        else:
            flags.append(False)
        
        if(finFlag == True):
            flags.append(True)
        else:
            flags.append(False)

        if(extraFlags == None):
            flags.extend([False, False, False, False, False, False, False, False, False, False, False, False, False])

        flags = flags.tobytes()
        header += flags

        # Length
        length = 8
        if(rsaFlag == True):
            length += 64
        else:
            if(payload != None):
                length += len(bytes(str(payload), 'ascii'))
        header += length.to_bytes(2, byteorder = 'big')

        # encoding body to bytes
        body = b''
        if(rsaFlag == True):
            body = payload    #Key doesn't need converting
        elif(payload != None):
            body = bytes(str(payload), 'ASCII')

        packet = header + body

        # Only return variable
        global encryptedBytes

        # Emcrypts the message usimg RSA if necessary
        if key == None:
            encryptedBytes = packet
        else:
            cipherText = rsa.encrypt(body, key)
            encryptedBytes = header + cipherText

    # Getter for message to be sent
    def getEncryptedBytes(self):
        return encryptedBytes
