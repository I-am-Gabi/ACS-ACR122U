from smartcard.CardType import AnyCardType
from smartcard.CardConnection import CardConnection
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString

from settings import fido_server
import sys
import requests
import time 

import json  
from collections import OrderedDict

def bytearry2json(content): 
    UAFmsg = content   
    UAFmsg = UAFmsg.replace('\x00{"uafProtocolMessage":', '').replace('"[', '[').replace(']"', ']').replace('\\"', '"').replace('\\n', '\n')
    UAFmsg = UAFmsg[:len(UAFmsg)-1]
    UAFmsg = UAFmsg.split('"')
    uaf_scope = '[{"assertions": [{ "assertion":"%s", "assertionScheme":"%s"}], "fcParams":"%s", "header":{ "appID":"%s", "op":"%s", "serverData":"%s", "upv":{ "major":1, "minor":0 }}}]' % (UAFmsg[5], UAFmsg[9], UAFmsg[13], UAFmsg[19], UAFmsg[23], UAFmsg[27])

    data = json.loads(uaf_scope, object_pairs_hook=OrderedDict, strict=False) 
    json_ = json.dumps(data, separators=(',', ':')) 
    return uaf_scope 

BLOCK_SIZE = 200 

cardtype = AnyCardType()
cardrequest = CardRequest( timeout=10, cardType=cardtype )
cardservice = cardrequest.waitforcard()

def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)) 
        if len(hv) == 1:
            hv = '0'+hv 
        lst.append(int(hv, 16))
    
    return lst 

#convert hex repr to string
def toStr(s):
    return s and chr(int(s[:2], base=16)) + toStr(s[2:]) or ''


# Communication parameters are mostly important for the protocol negotiation between the smart card reader and the card. 
# The main smartcard protocols are the T=0 protocol and the T=1 protocol, for byte or block transmission, respectively. 
# The required protocol can be specified at card connection or card transmission.
connection = cardservice.connection.connect(CardConnection.T1_protocol)
# connection attribute, which is a CardConnection for the card
print toHexString( cardservice.connection.getATR() )

print 'reader: ', cardservice.connection.getReader()

SELECT = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xF0, 0x39, 0x41, 0x48, 0x14, 0x81, 0x00, 0x00] 
apdu = SELECT 
print 'sending: [apdu] ' + toHexString(apdu)

response, sw1, sw2 = cardservice.connection.transmit(apdu, CardConnection.T1_protocol) 
response.append(sw1)
response.append(sw2)
str_hex = [str(hex(h)).replace('0x', '') for h in response]
str_hex = ''.join(str_hex)
print "response: " + str_hex.decode("hex")

######################################## FIDO Auth Request Message
print("Doing AuthRequest to FIDO UAF Server\n");
UAFurl = fido_server['AUTH_REQUEST_MSG'] % (fido_server['SCHEME'], fido_server['HOSTNAME'], fido_server['AUTH_REQUEST_ENDPOINT'])
 
try:
    r = requests.get(UAFurl)
    r.raise_for_status()
except requests.exceptions.RequestException as e:  # This is the correct syntax
    print(e) 
    sys.exit(1)

content = r.content  
blocks = (len(content) / BLOCK_SIZE) + 1 

data_message = "BLOCK:" + str(blocks)
print 'sending: ' + data_message

response, sw1, sw2 = cardservice.connection.transmit(toHex(data_message), CardConnection.T1_protocol ) 
response.append(sw1)
response.append(sw2)
str_hex = [str(hex(h)).replace('0x', '') for h in response]
str_hex = ''.join(str_hex)
print "response: " + str_hex.decode("hex")

######################################## SEND PACK 

# Sending UAFRequestMessage to card
chunks = len(content)
msg_packages = ([ content[i:i + BLOCK_SIZE] for i in range(0, chunks, BLOCK_SIZE) ])
for pack, index in zip(msg_packages, range(1, chunks+1)):
    print("Seding package %s..." % index)
    data_message = toHex(pack) 
    response, sw1, sw2 = cardservice.connection.transmit( data_message, CardConnection.T1_protocol )
    response.append(sw1)
    response.append(sw2)
    str_hex = [str(hex(h)).replace('0x', '') for h in response]
    str_hex = ''.join(str_hex)
    print "response: " + str_hex.decode("hex")

print("\nSending READY!")


data_message = toHex("READY")
response, sw1, sw2 = cardservice.connection.transmit( data_message, CardConnection.T1_protocol )
response.append(sw1)
response.append(sw2)
str_hex = [str(hex(h)).replace('0x', '') for h in response]
str_hex = ''.join(str_hex)
print "response: " + str_hex.decode("hex")

print("\nWaiting...\n") 

time.sleep(5)

while 'WAIT' == str_hex.decode("hex"): 
    data_message = toHex("READY")
    print("SEND: " + "READY")
    response, sw1, sw2 = cardservice.connection.transmit( data_message, CardConnection.T1_protocol )
    response.append(sw1)
    response.append(sw2)
    str_hex = [str(hex(h)).replace('0x', '') for h in response]
    str_hex = ''.join(str_hex)
    print "response: " + str_hex.decode("hex")

data_message = toHex("RESPONSE")
print("Sending RESPONSE!")
response, sw1, sw2 = cardservice.connection.transmit( data_message, CardConnection.T1_protocol )
response.append(sw1)
response.append(sw2)
str_hex = [str(hex(h)).replace('0x', '') for h in response]
str_hex = ''.join(str_hex)
print "response: " + str_hex.decode("hex")

blocks = int(str_hex.decode("hex").split(':')[1]) 
UAFmsg = '\0'
for block in range(0, blocks): 
    print("receiving block --> %s" % block)
    data_message = toHex("NEXT") 
    response, sw1, sw2 = cardservice.connection.transmit( data_message, CardConnection.T1_protocol )
    response.append(sw1)
    response.append(sw2)
    str_hex = [str(hex(h)).replace('0x', '') for h in response]
    str_hex = ''.join(str_hex)
    print "response: " + str_hex.decode("hex")  
    UAFmsg += str_hex.decode("hex") 
 
UAFmsg = bytearry2json(UAFmsg) 

print("Forwarding card response to FIDO UAF Server: \n")
UAFurl = fido_server['AUTH_REQUEST_MSG'] % (fido_server['SCHEME'], fido_server['HOSTNAME'], fido_server['AUTH_RESPONSE_ENDPOINT'])
headers = { 'Accept': 'application/json', 'Content-Type': 'application/json'}
r = requests.post(UAFurl, data=UAFmsg, headers=headers)

response = json.loads(r.text)
print response
if response[0]["status"] == "SUCCESS":  
    print("[FIDO]: SUCCESS!")