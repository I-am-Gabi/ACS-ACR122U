from smartcard.CardType import AnyCardType
from smartcard.CardConnection import CardConnection
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString

from settings import fido_server
import sys
import requests
import time

BLOCK_SIZE = 200 

cardtype = AnyCardType()
cardrequest = CardRequest( timeout=10, cardType=cardtype )
cardservice = cardrequest.waitforcard()

def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch))#.replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv 
        lst.append(int(hv, 16))
    
    return lst# reduce(lambda x,y:x+y, lst)

# Communication parameters are mostly important for the protocol negotiation between the smart card reader and the card. 
# The main smartcard protocols are the T=0 protocol and the T=1 protocol, for byte or block transmission, respectively. 
# The required protocol can be specified at card connection or card transmission.
connection = cardservice.connection.connect(CardConnection.T1_protocol)
# connection attribute, which is a CardConnection for the card
print toHexString( cardservice.connection.getATR() )

print 'reader: ', cardservice.connection.getReader()

 
SELECT = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xF0, 0x39, 0x41, 0x48, 0x14, 0x81, 0x00, 0x00]
# DF_TELECOM = [0x7F, 0x10]
apdu = SELECT# + DF_TELECOM
print 'sending ' + toHexString(apdu)

response, sw1, sw2 = cardservice.connection.transmit( apdu, CardConnection.T1_protocol )
print "response: ", "%s" % (response)
print "status words: ", "%x %x" % (sw1, sw2)

######################################## SEND BLOCKS

# FIDO Auth Request Message
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

BLOCKS = [0x42, 0x4c, 0x4f, 0x43, 0x4b, 0x3a, 0x35] # BLOCK:5
print 'sending ' + toHexString(BLOCKS)

response, sw1, sw2 = cardservice.connection.transmit( BLOCKS, CardConnection.T1_protocol )
print "response: ", "%s" % (response)
print "status words: ", "%x %x" % (sw1, sw2)

######################################## SEND PACK

# Sending UAFRequestMessage to card
chunks = len(content)
msg_packages = ([ content[i:i + BLOCK_SIZE] for i in range(0, chunks, BLOCK_SIZE) ])
for pack, index in zip(msg_packages, range(1, chunks+1)):
    print("Seding package %s..." % index)
    pbtTx = toHex(pack)
    print pbtTx
    response, sw1, sw2 = cardservice.connection.transmit( pbtTx, CardConnection.T1_protocol )
    print "response: ", "%s" % (response)
    print "status words: ", "%x %x" % (sw1, sw2)

print("\nSending READY!")


pbtTx = toHex("READY")
response, sw1, sw2 = cardservice.connection.transmit( pbtTx, CardConnection.T1_protocol )
print "response: ", "%s" % (response)
print "status words: ", "%x %s" % (sw1, sw2)

print("\nWaiting...\n") 

time.sleep(5)

while '84' == str(sw2): 
	pbtTx = toHex("READY")
	print("SEND: " + "READY")
	response, sw1, sw2 = cardservice.connection.transmit( pbtTx, CardConnection.T1_protocol )
	print "response: ", "%s" % (response)
	print "status words: ", "%x %s" % (sw1, sw2)

pbtTx = toHex("RESPONSE")
print("Sending RESPONSE!")
response, sw1, sw2 = cardservice.connection.transmit( pbtTx, CardConnection.T1_protocol )
print "response: ", "%x %x %x %x %x" % (response[0],response[1],response[2],response[3],response[4])
print "status words: ", "%x %x" % (sw1, sw2)
