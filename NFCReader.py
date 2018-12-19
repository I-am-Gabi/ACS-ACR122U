from smartcard.CardType import AnyCardType
from smartcard.CardConnection import CardConnection
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString 

from settings import fido_server
from util import bytearry2json

import json
import sys
import requests
import time 
import binascii
import logging
logging.basicConfig(format='%(asctime)s | %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)

from collections import OrderedDict

BLOCK_SIZE = 250 

cardtype = AnyCardType()
cardrequest = CardRequest(timeout=10, cardType=cardtype)
cardservice = cardrequest.waitforcard()


# Communication parameters are mostly important for the protocol negotiation between the smart card reader and the card. 
# The main smartcard protocols are the T=0 protocol and the T=1 protocol, for byte or block transmission, respectively. 
# The required protocol can be specified at card connection or card transmission.
connection = cardservice.connection.connect(CardConnection.T1_protocol)
# connection attribute, which is a CardConnection for the card
# logging.info(toHexString( cardservice.connection.getATR() ))

# logging.info('reader: ', str(cardservice.connection.getReader()[0]))


######################################## APDU
SELECT = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xF0, 0x39, 0x41, 0x48, 0x14, 0x81, 0x00, 0x00] 
apdu = SELECT 
logging.info("sending: [apdu]")

response, sw1, sw2 = cardservice.connection.transmit(apdu, CardConnection.T1_protocol)  
response.append(sw1)
response.append(sw2)
str_hex = [str(hex(h)).replace('0x', '') for h in response]
str_hex = ' '.join(str_hex) 
if (bytes.fromhex(str_hex).decode('utf-8')) != "HELLO":
    logging.error("** Opss ** I'm expecting HELLO msg")

######################################## FIDO Auth Request Message
logging.info("Doing AuthRequest to FIDO UAF Server\n")
UAFurl = fido_server['AUTH_REQUEST_MSG'] % (fido_server['SCHEME'], fido_server['HOSTNAME'], fido_server['AUTH_REQUEST_ENDPOINT'])
 
try:
    r = requests.get(UAFurl)
    r.raise_for_status()
except requests.exceptions.RequestException as e:  # This is the correct syntax
    logging.error(e) 
    sys.exit(1)

content = r.content   
blocks = int((len(content) / BLOCK_SIZE) + 1)

data_message = "BLOCK:" + str(blocks)
logging.info('sending: ' + data_message)
 
response, sw1, sw2 = cardservice.connection.transmit(list(bytearray(data_message, 'utf8')), CardConnection.T1_protocol ) 
response.append(sw1)
response.append(sw2)
str_hex = [str(hex(h)).replace('0x', '') for h in response]
str_hex = ' '.join(str_hex) 
logging.info("response: " + bytes.fromhex(str_hex).decode('utf-8'))

######################################## SEND PACK 

# Sending UAFRequestMessage to card
chunks = len(content)
msg_packages = ([ content[i:i + BLOCK_SIZE] for i in range(0, chunks, BLOCK_SIZE) ])
for pack, index in zip(msg_packages, range(1, chunks+1)):
    logging.info("Seding package %s..." % index)  
    response, sw1, sw2 = cardservice.connection.transmit(list(bytearray(pack)), CardConnection.T1_protocol )
    response.append(sw1)
    response.append(sw2) 
    str_hex = [str(hex(h)).replace('0x', '') for h in response]
    str_hex = ' '.join(str_hex) 
    logging.info("response: " + bytes.fromhex(str_hex).decode('utf-8'))

logging.info("Sending READY!")

response, sw1, sw2 = cardservice.connection.transmit(list(bytearray("READY", 'utf8')), CardConnection.T1_protocol )
response.append(sw1)
response.append(sw2)
str_hex = [str(hex(h)).replace('0x', '') for h in response]
str_hex = ' '.join(str_hex) 
logging.info("response: " + bytes.fromhex(str_hex).decode('utf-8'))

logging.info("Waiting...\n") 

time.sleep(5)

while 'WAIT' == bytes.fromhex(str_hex).decode('utf-8'):  
    logging.info("SEND: " + "READY")
    response, sw1, sw2 = cardservice.connection.transmit(list(bytearray("READY", 'utf8')), CardConnection.T1_protocol )
    response.append(sw1)
    response.append(sw2)
    str_hex = [str(hex(h)).replace('0x', '') for h in response]
    str_hex = ' '.join(str_hex) 
    logging.info("response: " + bytes.fromhex(str_hex).decode('utf-8')) 
 
logging.info("Sending RESPONSE!")
response, sw1, sw2 = cardservice.connection.transmit(list(bytearray("RESPONSE", 'utf8')), CardConnection.T1_protocol )
response.append(sw1)
response.append(sw2)
str_hex = [str(hex(h)).replace('0x', '') for h in response]
str_hex = ' '.join(str_hex) 
logging.info("response: " + bytes.fromhex(str_hex).decode('utf-8'))
logging.info("blocks: " + bytes.fromhex(str_hex).decode('utf-8').split(':')[1])

blocks = int(bytes.fromhex(str_hex).decode('utf-8').split(':')[1]) 
UAFmsg = '\0'
for block in range(0, blocks): 
    logging.info("receiving block --> %s" % block) 
    response, sw1, sw2 = cardservice.connection.transmit(list(bytearray("NEXT", 'utf8')), CardConnection.T1_protocol )
    response.append(sw1)
    response.append(sw2)
    str_hex = [str(hex(h)).replace('0x', '') for h in response]
    str_hex = ''.join(str_hex)
    # logging.info("response: " + str_hex.decode("hex"))
    UAFmsg += bytes.fromhex(str_hex).decode('utf-8')
 
UAFmsg = bytearry2json(UAFmsg) 

logging.info("Forwarding card response to FIDO UAF Server: \n")
UAFurl = fido_server['AUTH_REQUEST_MSG'] % (fido_server['SCHEME'], fido_server['HOSTNAME'], fido_server['AUTH_RESPONSE_ENDPOINT'])
headers = { 'Accept': 'application/json', 'Content-Type': 'application/json'}
r = requests.post(UAFurl, data=UAFmsg, headers=headers)

response = json.loads(r.text)
logging.info(response)
if response[0]["status"] == "SUCCESS":  
    logging.info("[FIDO]: SUCCESS!")
 