from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString, toBytes

cardtype = AnyCardType()
cardrequest = CardRequest( timeout=5, cardType=cardtype )
cardservice = cardrequest.waitforcard()

cardservice.connection.connect(CardConnection.T1_protocol)
print(toHexString( cardservice.connection.getATR() ))
print(cardservice.connection.getReader())