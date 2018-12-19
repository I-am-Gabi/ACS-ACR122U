1. instale [pyscard](https://pyscard.sourceforge.io/user-guide.html#).
  ```
  $ pip install pyscard
  ```
  
  Teste se a instalação aconteceu corretamente:
  
  ```
  $ wget https://raw.githubusercontent.com/I-am-Gabi/ACS-ACR122U/master/test-nfc.py
  $ python test-nfc.py
  ```

2. suba o [servidor fido](https://github.com/emersonmello/docker-fidouafserver)
  ```
  $ git clone http://github.com/emersonmello/docker-fidouafserver
  $ cd docker-fidouafserver
  $ docker-compose up
  ```

3. Instale o [app openingdoor](https://github.com/emersonmello/openingdoor)

4. Rode o projeto
  ```
  $ git clone https://github.com/I-am-Gabi/ACS-ACR122U.git
  $ cd ACS-ACR122U
  $ python NFCReader.py  
  ```
  Aproxime o celular do leitor.