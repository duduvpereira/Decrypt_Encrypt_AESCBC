""" 
EXEMPLO DA EXECUÇÃO EM PYTHON3:

eduardo-pereira@eduardopereira-VirtualBox:~/crypto/trab2$ python3 Decrypt_Encrypt_AESCBC_EduardoPereira.py 
O valor de a =  61
valor B: 7AC145D833A51F715B07FC84CA558075B2C77F466AB3D07C5A63009DEAF74A3789E572D8A4CBD0E50E2C6423216609A130551E0479FBC1D73FD5B70F2054CA80440A9B2C4918CE1248036AA0CEE1890098A58B0FB85183A0D56108976CB2F2923FF04762F9DF48554231B2CC7661B0FB8A532D22B217B37D2E71D45FECD561D1


Os 128 primeiros bits de S =  9b2361cbc49a4ecd311ce8e8103d1da1


Mensagem: 6FC94D7034562782D8C04E3D87D684042020FCBAEFAA97913A8BF5AF1741F8BD026208E90504F7473182102DA5E06319AE457A3BB322FA3C4B5E26D74EE5DC2A19BCD62C7FF9885791010810442AA510FBE054D50E8327938B4A14FFA1E530CB57634E2B0455D46494FC620ED0BA961D4237CCF3486E72FE103643E23A84C457EB6DBFE05D9645A39FAA6202234040D4C8F45C556DE3CF7A8B35D4AAE2F8AC5511C91A715DF429C60F64ED3D4C475515


Chave(128 primeiros bits de S): 9b2361cbc49a4ecd311ce8e8103d1da1


Mensagem Recebida:  Foi mesmo :-). Agora comenta bem o código e coloca este exemplo completo no início do código como comentário. Depois submete o código no Moodle. []s


Mensagem a ser enviada em HEX:  96052011513aeac5f1110e5583104e849ee784633fee5cf889ee6dc1b388dccdaf3a5b146701701e044e9f9a1a7e93b1518bcf9c7e6e3af0f67589e079e50a0e2c4f92400b83cac0a0f8468a8af1aa0f789b7976c67c17dc1a45d183e998b665e25c9e901a6be5b302f69aca6d6b10adabecc010dac0fa148191cdb7d1749b72645e54b3a7d49d04ee8c02f794cb60c8ba78dd5df9b6bebc50be636336490d8d790fd188aaa5a960318c5aa37cfa54d7

"""


import sys
import codecs
import time
import hashlib

from base64 import b64encode, b64decode, decode
from binascii import unhexlify

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from hashlib import md5

from Crypto.Random import get_random_bytes



if __name__ == '__main__':

    a = 97
    p = 124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084041279837566626881119772675984258163062926954046545485368458404445166682380071370274810671501916789361956272226105723317679562001235501455748016154805420913
    g = 115740200527109164239523414760926155534485715860090261532154107313946218459149402375178179458041461723723231563839316251515439564315555249353831328479173170684416728715378198172203100328308536292821245983596065287318698169565702979765910089654821728828592422299160041156491980943427556153020487552135890973413

    #Printa a
    print("O valor de a = ", hex(a)[2:])

    #Recebe B e converte pra int
    b2 = input("valor B: ")
    b2 = int(b2, 16)

    
    
    ##################################################################
    V = pow(b2, a, p) # B^a mod p

    hex_v = hex(V)[2:]  # converte para hex

   
    v_bytes = bytes.fromhex(hex_v)

    S = hashlib.sha256(v_bytes).hexdigest()  # Calc sha256 para os bytes de V
    #print(S)
    ##################################################################

    print("\n")

    #Pega os 128 primeiros bits de S
    S128 = ""
    for i in range(32):
        S128 += S[i]

    print("Os 128 primeiros bits de S = ", S128)
    print("\n")
    
    #Separa em bytes
    password = unhexlify(S128)
    #print(password)

    #Recebe a mensagem
    mensagem = input("Mensagem: ")
    print("\n")
    chave = input("Chave(128 primeiros bits de S): ")
    print("\n")
    #Separa em bytes
    password = unhexlify(chave)

    #msg = "CF9798B0C26693AC5775B7B22E690392FE2FADA778C9C0ED7B9AC7B985AF3AABE0890EB35CFE7E369011E5E0AC6FC32A72E6ED055C6A99F4E68D51138897EACB39C91B7ED96199314E3C49B8B0284E8CDB717EEB2F57DCA02919DC7ACB09D778"
    msg = mensagem

    #Pega os 128 primeiros bits da mensagem, iv
    iv = ""
    for i in range(32):
        iv += msg[i]
    #print(iv)
    #Separa em bytes
    iv = unhexlify(iv)

    #Pega a partir dos 128 primeiros bits, mensagem sem o IV
    msg2 = ""
    i=32
    for i in range(32, len(msg)):
        msg2 += msg[i]
    #print(msg2)
    out = bytes.fromhex(msg2)


    # Decipher cipher text
    decipher = AES.new(password, AES.MODE_CBC, iv)

    plaintext = unpad(decipher.decrypt(out), AES.block_size)
    
    #printa mensagem recebida
    print("Mensagem Recebida: ", plaintext.decode('utf-8'))
    print("\n")

    #inverte a menagem
    invText = plaintext.decode('utf-8')[::-1]
    #print(invText)
    
    #Gera um iv aleatorio para gerar a mensagem recebida
    iv = get_random_bytes(AES.block_size)
    #print(iv.hex())
    
    #Cifra a mensagem a ser enviada
    cipher = AES.new(password, AES.MODE_CBC, iv)
    cipher = (iv + cipher.encrypt(pad(invText.encode('utf-8'), AES.block_size)))
    #print (cipher)
    
    #Coloca pra HEXA
    cipher = cipher.hex()
    print("Mensagem a ser enviada em HEX: ", cipher)
    print("\n")

