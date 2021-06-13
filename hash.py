#Programmer: Ahmed Mohamed (AL-ALamy)
#Channel YouTube : AL-Alamy Tube
#Encrypt v1.0
#####################################################
#colors
B="\033[0;30m" # Black
R="\033[0;31m" # Red
G="\033[0;32m" # Green
Y="\033[0;33m" # Yellow
b="\033[0;34m" # Blue
P="\033[0;35m" # Purple
C="\033[0;36m" # Cyan
W="\033[0;37m" # White
#####################################################
import os,system,hashlib
os.system('clear')
print ("""    +B     
          +----------------INFO----------------+
          |    [+] Programmer:Ahmed Mohamed    |
          |    [+] Channel:AL-Alamy Tube       |
          |    [+] Gthub:AL-AlamySploit        |
          |         [+] Encrypt v1.0           |
          +------------------------------------+
          
         [01] Base64
         [02] Base32
         [03] Base16
         [04] MD4
         [05] MD5
         [06] SHA-1
         [07] SHA-224
         [08] SHA-256
         [09] SHA-384
         [10] SHA-512
      [00] Exit
      """)
A1 = raw_input ("""Encrypt > """)
######################################################
if A1 == '1' :
    import base64
    print ("""
    [1] Encrypt
    [2] Decrypt
    """)
    A1 = raw_input ("""Encrypt > """)
    if A1 == '1' :
          encrypt = raw_input('Anything for Encryption: ')
          en=base64.b64encode(encrypt)
          print ('+G [+] Your Encryption: ' +en)
  elif A1 == '2' :
    decrypt = raw_input('Anything for Decryption: ')
    de = base64.b64decode(decrypt)
    print ('+G [+] your Decryption: ' +de)
######################################################
elif A1 == '2' :
    import base64
    print ("""
    [1] Encrypt
    [2] Decrypt
    """)
    A1 = raw_input ("""Encrypt > """)
    if A1 == '1' :
    encrypt = raw_input('Anything for Encryption: ')
    et=base64.b32encode(encrypt)
    print ('[+] Your Encryption: ' +et)
  elif A1 == '2' :
    decrypt = raw_input('Anything for Decryption: ')
    dt = base64.b32decode(decrypt)
    print ('[+] your Decryption: ' +dt)
######################################################
elif A1 == '3' :
    import base64
    print ("""
    [1] Encrypt
    [2] Decrypt
    """)
    A1 = raw_input ("""Encrypt > """)
    if A1 == '1' :
    encrypt = raw_input('Anything for Encryption: ')
    ey=base64.b16encode(encrypt)
    print ('[+] Your Encryption: ' +ey)
  elif A1 == '2' :
    decrypt = raw_input('Anything for Decryption: ')
    dy = base64.b16decode(decrypt)
    print ('[+] your Decryption: ' +dy)
######################################################
elif A1 == '4' :
    in_user = raw_input('Enter anything for Encryption : ')
    md4 = hashlib.md4(in_user).hexdigest()
    print ('[+] Your Decryption : ' + md4)
######################################################
elif A1 == '5' :
    in_user2 = raw_input('Enter anything for Encryption : ')
    md5 = hashlib.md5(in_user2).hexdigest()
    print ('[+] Your Decryption : ' + md5)
######################################################    
elif A1 == '6' :
    in_user3= raw_input('Enter anything for Encryption : ')
    sha1 = hashlib.sha1(in_user3).hexdigest()
    print ('[+] Your Decryption : ' + sha1)
##################################################
elif A1 == '7' :
    in_user4 = raw_input('Enter anything for Encryption : ')
    sha224 = hashlib.sha224(in_user4).hexdigest()
    print ('[+] Your Decryption : ' + sha224)
######################################################
elif A1 == '8' : 
    in_user5 = raw_input('Enter anything for Encryption : ')
    sha256 = hashlib.sha256(in_user5).hexdigest()
    print ('[+] Your Decryption : ' + sha256)
######################################################   
elif A1 == '9' : 
    in_user6 = raw_input('Enter anything for Encryption : ')
    sha384 = hashlib.sha384(in_user6).hexdigest()
    print ('[+] Your Decryption : ' + sha384)
######################################################
elif A1 == '10' : 
    in_user7 = raw_input('Enter anything for Encryption : ')
    sha512 = hashlib.sha512(in_user7).hexdigest()
    print ('[+] Your Decryption : ' + sha512)
######################################################
elif A1 == '0' :
    sys.exit()
