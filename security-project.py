import base64
import binascii
import os
from base64 import b64encode, b64decode, standard_b64decode
import hashlib


from Cryptodome.Cipher import AES, Blowfish, PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util.Padding import pad
from pip._vendor.distlib.compat import raw_input

ans=True
while ans:
    print("""
    1.Codage et Décodage d'un message
    2.Hachage d'un message
    3.Craquage d'un message haché
    4.Chiffrement et déchiffrement Symétrique d'un message
    5.Chiffrement et déchiffrement Asymétrique d'un message
    6.Quitter
    """)
    ans=raw_input("Que voulez vous ? ")
    if ans=="1":
      ans2 =True
      while ans2:
        print("""
          1.Codage
          2.Décodage
          3.Quitter
          """)
        ans2 = raw_input("Que voulez vous ? ")
        if ans2 == "1":
            chaine = input('Insérez une chaine de caractère:')
            #Codage
            my_str_as_bytes = str.encode(chaine)
            encoded = b64encode(my_str_as_bytes)
            print("Codage : ",encoded.decode())
        elif ans2 == "2":
            chaine = input('Insérez une chaine de caractère:')
            #Decodage
            try:
                decoded = base64.b64decode(chaine)
                print("Decodage: ",decoded.decode())
            except Exception:
                print("Decodage: invalid format")
        elif ans2 == "3":
            ans2=None
        else:
            print("\n Votre choix n'est pas valide veuillez réssayer !")

    elif ans=="2":

      ans2 = True
      while ans2:
          print("""
          1.sha1
          2.sha224
          3.sha256
          4.sha512
          5.MD5
          6.Quitter
          """)
          ans2 = raw_input("Que voulez vous ? ")
          if ans2 == "1":
              x = input("\n Entrez votre message: ")
              # m = hashlib.sha224(x.encode()).hexdigest()
              m = hashlib.sha1(x.encode()).hexdigest()
              print(m)
          elif ans2 == "2":
              x = input("\n Entrez votre message: ")
              # m = hashlib.sha224(x.encode()).hexdigest()
              m = hashlib.sha224(x.encode()).hexdigest()
              print(m)
          elif ans2 == "3":
              x = input("\n Entrez votre message: ")
              # m = hashlib.sha224(x.encode()).hexdigest()
              m = hashlib.sha256(x.encode()).hexdigest()
              print(m)
          elif ans2 == "4":
              x = input("\n Entrez votre message: ")
              # m = hashlib.sha224(x.encode()).hexdigest()
              m = hashlib.sha512(x.encode()).hexdigest()
              print(m)
          elif ans2 == "5":
              x = input("\n Entrez votre message: ")
              # m = hashlib.sha224(x.encode()).hexdigest()
              m = hashlib.md5(x.encode()).hexdigest()
              print(m)
          elif ans2 == "6":
              ans2=None
          else:
              print("\n Votre choix n'est pas valide veuillez réssayer !")

    elif ans=="3":
      hashe = input("Entrez votre hashé: ")
      ans3 = True
      while ans3:
        print("""
        1.sha1
        2.sha224
        3.sha256
        4.sha512
        5.MD5
        6.Quitter
        """)
        ans3 = raw_input("Quelle est le type de hash que vous désirez? ")
        if ans3 == "1":
            f = open("dict.txt","r")
            lines = f.read().splitlines()
            for line in lines:
                if ( hashe == hashlib.sha1(line.encode()).hexdigest() ):
                    print("*************** Congrats *********************************")
                    print("Votre mot est " , line)
                    print("**********************************************************")
                    break
        elif ans3 == "2":
            f = open("dict.txt", "r")
            lines = f.read().splitlines()
            for line in lines:
                if (hashe == hashlib.sha224(line.encode()).hexdigest()):
                    print("*************** Congrats *********************************")
                    print("Votre mot est ", line)
                    print("**********************************************************")
                    break
        elif ans3 == "3":
            f = open("dict.txt", "r")
            lines = f.read().splitlines()
            for line in lines:
                if (hashe == hashlib.sha256(line.encode()).hexdigest()):
                    print("*************** Congrats *********************************")
                    print("Votre mot est ", line)
                    print("**********************************************************")
                    break
        elif ans3 == "4":
            f = open("dict.txt", "r")
            lines = f.read().splitlines()
            for line in lines:
                if (hashe == hashlib.sha512(line.encode()).hexdigest()):
                    print("*************** Congrats *********************************")
                    print("Votre mot est ", line)
                    print("**********************************************************")
                    break
        elif ans3 == "5":
            f = open("dict.txt", "r")
            lines = f.read().splitlines()
            for line in lines:
                if (hashe == hashlib.md5(line.encode()).hexdigest()):
                    print("*************** Congrats *********************************")
                    print("Votre mot est ", line)
                    print("**********************************************************")
                    break
        elif ans3 == "6":
            ans3=None
        else:
            print("\n Votre choix n'est pas valide veuillez réssayer !")

    elif ans=="4":
        ans4_1 = True
        while ans4_1:
            print("""
            1.Chiffrement
            2.Déchiffrement
            3.Quitter
            """)
            ans4_1 = raw_input("Que voulez vous ? ")
            #Chiffrement
            if ans4_1 == "1":
                private_msg = input("Saisir le message à chiffrer : ")
                print("\n Chiffrement et déchiffrement Symétrique d'un message")
                ans4 = True
                while ans4:
                    print("""
                    1.AES
                    2.Blowfish
                    3.Quitter
                    """)
                    ans4 = raw_input("Quelle est le type de chiffrement que vous désirez? ")
                    if ans4 == "1":
                        # AES Encrypt
                        AES_key_length = 16
                        secret_key = input("Enter votre secret ")
                        def encrypt(plaintext, key, mode):
                            encobj = AES.new(key, mode)
                            return (encobj.encrypt(plaintext))
                        ciphertext = encrypt(
                            pad(private_msg.encode(), AES_key_length),
                            pad(secret_key.encode(), AES_key_length),
                            AES.MODE_ECB)
                        print("Cipher (Hex): ", ciphertext.hex())
                        print("Cipher (Base64): ", base64.b64encode(ciphertext).decode())
                        print("Cipher (ECB): " + binascii.hexlify(bytearray(ciphertext)).decode())

                    elif ans4 == "2":
                        bs = Blowfish.block_size
                        key = input("Entrez votre longue clé ici : ")
                        cipher = Blowfish.new(key.encode(),Blowfish.MODE_ECB)
                        ciphertext = cipher.encrypt(pad(private_msg.encode(),block_size=16))
                        print(ciphertext.hex())
                    elif ans4 =="3":
                        ans4=None
                    else:
                        print("Votre choix n'est pas valide !")



            #Déchiffrement
            elif ans4_1 =="2":
                ciphertext = input("Saisir le message chiffré : ")
                ans4_2 = True
                while ans4_2:
                    print("""
                    1.AES
                    2.Blowfish
                    3.Quitter
                    """)
                    ans4_2 = raw_input("Quelle est le type de chiffrement que vous désirez? ")
                    if ans4_2 == "1":
                        ciphertext = bytes.fromhex(ciphertext)
                        AES_key_length = 16
                        secret_key = input("Enter votre secret : ")
                        # AES Decryption
                        def decrypt(ciphertext, key, mode):
                            encobj = AES.new(key, mode)
                            return (encobj.decrypt(ciphertext))

                        plaintext = decrypt(ciphertext,pad(secret_key.encode(), AES_key_length),AES.MODE_ECB)
                        print("\n ***********************************")
                        print(" ***********************************")
                        print("Le text clair est :  ", plaintext.decode())
                        print(" ***********************************")
                        print(" ***********************************")
                    elif ans4_2 == "2":
                        ciphertext = bytes.fromhex(ciphertext)
                        key = input("Enterez votre mot de passe")
                        cypher = Blowfish.new(key.encode(),Blowfish.MODE_ECB)
                        print("\n ***********************************")
                        print(" ***********************************")
                        plaintext = cypher.decrypt(ciphertext)
                        print("Le text clair est :  " ,plaintext.decode())
                        print(" ***********************************")
                        print(" ***********************************")
                    elif ans4_2 =="3":
                        ans4_2=None
                    else:
                        print("Votre choix n'est pas valide !")
            elif ans4_1 =="3":
                ans4_1=None
            else:
                print("Votre choix n'est pas valide !")

    elif ans=="5":
      print("\n Chiffrement et déchiffrement Asymétrique d'un message : ")
      ans5 = True
      while ans5:
          print("""
          1.RSA - Chiffrement & Signature
          2.RSA - Déchiffrement & Verification de la signature
          3.Quitter
          """)
          ans5 = raw_input("Que voulez vous ? ")

          # RSA
          if ans5 == "1":
              message = input("Entrez un message clair : ")
              ans5_1 = True
              while ans5_1:
                  print("""
                  1.Voir ma paire de clés
                  2.Génération des paires de clés
                  3.Chiffrer ou signer message
                  4.Quiiter
                  """)
                  ans5_1 = raw_input("Que voulez vous ? ")
                  if ans5_1 == "1":
                      secret_code = input("Entrer un mot de passe : ")
                      encoded_key = open("rsa_key.bin", "rb").read()
                      key = RSA.import_key(encoded_key, passphrase=secret_code)

                      print(key.publickey().export_key())
                  elif ans5_1 == "2":
                      secret_code = input("Entrer un mot de passe")
                      key = RSA.generate(2048)
                      encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,
                                                     protection="scryptAndAES128-CBC")
                      file_out = open("rsa_key.bin", "wb")
                      file_out.write(encrypted_key)
                      file_out.close()
                      print(key.publickey().export_key())
                  elif ans5_1 == "3":
                      ans5_2 = True
                      while ans5_2:
                          print("""
                          1.Chiffrer le message
                          2.Signer le message
                          3.Quitter
                          """)
                          ans5_2 = raw_input("Que voulez vous ? ")
                          if ans5_2 == "1":
                              # Chiffrer le message
                              secret_code = input("Entrer votre mot de passe : ")
                              encoded_key = open("rsa_key.bin", "rb").read()
                              key = RSA.import_key(encoded_key, passphrase=secret_code)

                              #data = "I met aliens in UFO. Here is the map.".encode("utf-8")
                              data = message.encode("utf-8")
                              file_out = open("encrypted_data.bin", "wb")
                              recipient_key = key
                              session_key = get_random_bytes(16)
                              # Encrypt the session key with the public RSA key
                              cipher_rsa = PKCS1_OAEP.new(recipient_key)
                              enc_session_key = cipher_rsa.encrypt(session_key)
                              # Encrypt the data with the AES session key
                              cipher_aes = AES.new(session_key, AES.MODE_EAX)
                              ciphertext, tag = cipher_aes.encrypt_and_digest(data)
                              print( ciphertext.hex() )
                              [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
                              file_out.close()

                          elif ans5_2 =="2":
                              secret_code = input("Entrer votre mot de passe : ")
                              encoded_key = open("rsa_key.bin", "rb").read()
                              key = RSA.import_key(encoded_key, passphrase=secret_code)

                              h = SHA256.new(message.encode())
                              signature = pkcs1_15.new(key).sign(h)
                              print("Message signé : ", signature.hex())
                          elif ans5_2 =="3":
                              ans5_2=None
                          else:
                              print("Votre choix n'est pas valide !")
                  elif ans5_1 =="4":
                      ans5_1=None
                  else:
                      print("Votre choix n'est pas valide !")
          elif ans5 == "2":
              # RSA : Déchiffrement ou verif signature
              ans5_3 = True
              while ans5_3:
                  print("""
                  1.Déchiffrement
                  2.Vérifier la signature d'un message
                  3.Quitter
                  """)
                  ans5_3 = raw_input("Que voulez vous ? ")
                  if ans5_3 == "1":
                      secret_code = input("Entrer votre mot de passe : ")
                      encoded_key = open("rsa_key.bin", "rb").read()
                      key = RSA.import_key(encoded_key, passphrase=secret_code)

                      file_in = open("encrypted_data.bin", "rb")

                      private_key = key

                      enc_session_key, nonce, tag, ciphertext = \
                          [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

                      # Decrypt the session key with the private RSA key
                      cipher_rsa = PKCS1_OAEP.new(private_key)
                      session_key = cipher_rsa.decrypt(enc_session_key)

                      # Decrypt the data with the AES session key
                      cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                      data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                      print(data.decode("utf-8"))
                  elif ans5_3 == "2":
                      #Signature vérification
                      message = input("Entrer votre message le même de que vous avez signé : ")
                      signature = input("Entrer votre la signature sous HEX : ")
                      signature = bytes.fromhex(signature)
                      secret_code = input("Entrer votre mot de passe : ")
                      encoded_key = open("rsa_key.bin", "rb").read()
                      key = RSA.import_key(encoded_key, passphrase=secret_code)
                      h = SHA256.new(message.encode())
                      try:
                        pkcs1_15.new(key).verify(h, signature)
                        print("\n**********************************")
                        print ("The signature is valid.")
                        print("**********************************")
                      except (ValueError, TypeError):
                        print("\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
                        print("The signature is not valid.")
                        print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
                  elif ans5_3 == "3":
                      ans5_3=None
                  else:
                      print("Votre choix n'est pas valide !")




          elif ans5 == "3":
              ans5 = None
    elif ans=="6":
      print("\n Au revoir")
      ans = None
    else:
       print("\n Votre choix n'est pas valide veuillez réssayer !")