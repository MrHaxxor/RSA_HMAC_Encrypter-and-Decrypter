# Create private Key
$ openssl genrsa -out private.pem 2048

# Create Public Key
$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem

OR

# Get Public key From Website/IP

$ openssl s_client -connect www.example.com:443 | openssl x509 -pubkey -noout

# To Encrypt data as same as Mobile, ios, Tv app do.
> change $data variable a text to encrypt.
$ php Enc_Dec.php

# To Decrypt data as same as Server do.
$ php Decrypter.php 
> change $encryptedData variable a text to Decrypt.




