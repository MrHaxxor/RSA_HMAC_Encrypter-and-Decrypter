# Create private Key
$ openssl genrsa -out private.pem 2048

# Create Public Key
$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem

OR

# Get From Website

openssl s_client -connect www.example.com:443 | openssl x509 -pubkey -noout

# To Create wordlist of payloads or use your one.
$ crunch  4 4  -t %%%%   > wordlist.txt 

>> For more option see help page.

# To Encrypt data as same as Mobile, ios, Tv app do.
>> channge $data variable a text to encrypt.
$ php Enc_Dec.php

# To Decrypt data as same as Server do.
$ php Decrypter.php 
>> channge  $encryptedData variable a text to Decrypt.


# For Attack of OTP or Username or Password 
>> Use generated Payloads with Burpsuite as required.




