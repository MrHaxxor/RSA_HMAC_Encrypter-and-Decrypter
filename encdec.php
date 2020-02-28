<?php

$data = ["data" => '{"userName":"test","otp":"8989"}'];

define('RSA_PRIVATE', 'private.pem');
define('RSA_PUBLIC', 'public.pem');
define('CIPHER_ALGO', 'AES-256-CBC');
define('HASH_ALGO', 'SHA256');
define('HASH_KEY', 'hmac@password');

printData($data);

$encryptedData = payloadEncrypt($data);
printData($encryptedData);

function printData($obj)
{
    echo "<pre>";
    print_r($obj);
    echo "<pre>";
}

function payloadEncrypt($params)
{
    $data = isset($params['data']) && $params['data'] != '' ? $params['data'] : null;
            
    if ($data == null) {
        printData("Missing Data.");
        exit();
    }
    
    $binKey = random_bytes(32);

    $EncryptedBinaryKey = RSAEncrypt($binKey);

    if(!isset($EncryptedBinaryKey['data']) || $EncryptedBinaryKey['data'] == "") {
        printData($EncryptedBinaryKey);
        exit();
    }

    $iv = random_bytes(openssl_cipher_iv_length(CIPHER_ALGO));

    $cipherText = openssl_encrypt(
        $data,
        CIPHER_ALGO,
        $binKey,
        OPENSSL_RAW_DATA,
        $iv
    );

    $ivHex = bin2hex($iv);
    $cipherHex = bin2hex($cipherText);
    $combinedcipher = $ivHex.$cipherHex;

    $generateHash = hash_hmac(HASH_ALGO, $combinedcipher, HASH_KEY);

    return [
        "param1" => $combinedcipher,
        "param2" => base64_encode($EncryptedBinaryKey['data']),
        "param3" => $generateHash,
    ];

}

function RSAEncrypt($data)
{
    while(openssl_error_string() !== false);
    
    $fileHander = fopen(RSA_PUBLIC, 'r');
    $publicKey = fread($fileHander, 8192);
    fclose($fileHander);

    if (! openssl_public_encrypt(
        $data,
        $encryptedKey,
        $publicKey
        ,$padding = OPENSSL_PKCS1_OAEP_PADDING
    )) {
        return [
            'code' => 400,
            'status' => 'failed',
            'message' => 'RSA Encryption ERROR',
            'error_message' => "RSA Decryption ERROR : ".openssl_error_string()
        ];
    }
    
    return [
        'code' => 200,
        'status' => 'success',
        'message' => 'success',
        'data' => $encryptedKey
    ];
}

function validatePayload(array $params) : array
{
    if (! isset($params['param1']) || $params['param1'] === "") {
        return [
            "code" => 601,
            "status" => "failed",
            "message" => "Missing param1."
        ];
    }
    
    if (! isset($params['param2']) || $params['param2'] === "") {
        return [
            "code" => 601,
            "status" => "failed",
            "message" => "Missing param2."
        ];
    }
    
    if (! isset($params['param3']) || $params['param3'] === "") {
        return [
            "code" => 601,
            "status" => "failed",
            "message" => "Missing param3."
        ];
    }
    
    return [
        "code" => 200,
        "status" => "success",
        "message" => "valid data"
    ];
}

function hashValidation($data, $hash)
{
    $generateHash = hash_hmac(HASH_ALGO, $data, HASH_KEY);
    
    if ($generateHash !== $hash) {
        return false;
    }
    
    return true;
}

function decryptData($cipherText, $decriptionKey)
{
    try {
    
        //Get Key
        $key = $decriptionKey;
        
        //Get Algo from Credentials file
        $algo = CIPHER_ALGO;
        
        if (strlen($cipherText) <= 32) {
            return null;
        }
        
        $iv = substr($cipherText, 0, 32);
        
        $cipherText = substr($cipherText, 32);
        
        if ($cipherText == '') {
            return null;
        }
        
        //Convert $iv hex to bin
        $iv = hex2bin($iv);
        
        //$cipherText Hex decode
        $cipherText = hex2bin($cipherText);
        
        // Decrypt $data with key and iv
        $plaintext = openssl_decrypt(
            $cipherText,
            $algo,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        return $plaintext;
        
    } catch (\Throwable $exception) {
        return null;
    }
}
