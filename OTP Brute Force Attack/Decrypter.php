<?php

define('RSA_PRIVATE', 'private.pem');
define('RSA_PUBLIC', 'public.pem');
define('CIPHER_ALGO', 'AES-256-CBC');
define('HASH_ALGO', 'SHA256');
define('HASH_KEY', 'hmac@password');

$encryptedData=[
"param1" => "9a724726b912da9b3171a36ddd5b6fc42baf942f0a809709e365afc31184efe1049a19880fc7eedcdb71e2735f23b71e60f1f54059bd19f9f0849f31d6ca9003",
"param2" => "xE1LuJ3u1+9V/1P6QMrbjMTIaeFkBdIlwsgLLJx/+iC4rludlZH42mL1AyZlu9jTLtLcYaXAvJ6DG21mIe614GkdOVKzojCPpKzBT315lHQnCrt9cDpCodfle/BvI5TnrZEQKtOhG1dWn1omPsfWkpKXnmpX241hPvZtSEc88C50vsVbLUWZ95ghW6G07yTmK+/Tz6Ah6/rVUWukBaop5fQTcO1sPV9igHcdsmn/zk/EQdWR4AAzW4vFYhtFaq6/C5OoUWVhkj4EgVqQCZ71MWWAC6dH7eUiW7xAiuVpfwv+IH8g2UozCXe9Zrz59KdCl6za0XApKlYQOxyJ0e3CUQ==",
"param3" => "6d71b7cfd7bd510226d23a4228c80a3fcc8619b90b30818c3c375b0bc7a99e43",
];

$decrryptedData = payloadDecrypt($encryptedData);
printData($decrryptedData);
exit();

function printData($obj)
{
    echo "\n"."<pre>";
    print_r($obj);
    echo "<pre>"."\n";
}

function payloadDecrypt($data)
{
    $payloadValidation = validatePayload($data);
    
    if ($payloadValidation['code'] !== 200) {
        return $payloadValidation;
    }
    
    $cipherData = $data['param1'];
    $RSAEncryptedKey = $data['param2'];
    $hmacHash = $data['param3'];
    
    if (hashValidation($cipherData, $hmacHash) === false) {
        return [
            "code" => 400,
            "status" => "failed",
            "message" => "Hash Validation failed."
        ];
    }
    
    $encryptionKey = RSADecrypt(base64_decode($RSAEncryptedKey));
    
    if ($encryptionKey['code'] !== 200) {
        return $encryptionKey;
    }
    
    $plainTextData = decryptData($cipherData, $encryptionKey['data']);
    
    if ($plainTextData !== null) {
        return [
            "code" => 200,
            "status" => "success",
            "message" => "success",
            "data" => $plainTextData
        ];
    }
    
    return [
        "code" => 400,
        "status" => "failed",
        "message" => "Sometnig went wrong. Please try again.",
        "error_message" => "AES decryption failed."
    ];
}

function RSADecrypt($cipherData)
{
    while(openssl_error_string() !== false);
    
    $fileHander = fopen(RSA_PRIVATE, 'r');
    $privateKey = fread($fileHander, 8192);
    fclose($fileHander);
    
    if(! openssl_private_decrypt(
        $cipherData, 
        $decryptedKey, 
        $privateKey,
        $padding = OPENSSL_PKCS1_OAEP_PADDING
    )) {
        return [
            'code' => 400,
            'status' => 'failed',
            'message' => 'RSA Decryption ERROR',
            'error_message' => "RSA Decryption ERROR : ".openssl_error_string()
        ];
    }
    
    return [
        'code' => 200,
        'status' => 'success',
        'message' => 'success',
        'data' => $decryptedKey
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
