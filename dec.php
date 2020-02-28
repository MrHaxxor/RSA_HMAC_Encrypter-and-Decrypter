<?php

$data = ["data" => '{"userName":"test","otp":"8989"}'];

$encryptedData=[
"param1" => "f5a0ce09aa5d6f1575e875e2290a2dbf8c0167816819b39cdb85ab07f04760948c00b290cbbc48a12775ba9b25724f05f79d2c6d31de806e2466cac1c1cdff16",
"param2" => "F0UjkggpOBBKQeFD7ALYgKXwuwM54uIQhFXtUDQY+6v3JNLokjorxtS8bojTOELp40o+hzN4l/nOUUHrG7bOGU2ZlaCP1mBNmtRswufB/TCbMH7LnL9kNxz+iiothT6i2mMSWC7+ysiUNJF8NBhDWuTHSZlHuQMxEr0k2he+aD/Oq6b+fjf/FVcDDP7DN4faMKDfA6/jqnqNv6LiEqk9vCBK54IZnvkKEN4WllcrSNnbOqAQcqlQaF0WmHETugDZv4y3sMS6l9xx19Kvb6YAc3+wEz0R7ZNKp7ky/WSGJlTFvMb7ZOvvi41kwq15v1E0YyZlpegTxwP0wI5H9Y7FXQ==",
"param3" => "388d064e4c37d1fd7fb37cd016b6381dcc6155f7d1052d778500ac089a34570f",
];

define('RSA_PRIVATE', 'private.pem');
define('RSA_PUBLIC', 'public.pem');
define('CIPHER_ALGO', 'AES-256-CBC');
define('HASH_ALGO', 'SHA256');
define('HASH_KEY', 'hmac@password');

$decrryptedData = payloadDecrypt($encryptedData);
printData($decrryptedData);

function printData($obj)
{
    echo "<pre>";
    print_r($obj);
    echo "<pre>";
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
