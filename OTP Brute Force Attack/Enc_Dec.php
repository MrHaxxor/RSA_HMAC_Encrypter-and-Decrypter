<?php
/**********
	Author: Jagdish SK
	
************/


$data = ["data" => '{"userName":"test","otp":"8989"}'];

define('RSA_PRIVATE', 'private.pem');
define('RSA_PUBLIC', 'public.pem');
define('CIPHER_ALGO', 'AES-256-CBC');
define('HASH_ALGO', 'SHA256');
define('HASH_KEY', 'hmac@password');

$filename="wordlist.txt";
$fp = @fopen($filename, 'r'); 

unlink ("Data_With_Payload.txt"); 
$Data_with_payload = 'Data_With_Payload.txt';

unlink ("payload.txt"); 
$file = 'payload.txt';

// Add each line to an array
if ($fp) {
   $attack_payload = explode("\n", fread($fp, filesize($filename)));
//print_r($members[0]);
}

$arrayLength=count($attack_payload);
$i = 0;
while ($i < $arrayLength)
        {
	$data =$data;
	$data_decode=json_decode($data['data'],true);
	$data_decode["otp"]=$attack_payload[$i];
	$data["data"]=json_encode($data_decode);
//	print_r($data);
	
	$encryptedData = payloadEncrypt($data);
	//print_r("\n Encrypted Payload ".$i." => ".$encryptedData["Payload"]."\n");

	$decrryptedData = payloadDecrypt($encryptedData);
	$decrryptedData2=implode(" ",$decrryptedData);
	//echo "\n Plaintext Data ".$i."=> ";
	//print_r(array($decrryptedData));

	file_put_contents($file,"\n".$encryptedData["Payload"]."\n", FILE_APPEND);
	file_put_contents($Data_with_payload, "\n\n Encrypted Payload ".$i." => ".$encryptedData["Payload"]."\n", FILE_APPEND);
	file_put_contents($Data_with_payload, "\n Plaintext Data ".$i." => ", FILE_APPEND);
	file_put_contents($Data_with_payload, $decrryptedData2, FILE_APPEND);
	$i++;
	if ($i == $arrayLength)
		{
			print_r("\n Payload List Created\n ");
		}
	
        }


$encryptedData = payloadEncrypt($data);
//print_r("\n Payload => ".$encryptedData["Payload"]."\n");

$decrryptedData = payloadDecrypt($encryptedData);
//printData("\n Decrypted Data=> ".$decrryptedData." \n");

//printData($data);
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
	# Modify as needed payload generation
	"Payload" => '{"param1":"'.$combinedcipher.'","param2":"'.base64_encode($EncryptedBinaryKey['data']).'","param3":"'.$generateHash.'"',
    ];
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

//root function ends here


?>




