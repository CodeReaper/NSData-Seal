NSData-Seal
===========

Easily encrypt and decrypt with public and private keys like openssl_seal in PHP.

Created as biproduct of [unsealed secrets](https://github.com/CodeReaper/unsealed-secrets) which is a collection of examples on how to encrypt and decrypt in multiple languages.    

## Encode data

	// assume we have NSData *sensitiveData

    NSString *resourcePath = [NSBundle mainBundle] pathForResource:@"name_of_public_certificate" ofType:@"der"];
    NSData *certData = [NSData dataWithContentsOfFile:resourcePath];
    SecKeyRef public_key = [certData publicKeyRef];

    NSData *sealed = [sensitiveData sealWithPublicKey:public_key];

## Decode data

	// assume we have NSData *sealed

	NSString *resourcePath = [[NSBundle mainBundle] pathForResource:@"name_of_p12" ofType:@"p12"];
    NSData *p12Data = [NSData dataWithContentsOfFile:resourcePath];
    SecKeyRef private_key = [p12Data privateKeyRefWithPassword:@""];

    NSData *unsealed = [sealed openWithPrivateKey:private_key];

## Help with OpenSSL commands
It can be a little tricky getting the private and public key to work,
so you can use the following to generate a 2048 bit keypair.

	openssl genrsa -out private_key.pem 2048
	openssl req -new -key private_key.pem -out certificate_request.csr -subj '/CN=www.example.com/O=Example LTD./C=US'
	openssl x509 -req -days 3650 -in certificate_request.csr -signkey private_key.pem -out public_certificate.crt
	openssl x509 -outform der -in public_certificate.crt -out public_certificate.der
	openssl pkcs12 -export -out private_p12.p12 -inkey private_key.pem -in public_certificate.crt -passin pass: -passout pass:
	rm certificate_request.csr
	rm public_certificate.crt