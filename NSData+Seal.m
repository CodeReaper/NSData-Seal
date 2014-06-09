//
//  NSData+Seal.m
//  ExampleApp
//
//  Created by Jakob Jensen on 09/06/14.
//
//

#import "NSData+Seal.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation NSData (Seal)

- (NSData *)sealWithPublicKey:(SecKeyRef)publicKey
{
    uint8_t iv[128];
    arc4random_buf(&iv, 128);

    size_t tokenBytesLength = 256;
    uint8_t *tokenBytes =  (uint8_t *)malloc(sizeof(uint8_t) * tokenBytesLength);
    SecKeyEncrypt(publicKey,
                  kSecPaddingPKCS1,
                  iv,
                  128,
                  tokenBytes,
                  &tokenBytesLength);

    NSData *tokenData = [NSData dataWithBytes:tokenBytes length:tokenBytesLength];
    free(tokenBytes);
    NSString *token = [tokenData base64EncodedStringWithOptions:0];

    size_t usedBuffer;
    size_t bufferSize = self.length + kCCKeySizeMinRC4;
    void *buffer = malloc(bufferSize);

    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmRC4,
                                          kCCModeRC4,
                                          iv,
                                          128,
                                          NULL,
                                          self.bytes,
                                          self.length,
                                          buffer,
                                          bufferSize,
                                          &usedBuffer);

    if (cryptStatus != kCCSuccess) {
        free(buffer);
        return nil;
    }

    NSData *payloadData = [NSData dataWithBytes:buffer length:usedBuffer];
    free(buffer);
    NSString *payload = [payloadData base64EncodedStringWithOptions:0];

    NSMutableDictionary *json = [NSMutableDictionary new];

    json[@"token"] = token;
    json[@"payload"] = payload;

    return [NSJSONSerialization dataWithJSONObject:json options:0 error:nil];
}

- (NSData *)openWithPrivateKey:(SecKeyRef)privateKey
{
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:self options:0 error:nil];

    NSString *token = json[@"token"];
    NSString *payload = json[@"payload"];

    if (!token || !payload) return nil;

    NSData *tokenData = [[NSData alloc] initWithBase64EncodedString:token options:0];
    NSData *payloadData = [[NSData alloc] initWithBase64EncodedString:payload options:0];

    size_t tokenBytesLength = 256;
    uint8_t *tokenBytes =  (uint8_t *)malloc(sizeof(uint8_t) * tokenBytesLength);
    SecKeyDecrypt(privateKey,
                  kSecPaddingPKCS1,
                  tokenData.bytes,
                  tokenData.length,
                  tokenBytes,
                  &tokenBytesLength);

    size_t usedBuffer;
    size_t bufferSize = payloadData.length + kCCKeySizeMinRC4;
    void *buffer = malloc(bufferSize);

    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmRC4,
                                          kCCModeRC4,
                                          tokenBytes,
                                          128,
                                          NULL,
                                          payloadData.bytes,
                                          payloadData.length,
                                          buffer,
                                          bufferSize,
                                          &usedBuffer);
    free(tokenBytes);

    if (cryptStatus != kCCSuccess) {
        free(buffer);
        return nil;
    }

    NSData *unsealedData = [NSData dataWithBytes:buffer length:usedBuffer];
    free(buffer);

    return unsealedData;
}

- (SecKeyRef)publicKeyRef
{
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)self);
    SecKeyRef key = NULL;
    SecTrustRef trust = NULL;
    SecPolicyRef policy = NULL;

    if (cert != NULL) {
        policy = SecPolicyCreateBasicX509();
        if (policy) {
            if (SecTrustCreateWithCertificates((CFTypeRef)cert, policy, &trust) == noErr) {
                SecTrustResultType result;
                if (SecTrustEvaluate(trust, &result) == noErr) {
                    key = SecTrustCopyPublicKey(trust);
                }
            }
        }
    }
    if (policy) CFRelease(policy);
    if (trust) CFRelease(trust);
    if (cert) CFRelease(cert);
    return key;
}

- (SecKeyRef)privateKeyRefWithPassword:(NSString *)password
{
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];

    SecKeyRef privateKeyRef = NULL;

    [options setObject:password forKey:(__bridge id)kSecImportExportPassphrase];

    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);

    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef)self, (__bridge CFDictionaryRef)options, &items);

    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);

        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }

    CFRelease(items);
    return privateKeyRef;
}

@end
