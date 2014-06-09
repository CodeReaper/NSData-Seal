//
//  NSData+Seal.h
//  ExampleApp
//
//  Created by Jakob Jensen on 09/06/14.
//
//

#import <Foundation/Foundation.h>

@interface NSData (Seal)

- (NSData *)sealWithPublicKey:(SecKeyRef)publicKey;
- (NSData *)openWithPrivateKey:(SecKeyRef)privateKey;

- (SecKeyRef)publicKeyRef;
- (SecKeyRef)privateKeyRefWithPassword:(NSString *)password;

@end
