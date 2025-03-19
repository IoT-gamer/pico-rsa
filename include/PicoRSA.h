/**
 * PicoRSA - RSA encryption library for Raspberry Pi Pico W
 * 
 * This library provides easy-to-use RSA encryption, decryption, 
 * signing and verification capabilities for Raspberry Pi Pico W
 * and other Arduino-compatible boards that include BearSSL.
 * 
 * Based on the BearSSL cryptographic library that comes with
 * the Arduino-Pico core.
 */

 #ifndef PICO_RSA_H
 #define PICO_RSA_H
 
 #include <Arduino.h>
 #include "bearssl/bearssl.h"
 
 class PicoRSA {
 public:
     /**
      * Constructor for PicoRSA
      * 
      * @param keyBits The size of the RSA key in bits (default: 1024)
      *                Note: 2048 bits is more secure but very slow to generate
      *                on Pico W. 1024 bits is a reasonable compromise for
      *                many applications.
      */
     PicoRSA(uint32_t keyBits = 1024);
     
     /**
      * Destructor 
      */
     ~PicoRSA();
     
     /**
      * Generate a new RSA key pair
      * 
      * @param publicExponent The public exponent to use (default: 65537)
      * @return true if key generation was successful, false otherwise
      */
     bool generateKeyPair(uint32_t publicExponent = 65537);
     
     /**
      * Encrypt a message using RSA-OAEP with SHA-256
      * 
      * @param message Pointer to the message to encrypt
      * @param messageLen Length of the message in bytes
      * @param output Buffer to store the encrypted message
      * @param outputMaxLen Maximum length of the output buffer
      * @return The length of the encrypted message, or 0 on failure
      */
     size_t encrypt(const uint8_t* message, size_t messageLen, 
                   uint8_t* output, size_t outputMaxLen);
     
     /**
      * Decrypt a message using RSA-OAEP with SHA-256
      * 
      * @param data Buffer containing the encrypted message (will be modified)
      * @param messageLen Pointer to variable containing encrypted length,
      *                   will be updated with decrypted length
      * @return true if decryption was successful, false otherwise
      */
     bool decrypt(uint8_t* data, size_t* messageLen);
     
     /**
      * Sign a message hash using RSA-PSS
      * 
      * @param hash The hash of the message to sign
      * @param hashLen Length of the hash in bytes
      * @param signature Buffer to store the signature
      * @param saltLen Length of the salt to use (default: 20 bytes)
      * @return true if signing was successful, false otherwise
      */
     bool sign(const uint8_t* hash, size_t hashLen, 
              uint8_t* signature, size_t saltLen = 20);
     
     /**
      * Verify a signature using RSA-PSS
      * 
      * @param signature The signature to verify
      * @param signatureLen Length of the signature in bytes
      * @param hash The hash of the message
      * @param hashLen Length of the hash in bytes
      * @param saltLen Length of the salt used (default: 20 bytes)
      * @return true if the signature is valid, false otherwise
      */
     bool verify(const uint8_t* signature, size_t signatureLen, 
                const uint8_t* hash, size_t hashLen, size_t saltLen = 20);
     
     /**
      * Sign a message directly (hash computed internally using SHA-256)
      * 
      * @param message The message to sign
      * @param messageLen Length of the message in bytes
      * @param signature Buffer to store the signature
      * @param saltLen Length of the salt to use (default: 20 bytes)
      * @return true if signing was successful, false otherwise
      */
     bool signMessage(const uint8_t* message, size_t messageLen, 
                     uint8_t* signature, size_t saltLen = 20);
     
     /**
      * Verify a message signature directly (hash computed internally using SHA-256)
      * 
      * @param signature The signature to verify
      * @param signatureLen Length of the signature in bytes
      * @param message The message that was signed
      * @param messageLen Length of the message in bytes
      * @param saltLen Length of the salt used (default: 20 bytes)
      * @return true if the signature is valid, false otherwise
      */
     bool verifyMessage(const uint8_t* signature, size_t signatureLen,
                       const uint8_t* message, size_t messageLen, 
                       size_t saltLen = 20);
     
     /**
      * Get the maximum message length that can be encrypted with current key
      * 
      * @return The maximum length in bytes, or 0 if no key has been generated
      */
     size_t getMaxEncryptLen() const;
     
     /**
      * Get the signature length (equals modulus length)
      * 
      * @return The signature length in bytes, or 0 if no key has been generated
      */
     size_t getSignatureLen() const;
     
     /**
      * Get the RSA key size in bits
      * 
      * @return The key size in bits
      */
     uint32_t getKeyBits() const;
     
     /**
      * Check if RSA keys have been generated
      * 
      * @return true if keys are available, false otherwise
      */
     bool hasKeys() const;
     
     /**
      * Add entropy to the random number generator
      * 
      * @param seed Pointer to additional entropy data
      * @param seedLen Length of entropy data in bytes
      */
     void addEntropy(const uint8_t* seed, size_t seedLen);
 
 private:
     // Initialize the random number generator
     void initRNG();
     
     // Collect entropy from various sources
     void collectEntropy(uint8_t* buffer, size_t length);
 
     uint32_t mKeyBits;
     uint8_t* mPrivateKeyBuffer;
     uint8_t* mPublicKeyBuffer;
     br_rsa_private_key mPrivKey;
     br_rsa_public_key mPubKey;
     br_hmac_drbg_context mRng;
     bool mKeysGenerated;
 };
 
 #endif // PICO_RSA_H