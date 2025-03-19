#include "PicoRSA.h"

PicoRSA::PicoRSA(uint32_t keyBits) : 
    mKeyBits(keyBits),
    mPrivateKeyBuffer(nullptr),
    mPublicKeyBuffer(nullptr),
    mKeysGenerated(false) {
    
    // Allocate buffers for keys
    mPrivateKeyBuffer = new uint8_t[BR_RSA_KBUF_PRIV_SIZE(mKeyBits)];
    mPublicKeyBuffer = new uint8_t[BR_RSA_KBUF_PUB_SIZE(mKeyBits)];
    
    // Initialize the random number generator
    initRNG();
}

PicoRSA::~PicoRSA() {
    // Free allocated memory
    delete[] mPrivateKeyBuffer;
    delete[] mPublicKeyBuffer;
}

bool PicoRSA::generateKeyPair(uint32_t publicExponent) {
    // Get the default RSA key generation implementation
    br_rsa_keygen keygen = br_rsa_keygen_get_default();
    
    // Create a PRNG wrapper for BearSSL functions
    const br_prng_class **rng_ctx = (const br_prng_class **)&mRng;
    
    // Generate the key pair
    uint32_t ret = keygen(
        rng_ctx, 
        &mPrivKey, mPrivateKeyBuffer, 
        &mPubKey, mPublicKeyBuffer,
        mKeyBits, publicExponent
    );
    
    mKeysGenerated = (ret == 1);
    return mKeysGenerated;
}

size_t PicoRSA::encrypt(const uint8_t* message, size_t messageLen, 
                      uint8_t* output, size_t outputMaxLen) {
    if (!mKeysGenerated) return 0;
    
    // Get the default OAEP encryption implementation
    br_rsa_oaep_encrypt encrypt = br_rsa_oaep_encrypt_get_default();
    
    // Create a PRNG wrapper for BearSSL functions
    const br_prng_class **rng_ctx = (const br_prng_class **)&mRng;
    
    // Encrypt the message using OAEP
    return encrypt(
        rng_ctx,
        &br_sha256_vtable,
        NULL, 0,  // No label
        &mPubKey,
        output, outputMaxLen,
        message, messageLen
    );
}

bool PicoRSA::decrypt(uint8_t* data, size_t* messageLen) {
    if (!mKeysGenerated) return false;
    
    // Get the default OAEP decryption implementation
    br_rsa_oaep_decrypt decrypt = br_rsa_oaep_decrypt_get_default();
    
    // Decrypt the message
    uint32_t result = decrypt(
        &br_sha256_vtable,
        NULL, 0,  // No label
        &mPrivKey,
        data, messageLen
    );
    
    return (result == 1);
}

bool PicoRSA::sign(const uint8_t* hash, size_t hashLen, 
                 uint8_t* signature, size_t saltLen) {
    if (!mKeysGenerated) return false;
    
    // Get the default PSS signature implementation
    br_rsa_pss_sign sign = br_rsa_pss_sign_get_default();
    
    // Create a PRNG wrapper for BearSSL functions
    const br_prng_class **rng_ctx = (const br_prng_class **)&mRng;
    
    // Sign the hash
    uint32_t result = sign(
        rng_ctx,
        &br_sha256_vtable,  // Hash function for data
        &br_sha256_vtable,  // Hash function for MGF1
        hash,               // Message hash
        saltLen,            // Salt length
        &mPrivKey,          // Private key
        signature           // Output signature buffer
    );
    
    return (result == 1);
}

bool PicoRSA::verify(const uint8_t* signature, size_t signatureLen, 
                   const uint8_t* hash, size_t hashLen, size_t saltLen) {
    if (!mKeysGenerated) return false;
    
    // Get the default PSS verification implementation
    br_rsa_pss_vrfy verify = br_rsa_pss_vrfy_get_default();
    
    // Verify the signature
    uint32_t result = verify(
        signature,          // Signature
        signatureLen,       // Signature length
        &br_sha256_vtable,  // Hash function for data
        &br_sha256_vtable,  // Hash function for MGF1
        hash,               // Message hash
        saltLen,            // Salt length
        &mPubKey            // Public key
    );
    
    return (result == 1);
}

bool PicoRSA::signMessage(const uint8_t* message, size_t messageLen, 
                        uint8_t* signature, size_t saltLen) {
    uint8_t hash[32]; // SHA-256 output
    
    // Compute the SHA-256 hash of the message
    br_sha256_context ctx;
    br_sha256_init(&ctx);
    br_sha256_update(&ctx, message, messageLen);
    br_sha256_out(&ctx, hash);
    
    // Sign the hash
    return sign(hash, sizeof(hash), signature, saltLen);
}

bool PicoRSA::verifyMessage(const uint8_t* signature, size_t signatureLen,
                          const uint8_t* message, size_t messageLen, 
                          size_t saltLen) {
    uint8_t hash[32]; // SHA-256 output
    
    // Compute the SHA-256 hash of the message
    br_sha256_context ctx;
    br_sha256_init(&ctx);
    br_sha256_update(&ctx, message, messageLen);
    br_sha256_out(&ctx, hash);
    
    // Verify the signature
    return verify(signature, signatureLen, hash, sizeof(hash), saltLen);
}

size_t PicoRSA::getMaxEncryptLen() const {
    if (!mKeysGenerated) return 0;
    
    // For RSA-OAEP with SHA-256, max message length is:
    // keySize - 2 * hashSize - 2
    return (mKeyBits / 8) - 2 * 32 - 2;
}

size_t PicoRSA::getSignatureLen() const {
    if (!mKeysGenerated) return 0;
    return (mKeyBits + 7) / 8;
}

uint32_t PicoRSA::getKeyBits() const {
    return mKeyBits;
}

bool PicoRSA::hasKeys() const {
    return mKeysGenerated;
}

void PicoRSA::addEntropy(const uint8_t* seed, size_t seedLen) {
    if (seed && seedLen > 0) {
        // Reseed the HMAC-DRBG with additional entropy
        br_hmac_drbg_update(&mRng, seed, seedLen);
    }
}

void PicoRSA::initRNG() {
    uint8_t seed[32];
    
    // Collect entropy from various sources
    collectEntropy(seed, sizeof(seed));
    
    // Initialize the HMAC-DRBG context
    br_hmac_drbg_init(&mRng, &br_sha256_vtable, seed, sizeof(seed));
    
    // Clear the seed from memory for security
    memset(seed, 0, sizeof(seed));
}

void PicoRSA::collectEntropy(uint8_t* buffer, size_t length) {
    // Use a counter to mix values
    uint32_t counter = 0;
    
    for (size_t i = 0; i < length; i++) {
        uint8_t entropy = 0;
        
        // 1. Use analog noise from floating pin
        entropy ^= (uint8_t)(analogRead(A0) & 0xFF);
        
        // 2. Use timer values
        entropy ^= (uint8_t)(micros() & 0xFF);
        
        // 3. Use counter to ensure unique values
        entropy ^= (uint8_t)(counter & 0xFF);
        counter += micros(); // Increment by non-constant amount
        
        // Add small unpredictable delay
        delayMicroseconds((analogRead(A1) % 10) + 1);
        
        // Store result
        buffer[i] = entropy;
    }
}