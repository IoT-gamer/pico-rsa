# PicoRSA Library for Raspberry Pi Pico

A lightweight RSA encryption, decryption, and digital signature library for Raspberry Pi Pico W using the Arduino-Pico core which includes BearSSL.

## Features

- **RSA Key Generation** - Generate RSA key pairs directly on your microcontroller
- **RSA Encryption/Decryption** - Secure messages using RSA-OAEP with SHA-256
- **Digital Signatures** - Sign and verify messages using RSA-PSS
- **Simple API** - Easy-to-use functions with clear documentation
- **Low Resource Usage** - Optimized for microcontrollers with limited resources

## Installation

### PlatformIO

Edit your project's `platformio.ini`:

```ini
[env:rpipicow]
platform = https://github.com/maxgerhardt/platform-raspberrypi.git
board = rpipicow
framework = arduino
board_build.core = earlephilhower
board_build.filesystem_size = 0.5m
lib_deps =
    pico-rsa

; Or if you want to use the latest version from GitHub
; lib_deps =
;    https://github.com/IoT-gamer/pico-rsa
```

### Arduino IDE

1. Create a folder named BLENotify in your Arduino libraries folder
2. Copy the `picoRSA.h` and `picoRSA.cpp` files into this folder
3. Restart the Arduino IDE

## Hardware Compatibility

This library has been tested with:
- Raspberry Pi Pico W with Arduino-Pico core

It should work with any board that:
- Supports the Arduino-Pico core (which includes BearSSL)
- Has sufficient RAM for RSA operations

## Key Size Recommendations

- **512 bits**: Not recommended for security, but useful for testing
- **1024 bits**: Good compromise between security and performance on Pico W
- **2048 bits**: Good security, but key generation is very slow on Pico W

## Examples

The library includes the following examples:

- **SimpleEncryptDecrypt**: Basic example of RSA encryption and decryption
- **SignAndVerify** - Shows how to create and verify digital signatures

## API Reference

### Constructor

```cpp
PicoRSA(uint32_t keyBits = 1024);
```

Creates a new PicoRSA instance with the specified key size in bits.

### Key Generation

```cpp
bool generateKeyPair(uint32_t publicExponent = 65537);
```

Generates a new RSA key pair with the specified public exponent.

### Encryption/Decryption

```cpp
size_t encrypt(const uint8_t* message, size_t messageLen, 
               uint8_t* output, size_t outputMaxLen);
```

Encrypts a message using RSA-OAEP with SHA-256. Returns the length of the encrypted data.

```cpp
bool decrypt(uint8_t* data, size_t* messageLen);
```

Decrypts a message that was encrypted with RSA-OAEP. Updates `messageLen` with the length of the decrypted data.

### Digital Signatures

```cpp
bool signMessage(const uint8_t* message, size_t messageLen, 
                uint8_t* signature, size_t saltLen = 20);
```

Signs a message using RSA-PSS with SHA-256.

```cpp
bool verifyMessage(const uint8_t* signature, size_t signatureLen,
                  const uint8_t* message, size_t messageLen, 
                  size_t saltLen = 20);
```

Verifies a message signature created with RSA-PSS.

### Utility Functions

```cpp
size_t getMaxEncryptLen() const;
```

Returns the maximum message length that can be encrypted with the current key size.

```cpp
size_t getSignatureLen() const;
```

Returns the length of signatures produced by this key.

```cpp
uint32_t getKeyBits() const;
```

Returns the key size in bits.

```cpp
bool hasKeys() const;
```

Returns true if keys have been generated.

```cpp
void addEntropy(const uint8_t* seed, size_t seedLen);
```

Adds additional entropy to the random number generator.

## Security Considerations

- **Key Generation:** RSA key generation requires good entropy. The library collects entropy from analog inputs, but consider adding additional entropy sources for critical applications.
- **Key Size:** 1024-bit RSA is a good compromise for Pico W.
- **Storage:** This library does not handle persistent storage of keys. For production use, implement secure key storage.

## Entropy Guide

For critical applications, consider improving the entropy for key generation:

```cpp
// Create additional entropy from various sources
uint8_t extraEntropy[32];

// Use floating analog pins
for (int i = 0; i < 8; i++) {
  extraEntropy[i] = analogRead(A0 + i) & 0xFF;
}

// Use WiFi if available (Pico W)
#ifdef ARDUINO_ARCH_RP2040
  #include <WiFi.h>
  if (WiFi.status() == WL_CONNECTED) {
    extraEntropy[8] = WiFi.RSSI() & 0xFF;
  }
#endif

// Add the entropy before generating keys
PicoRSA rsa(1024);
rsa.addEntropy(extraEntropy, sizeof(extraEntropy));
rsa.generateKeyPair();
```

## License

This library is released under the MIT License. See LICENSE for details.

## Acknowledgments

- Based on [BearSSL](https://bearssl.org/) by Thomas Pornin
- Developed using [Arduino-Pico core](https://github.com/earlephilhower/arduino-pico) by Earle F. Philhower, III