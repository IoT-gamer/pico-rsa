#include <Arduino.h>
#include <PicoRSA.h>

// Forward declaration of utility function
void printHex(const uint8_t* data, size_t len);

// Buffer for message encryption/decryption
uint8_t encryptedBuffer[128];  // Buffer size should be at least the key size in bytes

void setup() {
  // Initialize serial communication
  Serial.begin(115200);
  while (!Serial) delay(10); // Wait for serial to open
  
  delay(2000); // Wait for serial connection to stabilize

  Serial.println("PicoRSA Encryption/Decryption Example");
  Serial.println("=====================================");

  // Create PicoRSA with 1024-bit keys
  PicoRSA rsa(1024);
  
  // Generate RSA key pair
  Serial.println("Generating RSA key pair...");
  if (!rsa.generateKeyPair()) {
    Serial.println("Key generation failed!");
    while (1); // Stop execution
  }
  Serial.println("RSA key pair generated successfully!");
  
  // Display key information
  Serial.print("Key Size: ");
  Serial.print(rsa.getKeyBits());
  Serial.println(" bits");
  
  Serial.print("Maximum Encrytable Message Length: ");
  Serial.print(rsa.getMaxEncryptLen());
  Serial.println(" bytes");
  
  // Message to encrypt
  const char* message = "This is a secret message that will be encrypted with RSA-OAEP.";
  Serial.print("Original Message: ");
  Serial.println(message);
  
  // Encrypt the message
  Serial.println("Encrypting message...");
  size_t encLen = rsa.encrypt((const uint8_t*)message, strlen(message), 
                             encryptedBuffer, sizeof(encryptedBuffer));
  
  if (encLen == 0) {
    Serial.println("Encryption failed!");
    while (1);
  }
  
  Serial.print("Encrypted data (");
  Serial.print(encLen);
  Serial.println(" bytes):");
  printHex(encryptedBuffer, encLen);
  
  // Create a buffer for the decrypted message
  uint8_t decryptedBuffer[128];
  memcpy(decryptedBuffer, encryptedBuffer, encLen);
  size_t messageLen = encLen;
  
  // Decrypt the message
  Serial.println("Decrypting message...");
  if (!rsa.decrypt(decryptedBuffer, &messageLen)) {
    Serial.println("Decryption failed!");
    while (1);
  }
  
  // Null-terminate the decrypted message
  decryptedBuffer[messageLen] = 0;
  
  Serial.print("Decrypted message: ");
  Serial.println((char*)decryptedBuffer);

  Serial.println("Example completed!");
}

void loop() {
  // Nothing to do in the loop
  delay(1000);
}

// Utility function to print bytes in hexadecimal format
void printHex(const uint8_t* data, size_t len) {
  // Print first 32 bytes (or less if data is shorter)
  size_t printLen = (len > 32) ? 32 : len;
  
  for (size_t i = 0; i < printLen; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
    if ((i + 1) % 16 == 0) Serial.println();
    else Serial.print(" ");
  }
  
  if (len > 32) {
    Serial.println("...(truncated)");
  } else if (printLen % 16 != 0) {
    Serial.println();
  }
}