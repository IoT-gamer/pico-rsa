#include <Arduino.h>
#include <PicoRSA.h>  // PicoRSA handles the BearSSL include internally

// Forward declaration of utility function
void printHex(const uint8_t* data, size_t len);

// Buffer for the signature
uint8_t signatureBuffer[128];  // Buffer size should be at least the key size in bytes

void setup() {
  // Initialize serial communication
  Serial.begin(115200);
  while (!Serial) delay(10); // Wait for serial to open
  delay(3000); // Wait for serial connection to stabilize

  Serial.println("PicoRSA Signing and Verification Example");
  Serial.println("========================================");

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
  
  Serial.print("Signature Length: ");
  Serial.print(rsa.getSignatureLen());
  Serial.println(" bytes");
  
  // Message to sign
  const char* message = "This message will be digitally signed to ensure authenticity.";
  Serial.print("Message to sign: ");
  Serial.println(message);
  
  // Sign the message
  Serial.println("Signing message...");
  if (!rsa.signMessage((const uint8_t*)message, strlen(message), signatureBuffer)) {
    Serial.println("Signing failed!");
    while (1);
  }
  
  Serial.print("Signature (");
  Serial.print(rsa.getSignatureLen());
  Serial.println(" bytes):");
  printHex(signatureBuffer, rsa.getSignatureLen());
  
  // Verify the signature
  Serial.println("Verifying signature with original message...");
  bool result = rsa.verifyMessage(
    signatureBuffer, rsa.getSignatureLen(),
    (const uint8_t*)message, strlen(message)
  );
  
  if (result) {
    Serial.println("✓ Signature verified successfully!");
  } else {
    Serial.println("✗ Signature verification failed!");
  }
  
  // Try with a tampered message
  const char* tamperedMessage = "This message has been altered after signing!";
  Serial.print("\nTampered message: ");
  Serial.println(tamperedMessage);
  
  // Verify the original signature against the tampered message
  Serial.println("Verifying original signature against tampered message...");
  result = rsa.verifyMessage(
    signatureBuffer, rsa.getSignatureLen(),
    (const uint8_t*)tamperedMessage, strlen(tamperedMessage)
  );
  
  if (result) {
    Serial.println("✗ ERROR: Signature verified (should have failed)!");
  } else {
    Serial.println("✓ GOOD: Signature verification failed as expected!");
  }

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