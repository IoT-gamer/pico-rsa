# PicoRSA Examples

This directory contains example projects demonstrating how to use the PicoRSA library.

## Examples
1. **SimpleEncryptDecrypt** - Basic example of RSA encryption and decryption
2. **SignAndVerify** - Shows how to create and verify digital signatures

## Running the Examples As PlatformIO Projects

Each example directory includes a `platformio.ini` file so they can be run as standalone PlatformIO projects.

To run an example:

1. Open the example directory in PlatformIO
2. Connect your Raspberry Pi Pico W
3. Click the "Upload" button (or run `platformio run -t upload`)
4. Open the serial monitor with `platformio device monitor`

## Notes
- Key generation is slow on the Pico, so it may take a few seconds to generate keys
- Key size is 1024 bits by default, but can be changed in the example code