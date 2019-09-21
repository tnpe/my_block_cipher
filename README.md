# My Block Cipher

CSE 539 Project 1

## Dependency

OpenSSL Library

`sudo apt-get update`

`sudo apt-get install openssl libssl-dev`

## Usage

`./block_cipher parameter1 parameter2 parameter3 parameter4`

Parameter1: 0 for encryption, 1 for decryption;

Parameter2: key;

Parameter3: input file name;

Parameter4: output file name.

## Settings

C Standard: C99

Block Size: 32 bits (required by the instructor for this project)

Effective Key Size: 32 bits (required by the instructor for this project)

Mode of Operation: ECB (required by the instructor for this project)
