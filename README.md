# ECDH Network Chat

## Project Overview

This project implements a secure network chat using Elliptic Curve Diffie-Hellman (ECDH) key exchange for encrypted messaging. It demonstrates key generation, shared secret derivation, AES encryption/decryption, and real-time messaging over WebSockets.

---

## Setup and Running

### 1. Prepare the Server

- Open your terminal and **navigate to the project folder** containing all the project files (`server.js`, `client.js`, `test.js`, etc.).  
  For example, if your files are in a folder named `ECDHChat`, run:

  cd path/to/ECDHChat

- Install all necessary dependencies by running:

  npm install

- Once dependencies are installed, start the server with:

  node server.js

- The WebSocket server will listen by default on:
  `ws://localhost:3000`

### 2. Open the Client

- Click the http://localhost:3000 link displayed in your terminal to open the chat application in your default web browser.
- Open as many browser tabs or windows as the number of users you want to simulate.
- Enter your username and join the chat.
- Use the test buttons to run ECDH key exchange tests, encryption tests and performance benchmarks.

---

## Features

- Real-time encrypted chat with multiple users using ECDH-derived AES keys.
- User directory management and public key exchange via WebSocket server.
- Test suite demonstrating shared secret equality, encryption correctness, and performance.
- Clear console and on-page output logs with informative emojis for better readability.

---

## Technical Details

- Cryptography is based on the `secp256k1` elliptic curve using the `elliptic` JavaScript library.
- AES encryption/decryption is implemented with the `crypto-js` library using SHA-256 hashed shared secrets as keys.
- Communication is handled via a WebSocket server (`ws` library recommended for the server).
- Client-side code is plain JavaScript with no additional framework requirements.

---

## Prerequisites

- Node.js installed (v14 or later recommended).
- A modern web browser with JavaScript enabled.

---

## Notes

- Make sure the server is running before opening the client, otherwise the client will not be able to connect.

---
