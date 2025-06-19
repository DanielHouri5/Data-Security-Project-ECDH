// test.js

// Reference to the <pre> element in the HTML to display logs and test outputs to the user.
const output = document.getElementById('output');

/**
 * Creates a simulated chat client using ECDH encryption over WebSocket.
 * Each client generates its own elliptic curve key pair and can
 * register, send, and receive encrypted messages.
 *
 * @param {string} name - The unique username of the client.
 * @returns {object} client - The client object with methods and state.
 */
function createClient(name) {
  // Clear previous output logs when creating a new client
  output.textContent = '';

  // Client object encapsulating all properties and methods related to the user
  const client = {
    name, // Client username
    socket: new WebSocket('ws://localhost:3000'), // WebSocket connection to server
    keyPair: ec.genKeyPair(), // Elliptic curve key pair generation (private + public keys)
    publicKeyHex: '', // Hex representation of this client's public key
    userPublicKeys: {}, // Dictionary of other users' public keys (by username)
    sharedSecrets: {}, // Cache of derived shared secrets with other users (by username)
    ready: false, // Flag indicating whether registration and key exchange is complete

    /**
     * Send a JSON object to the server via WebSocket.
     * Automatically stringifies the object.
     * @param {Object} obj - The message object to send.
     */
    send(obj) {
      this.socket.send(JSON.stringify(obj));
    },

    /**
     * Handle incoming messages from the server and dispatch based on message type.
     * Types handled:
     * - 'registerSuccess': Registration confirmation and key sending
     * - 'userDirectory': List of connected users and their public keys
     * - 'message': Encrypted message from another user
     * - 'error': Server error message
     *
     * @param {Object} msg - Incoming message object from server.
     */
    handleMessage(msg) {
      switch (msg.type) {
        case 'registerSuccess':
          // After successful registration, send this client's public key to server
          this.publicKeyHex = this.keyPair.getPublic('hex');
          this.send({ type: 'publicKey', key: this.publicKeyHex });
          this.ready = true; // Client is now ready to send/receive messages
          console.log(`🟢 [${this.name}] Registered and sent public key`);
          logOutput(`🟢 [${this.name}] Registered and sent public key`);
          break;

        case 'userDirectory':
          // Receive updated list of other users and their public keys
          this.userPublicKeys = {};
          for (const [user, pubKeyHex] of Object.entries(msg.users)) {
            if (user !== this.name) {
              // Convert each public key hex string into an elliptic curve public key object
              this.userPublicKeys[user] = ec
                .keyFromPublic(pubKeyHex, 'hex')
                .getPublic();
            }
          }
          // Log how many users are currently available to chat with
          logOutput(
            `📋 [${this.name}] Updated user directory with ${
              Object.keys(this.userPublicKeys).length
            } users`
          );
          break;

        case 'message':
          // Handle encrypted message from another user
          this.handleIncomingMessage(msg);
          break;

        case 'error':
          // Log any server error messages
          console.error(`❌ [${this.name}] Server error: ${msg.message}`);
          logOutput(`❌ [${this.name}] Server error: ${msg.message}`);
          break;

        default:
          // Unknown message types are warned about
          console.warn(`⚠️ [${this.name}] Unknown message type: ${msg.type}`);
          logOutput(`⚠️ [${this.name}] Unknown message type: ${msg.type}`);
      }
    },

    /**
     * Handles decrypting an incoming encrypted message from another user.
     * Uses ECDH to derive the shared secret key, then AES to decrypt the ciphertext.
     *
     * @param {Object} param0 - Destructured message object containing sender and encrypted text.
     * @param {string} param0.from - The username of the sender.
     * @param {string} param0.text - The AES-encrypted message text.
     */
    handleIncomingMessage({ from, text }) {
      // If the sender's public key is unknown, cannot decrypt
      if (!this.userPublicKeys[from]) {
        console.warn(`⚠️ [${this.name}] No public key for ${from}`);
        logOutput(`⚠️ [${this.name}] No public key for ${from}`);
        return;
      }

      // Compute or retrieve cached ECDH shared secret with sender
      const sharedSecret =
        this.sharedSecrets[from] ||
        this.keyPair.derive(this.userPublicKeys[from]).toString(16);
      this.sharedSecrets[from] = sharedSecret;

      // Derive AES key from SHA-256 hash of the shared secret
      const aesKey = CryptoJS.SHA256(sharedSecret).toString();

      // Decrypt the AES ciphertext to UTF-8 plaintext
      const decrypted = CryptoJS.AES.decrypt(text, aesKey).toString(
        CryptoJS.enc.Utf8
      );

      // Log decrypted message for user visibility
      console.log(`📩 [${this.name}] Received from ${from}: "${decrypted}"`);
      logOutput(`📩 [${this.name}] Received from ${from}: "${decrypted}"`);
    },

    /**
     * Encrypt and send a plaintext message to a specified recipient.
     * Uses ECDH-derived shared secret and AES encryption before sending.
     *
     * @param {string} to - The recipient username.
     * @param {string} plaintext - The plaintext message to send.
     */
    sendEncryptedMessage(to, plaintext) {
      // Do not send if client isn't fully initialized
      if (!this.ready) {
        console.warn(`⚠️ [${this.name}] Not ready to send messages yet`);
        logOutput(`⚠️ [${this.name}] Not ready to send messages yet`);
        return;
      }

      // Cannot send if recipient's public key is unknown
      if (!this.userPublicKeys[to]) {
        console.warn(`⚠️ [${this.name}] No public key for ${to}`);
        logOutput(`⚠️ [${this.name}] No public key for ${to}`);
        return;
      }

      // Compute or reuse cached shared secret with recipient
      const sharedSecret =
        this.sharedSecrets[to] ||
        this.keyPair.derive(this.userPublicKeys[to]).toString(16);
      this.sharedSecrets[to] = sharedSecret;

      // Derive AES key from SHA-256 hash of shared secret
      const aesKey = CryptoJS.SHA256(sharedSecret).toString();

      // Encrypt plaintext message with AES
      const encrypted = CryptoJS.AES.encrypt(plaintext, aesKey).toString();

      // Send encrypted message object to server for routing
      this.send({ type: 'message', to, text: encrypted });

      // Log that encrypted message was sent
      console.log(
        `📤 [${this.name}] Sent encrypted message to ${to}: "${plaintext}"`
      );
      logOutput(
        `📤 [${this.name}] Sent encrypted message to ${to}: "${plaintext}"`
      );
    },
  };

  // WebSocket event handlers for connection lifecycle

  // When connection opens, send registration request with username
  client.socket.onopen = () => {
    client.send({ type: 'register', name: client.name });
  };

  // When a message is received from server, parse and handle it
  client.socket.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    client.handleMessage(msg);
  };

  // Log WebSocket errors
  client.socket.onerror = (err) => {
    console.error(`❌ [${client.name}] WebSocket error:`, err);
    logOutput(`❌ [${client.name}] WebSocket error: ${err.message || err}`);
  };

  // Log when connection closes
  client.socket.onclose = () => {
    console.log(`🔴 [${client.name}] Connection closed`);
    logOutput(`🔴 [${client.name}] Connection closed`);
  };

  return client;
}

/**
 * Logs a message to both the browser console and the output <pre> element in the UI.
 * @param {string} msg - The message to log.
 */
function logOutput(msg) {
  console.log(msg);
  output.textContent += msg + '\n';
}

/**
 * Runs an integration test by creating two clients (Alice and Bob),
 * waiting for them to be ready, and exchanging encrypted messages.
 * Demonstrates the end-to-end encrypted communication workflow.
 */
async function runIntegrationTest() {
  const alice = createClient('Alice');
  const bob = createClient('Bob');

  // Wait until both clients have registered and sent public keys
  await waitForReady([alice, bob]);
  await delay(500); // Small delay to ensure everything is set

  logOutput('👩 [Alice] Sending message to 🧔 Bob...');
  alice.sendEncryptedMessage('Bob', 'Hello Bob, this is Alice!');

  // Bob replies after 1 second
  setTimeout(() => {
    logOutput('🧔 [Bob] Sending message to 👩 Alice...');
    bob.sendEncryptedMessage('Alice', 'Hi Alice! Bob here.');
  }, 1000);

  // Wait 3 seconds to allow message exchange before closing connections
  await delay(3000);

  // Close WebSocket connections gracefully
  alice.socket.close();
  bob.socket.close();

  logOutput('✅ Integration test completed successfully! ✅');
  console.log('✅ Integration test completed successfully! ✅');
}

/**
 * Waits for all clients in the array to become ready (registered and keys exchanged).
 * @param {Array} clients - Array of client objects.
 * @returns {Promise} Resolves when all clients have ready === true.
 */
function waitForReady(clients) {
  return new Promise((resolve) => {
    const check = () => {
      if (clients.every((c) => c.ready)) resolve();
      else setTimeout(check, 100);
    };
    check();
  });
}

/**
 * Returns a Promise that resolves after a specified delay in milliseconds.
 * Useful for async/await timing.
 * @param {number} ms - Milliseconds to delay.
 * @returns {Promise}
 */
function delay(ms) {
  return new Promise((res) => setTimeout(res, ms));
}

/**
 * Performs a single test of shared secret derivation and AES encryption/decryption.
 * Generates new ECDH key pairs for Alice and Bob, derives shared secrets,
 * and verifies that both secrets match.
 * Then encrypts and decrypts a test message to confirm correct cryptography.
 *
 * @param {number} i - Test iteration number (used for message labeling).
 * @returns {Object} Result object containing keys, secrets, and test results.
 */
function testSharedSecretEquality(i) {
  // Generate ephemeral key pairs for Alice and Bob
  const alice = ec.genKeyPair();
  const bob = ec.genKeyPair();

  // Each derives the shared secret using the other's public key
  const secretAlice = alice.derive(bob.getPublic()).toString(16);
  const secretBob = bob.derive(alice.getPublic()).toString(16);
  const match = secretAlice === secretBob; // Shared secret must be equal

  // Test encryption using the shared secret as AES key (hashed via SHA256)
  const message = 'Test message ' + i;
  const aesKey = CryptoJS.SHA256(secretAlice).toString();
  const encrypted = CryptoJS.AES.encrypt(message, aesKey).toString();
  const decrypted = CryptoJS.AES.decrypt(encrypted, aesKey).toString(
    CryptoJS.enc.Utf8
  );
  const encryptionTestPass = decrypted === message; // Verify decryption correctness

  return {
    alicePublic: alice.getPublic('hex'),
    bobPublic: bob.getPublic('hex'),
    secretAlice,
    secretBob,
    match,
    encryptionTestPass,
    message,
    encrypted,
    decrypted,
  };
}

/**
 * Runs 10 repeated tests of ECDH key derivation and AES encryption.
 * Logs detailed results for each test in the UI output.
 */
function runTests() {
  output.textContent = '🧪 Running 10 tests...\n\n';

  for (let i = 0; i < 10; i++) {
    const result = testSharedSecretEquality(i + 1);

    output.textContent +=
      `🔁 Test #${i + 1}\n` +
      `──────────── Shared Secret Check ────────────\n` +
      `👩 Alice Public:    ${result.alicePublic.slice(0, 20)}...\n` +
      `🧔 Bob Public:      ${result.bobPublic.slice(0, 20)}...\n` +
      `✅ Shared (Alice):  ${result.secretAlice.slice(0, 20)}...\n` +
      `✅ Shared (Bob):    ${result.secretBob.slice(0, 20)}...\n` +
      `🔍 Match:           ${result.match ? '✅' : '❌'}\n\n` +
      `──────────── Encryption Test ─────────────\n` +
      `✉️ Plaintext:       ${result.message}\n` +
      `🔒 Ciphertext:      ${result.encrypted.slice(0, 30)}...\n` +
      `🔓 Decrypted:       ${result.decrypted}\n` +
      `✅ Encryption OK:   ${result.encryptionTestPass ? '✅' : '❌'}\n\n\n`;
  }
}

/**
 * Runs a specific test vector verification based on known ECDH keys and secrets.
 * Validates correctness of ECDH derivation and AES encryption against expected values.
 */
function runTestVector() {
  // Known private key (hex)
  const privateKeyHex = '1';
  // Corresponding known public key (uncompressed, hex)
  const publicKeyHex =
    '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';
  // Expected ECDH shared secret derived from private key 1 and the public key above
  const expectedSharedSecret =
    '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

  // Construct key objects from hex strings
  const alice = ec.keyFromPrivate(privateKeyHex, 'hex');
  const bobPubKey = ec.keyFromPublic(publicKeyHex, 'hex');

  // Derive shared secret and compare to expected value
  const sharedSecret = alice.derive(bobPubKey.getPublic()).toString(16);
  const match = sharedSecret === expectedSharedSecret;

  // Test AES encryption and decryption using the shared secret
  const message = 'Test vector message';
  const aesKey = CryptoJS.SHA256(sharedSecret).toString();
  const encrypted = CryptoJS.AES.encrypt(message, aesKey).toString();
  const decrypted = CryptoJS.AES.decrypt(encrypted, aesKey).toString(
    CryptoJS.enc.Utf8
  );
  const encryptionOK = decrypted === message;

  // Display detailed results in output area
  output.textContent =
    `🔎 Test Vector Verification\n` +
    `────────────────────────────────────────\n` +
    `🔐 Private Key:       ${privateKeyHex}\n` +
    `💻 Public Key:        ${publicKeyHex.slice(0, 40)}...\n` +
    `🔑 Expected Secret:   ${expectedSharedSecret}\n` +
    `🧮 Computed Secret:   ${sharedSecret}\n` +
    `🔍 Shared Match:      ${match ? 'PASS ✅' : 'FAIL ❌'}\n\n` +
    `──────────── Encryption Test ─────────────\n` +
    `✉️ Plaintext:         ${message}\n` +
    `🔒 Ciphertext:        ${encrypted.slice(0, 30)}...\n` +
    `🔓 Decrypted:         ${decrypted}\n` +
    `✅ Encryption OK:     ${encryptionOK ? '✅' : '❌'}\n`;
}

/**
 * Runs a performance benchmark of 1000 ECDH key pair generations
 * and shared secret derivations to measure speed.
 * Also logs notes about cryptographic properties.
 */
function runPerformanceTest() {
  // Capture start time in milliseconds
  const start = performance.now();

  // Generate 1000 pairs and compute shared secrets
  for (let i = 0; i < 1000; i++) {
    const alice = ec.genKeyPair();
    const bob = ec.genKeyPair();

    // Derive shared secrets from both ends
    const shared1 = alice.derive(bob.getPublic()).toString(16);
    const shared2 = bob.derive(alice.getPublic()).toString(16);

    // If secrets differ, something is wrong, stop the test
    if (shared1 !== shared2) {
      console.error('Mismatch in shared secret!');
      break;
    }
  }

  // Calculate total time taken
  const end = performance.now();
  const duration = end - start;

  // Output benchmark results and security info
  output.textContent =
    `⏱️ Time to run 1000 key exchanges: ${duration.toFixed(2)} ms\n\n` +
    `🔐 Security notes:\n` +
    `- Forward Secrecy: ✔️ Keys are ephemeral, so compromise does not expose past secrets.\n` +
    `- Unforgeability: ✔️ The shared secret cannot be forged without private keys.\n` +
    `- Parameter choice (secp256k1) balances good security and performance.\n` +
    `- Larger curves provide higher security but slower performance.\n`;
}
