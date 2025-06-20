// test.js

// Reference to the <pre> element in the HTML to display logs and test outputs to the user.
const output = document.getElementById('output');

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
  const alice = generateKey();
  const bob = generateKey();

  // Each derives the shared secret using the other's public key
  const secretAlice = computeSharedSecret(alice, bob.getPublic());
  const secretBob = computeSharedSecret(bob, alice.getPublic());
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
function runECDHTests() {
  output.textContent = '🧪 Running 10 tests...\n\n';

  for (let i = 0; i < 10; i++) {
    const result = testSharedSecretEquality(i + 1);

    const logText =
      `🔁 Test #${i + 1}\n` +
      `──────────── Shared Secret Check ────────────\n` +
      `👩 Alice Public:    ${result.alicePublic}\n` +
      `🧔 Bob Public:      ${result.bobPublic}\n` +
      `✅ Shared (Alice):  ${result.secretAlice}\n` +
      `✅ Shared (Bob):    ${result.secretBob}\n` +
      `🔍 Match:           ${result.match ? '✅' : '❌'}\n\n` +
      `──────────── Encryption Test ─────────────\n` +
      `✉️ Plaintext:       ${result.message}\n` +
      `🔒 Ciphertext:      ${result.encrypted}\n` +
      `🔓 Decrypted:       ${result.decrypted}\n` +
      `✅ Encryption OK:   ${result.encryptionTestPass ? '✅' : '❌'}\n\n\n`;

    console.log(logText);
    output.textContent += logText;
  }
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
    const alice = generateKey();
    const bob = generateKey();

    // Derive shared secrets from both ends
    const shared1 = computeSharedSecret(alice, bob.getPublic()).toString(16);
    const shared2 = computeSharedSecret(bob, alice.getPublic()).toString(16);

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
  const logText =
    `⏱️ Time to run 1000 key exchanges: ${duration.toFixed(2)} ms\n\n` +
    `🔐 Security notes:\n` +
    `- Forward Secrecy: ✔️ Keys are ephemeral, so compromise does not expose past secrets.\n` +
    `- Unforgeability: ✔️ The shared secret cannot be forged without private keys.\n` +
    `- Parameter choice (secp256k1) balances good security and performance.\n` +
    `- Larger curves provide higher security but slower performance.\n`;

  console.log(logText);
  output.textContent = logText;
}
