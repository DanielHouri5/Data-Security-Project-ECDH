// Initialize elliptic curve with secp256k1
const ec = new elliptic.ec('secp256k1');

// Connect to WebSocket server
const socket = new WebSocket('ws://localhost:3000');

// Global variables to store user data and crypto info
let keyPair = null; // Our private/public key pair
let username = ''; // Our chosen username
let publicKeyHex = ''; // Our public key in hex format
let sharedSecrets = {}; // Map: recipient username -> shared secret
let userPublicKeys = {}; // Map: username -> their public key object

// DOM element references
const loginSection = document.getElementById('login-section');
const mainContainer = document.getElementById('main-container');
const chatSection = document.getElementById('chat-section');
const userSelect = document.getElementById('recipient');
const chatLog = document.getElementById('chatLog');
const messageInput = document.getElementById('messageInput');

/**
 * Generates a new elliptic curve key pair using the secp256k1 curve.
 * The key pair contains a private key and the corresponding public key.
 * @returns {Object} - The generated key pair object.
 */
function generateKey() {
  // Use the elliptic library's ec instance to generate a new random key pair
  return ec.genKeyPair();
}

/**
 * Computes the shared secret between two key pairs using ECDH.
 * Given our private key and the other party's public key,
 * derives the shared secret point and returns it as a hex string.
 * @param {Object} myKey - Our key pair (with private key).
 * @param {Object} otherKey - The other party's public key object.
 * @returns {string} - The shared secret as a hexadecimal string.
 */
function computeSharedSecret(myKey, otherKey) {
  // Derive the shared secret by multiplying our private key with the other party's public key point
  // Returns a big number (BN), convert it to hex string for use as a key
  return myKey.derive(otherKey).toString(16);
}

// ===== User Login =====
function login() {
  const input = document.getElementById('username');
  username = input.value.trim();
  if (!username) {
    alert('Please enter your name');
    return;
  }

  keyPair = generateKey();
  publicKeyHex = keyPair.getPublic('hex');

  // Send registration message to the server
  socket.send(
    JSON.stringify({
      type: 'register',
      name: username,
    })
  );
}

// ===== Send Encrypted Message =====
function sendEncryptedMessage() {
  const to = userSelect.value;
  const message = messageInput.value.trim();
  if (!to || !message) {
    alert('Please select recipient and type a message');
    return;
  }

  const pubKey = userPublicKeys[to];
  if (!pubKey) {
    alert(`No public key for ${to}`);
    return;
  }

  // Derive shared secret using recipient's public key
  const sharedSecret = sharedSecrets[to] || keyPair.derive(pubKey).toString(16);
  sharedSecrets[to] = sharedSecret;

  // Use SHA256 of shared secret as AES key
  const aesKey = CryptoJS.SHA256(sharedSecret).toString();
  const encrypted = CryptoJS.AES.encrypt(message, aesKey).toString();

  // Send encrypted message via WebSocket
  socket.send(
    JSON.stringify({
      type: 'message',
      to,
      text: encrypted,
    })
  );

  appendMessage(`You to ${to}: ${message}`, 'outgoing');
  messageInput.value = '';
}

// ===== Handle Received Encrypted Message =====
function handleIncomingMessage({ from, text }) {
  const pubKey = userPublicKeys[from];
  if (!pubKey) {
    console.warn(`No public key for ${from}`);
    return;
  }

  // Derive shared secret with sender
  const sharedSecret =
    sharedSecrets[from] || keyPair.derive(pubKey).toString(16);
  sharedSecrets[from] = sharedSecret;

  // Decrypt message using derived key
  const aesKey = CryptoJS.SHA256(sharedSecret).toString();
  const decrypted = CryptoJS.AES.decrypt(text, aesKey).toString(
    CryptoJS.enc.Utf8
  );

  appendMessage(`${from} (decrypted): ${decrypted}`, 'incoming');
}

// ===== Display message in chat window =====
function appendMessage(text, type) {
  const msg = document.createElement('div');
  msg.className = `message ${type}`;
  msg.textContent = text;
  chatLog.appendChild(msg);
  chatLog.scrollTop = chatLog.scrollHeight;
}

// ===== Handle messages from WebSocket server =====
socket.addEventListener('message', (event) => {
  const data = JSON.parse(event.data);

  switch (data.type) {
    case 'userDirectory':
      userPublicKeys = {};
      userSelect.innerHTML =
        '<option value="" disabled selected>Choose user to message</option>';

      for (const [name, pubKeyHex] of Object.entries(data.users)) {
        if (name === username) continue;

        const pub = ec.keyFromPublic(pubKeyHex, 'hex').getPublic();
        userPublicKeys[name] = pub;

        // Compute and store shared secret
        const sharedSecret = computeSharedSecret(keyPair, pub);
        sharedSecrets[name] = sharedSecret;

        const opt = document.createElement('option');
        opt.value = name;
        opt.textContent = `${name} (Secret: ${sharedSecret}...)`;
        userSelect.appendChild(opt);
      }
      break;

    case 'message':
      handleIncomingMessage(data); // Decrypt and show incoming message
      break;

    case 'registerSuccess':
      // Send our public key to the server
      socket.send(
        JSON.stringify({
          type: 'publicKey',
          key: publicKeyHex,
        })
      );

      // Show chat UI and update header
      loginSection.style.display = 'none';
      mainContainer.style.display = 'flex';
      chatSection.style.display = 'flex';
      document.getElementById(
        'current-user'
      ).textContent = `Logged in as: ${username}`;
      document.getElementById(
        'public-key-display'
      ).textContent = `Your Public Key: ${publicKeyHex}`;
      break;

    case 'error':
      alert(data.message);
      document.getElementById('username').value = '';
      break;

    default:
      console.warn('Unknown message type:', data.type);
  }
});
