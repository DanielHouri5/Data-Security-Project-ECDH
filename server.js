// ===== server.js =====
const express = require('express');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Maps to track connected users and their public keys
const clients = new Map(); // username => WebSocket
const userPublicKeys = new Map(); // username => publicKey

// Handle new WebSocket connections
wss.on('connection', function connection(ws) {
  let username = null;

  // Handle incoming messages from clients
  ws.on('message', function incoming(message) {
    try {
      const data = JSON.parse(message);

      switch (data.type) {
        case 'register':
          // Handle new user registration
          if (clients.has(data.name)) {
            // If username is taken, send error message
            ws.send(
              JSON.stringify({
                type: 'error',
                message: 'Username already taken',
              })
            );
            return;
          }

          // Save the username and associate it with the WebSocket connection
          username = data.name;
          clients.set(username, ws);
          console.log(`${username} connected`);

          // Notify client that registration was successful
          ws.send(JSON.stringify({ type: 'registerSuccess' }));

          break;

        case 'publicKey':
          // Receive and store the user's public key
          if (!username) {
            console.warn('Received publicKey before register');
            return;
          }

          userPublicKeys.set(username, data.key);

          // Broadcast updated list of users and public keys to all clients
          broadcastUserDirectory();
          break;

        case 'message':
          // Handle encrypted message sent from one user to another
          const targetWs = clients.get(data.to);
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            // Forward the encrypted message to the intended recipient
            targetWs.send(
              JSON.stringify({
                type: 'message',
                from: username,
                text: data.text,
              })
            );
          }
          break;

        default:
          console.warn('Unknown message type:', data.type);
      }
    } catch (err) {
      console.error('Invalid JSON:', err);
    }
  });

  // Handle client disconnect
  ws.on('close', () => {
    if (username) {
      // Remove user and their public key from memory
      clients.delete(username);
      userPublicKeys.delete(username);
      console.log(`${username} disconnected`);

      // Notify all remaining clients about the updated user list
      broadcastUserDirectory();
    }
  });
});

// Broadcast updated user directory to all connected clients
function broadcastUserDirectory() {
  const directory = Object.fromEntries(userPublicKeys); // { username: publicKey, ... }

  const msg = JSON.stringify({
    type: 'userDirectory',
    users: directory,
  });

  clients.forEach((clientWs) => {
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(msg);
    }
  });
}

// Serve static files from the 'public' folder
app.use(express.static('public'));

// Start HTTP + WebSocket server on port 3000
server.listen(3000, () =>
  console.log('Server running at http://localhost:3000')
);
