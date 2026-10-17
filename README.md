# PrivateConnect Web

A starter web app for a host-moderated room chat. It uses Node.js, Express, Socket.IO, and browser Web Crypto.

## Features
- Host creates a room with a short room code
- Optional room access passcode
- Visitors request to join; host approves or rejects
- Host can remove approved members
- Encrypted text messages and small image attachments (AES-GCM in the browser)
- Server relays encrypted message payloads without decrypting them
- Responsive mobile-friendly interface

## Run locally
1. Install Node.js 18 or later.
2. Extract this ZIP and open a terminal in the `PrivateConnect_Web` folder.
3. Run `npm install`.
4. Run `npm start`.
5. On the host computer open `http://localhost:3000`.
6. To use another device on the same Wi-Fi, open `http://YOUR-COMPUTER-LAN-IP:3000` on that device. Find the computer's local IP in its network settings.
7. Keep the server running. If the network blocks device-to-device traffic, LAN access will not work.

## Important limitations
- This is a prototype, not a production-secure messenger or audited E2EE implementation.
- Everyone in a room must share the same encryption phrase out of band. The browser derives a room key using PBKDF2 and AES-GCM. It lacks forward secrecy, identity verification, safe key rotation, and a reviewed group protocol.
- The room passcode and membership are checked by the server; it can see names, join requests, room membership, IP/connection metadata, and timing. The server does not receive plaintext message/photo contents through the chat relay.
- A malicious server could alter client JavaScript before it reaches browsers, which undermines web E2EE. Production needs a trusted deployment, security review, key verification and a more robust design.
- Room state is in memory; rooms and participants disappear when the server stops. There is no persistent chat history.
- Photos are limited to small images. This demo does not implement durable file storage.
- No TLS is configured by default. Use HTTPS for deployment; Web Crypto requires a secure context (localhost is allowed).
- No rate limiting, database, authentication, anti-spam controls, or production hardening is included.
- The website cannot discover all devices merely by their shared public IP. Users join with a room code. To deploy beyond the local network, host the server on an internet-accessible service and configure HTTPS/firewall settings.
