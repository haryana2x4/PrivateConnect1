const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 8e6 });
const PORT = process.env.PORT || 3000;

// In-memory prototype: rooms disappear when the server restarts.
const rooms = new Map();
const safeText = (s, n = 80) => String(s || "").trim().slice(0, n);
const makeCode = () => crypto.randomBytes(3).toString("hex").toUpperCase();

app.use(express.static("public"));
app.get("/health", (_req, res) => res.json({ ok: true }));

io.on("connection", socket => {
  socket.on("host:create", ({ name, roomPasscode }, cb = () => {}) => {
    let code = makeCode();
    while (rooms.has(code)) code = makeCode();
    const room = {
      code,
      hostId: socket.id,
      hostName: safeText(name, 30) || "Host",
      // Room passcode is only used for access gating; never use it as the encryption key directly.
      roomPasscode: safeText(roomPasscode, 100),
      members: new Map([[socket.id, { name: safeText(name, 30) || "Host", role: "host", approved: true }]]),
      pending: new Map()
    };
    rooms.set(code, room);
    socket.join(code);
    cb({ ok: true, code, members: [] });
  });

  socket.on("room:request", ({ code, name, roomPasscode }, cb = () => {}) => {
    code = safeText(code, 10).toUpperCase();
    name = safeText(name, 30) || "Guest";
    const room = rooms.get(code);
    if (!room) return cb({ ok: false, error: "Room not found. Check the room code." });
    if (room.roomPasscode && room.roomPasscode !== safeText(roomPasscode, 100)) {
      return cb({ ok: false, error: "Incorrect room passcode." });
    }
    if (socket.id === room.hostId) return cb({ ok: false, error: "You are already the host." });
    room.pending.set(socket.id, { name, requestedAt: Date.now() });
    socket.data.pendingRoom = code;
    socket.emit("room:pending", { code });
    io.to(room.hostId).emit("host:pending", pendingList(room));
    cb({ ok: true, waiting: true });
  });

  socket.on("host:decision", ({ code, guestId, allow }, cb = () => {}) => {
    const room = rooms.get(safeText(code, 10).toUpperCase());
    if (!room || room.hostId !== socket.id) return cb({ ok: false, error: "Host permission required." });
    const pending = room.pending.get(guestId);
    if (!pending) return cb({ ok: false, error: "Request is no longer pending." });
    room.pending.delete(guestId);
    if (allow) {
      room.members.set(guestId, { name: pending.name, role: "member", approved: true });
      const guestSocket = io.sockets.sockets.get(guestId);
      if (guestSocket) {
        guestSocket.join(room.code);
        guestSocket.data.roomCode = room.code;
        guestSocket.emit("room:approved", { code: room.code, name: pending.name });
      }
      io.to(room.code).emit("room:members", memberList(room));
    } else {
      io.to(guestId).emit("room:rejected", { message: "The host declined your request." });
    }
    io.to(room.hostId).emit("host:pending", pendingList(room));
    cb({ ok: true });
  });

  // The server relays ciphertext only. It does not decrypt message or photo payloads.
  socket.on("chat:send", ({ code, packet }, cb = () => {}) => {
    const room = rooms.get(safeText(code, 10).toUpperCase());
    if (!room || !room.members.has(socket.id)) return cb({ ok: false, error: "Not approved for this room." });
    if (!packet || typeof packet !== "object" || typeof packet.iv !== "string" || typeof packet.data !== "string") {
      return cb({ ok: false, error: "Invalid encrypted packet." });
    }
    if (packet.data.length > 5_500_000) return cb({ ok: false, error: "Attachment too large (max about 4 MB before encryption)." });
    const member = room.members.get(socket.id);
    socket.to(room.code).emit("chat:packet", {
      sender: member.name,
      senderId: socket.id,
      packet,
      sentAt: Date.now()
    });
    cb({ ok: true });
  });

  socket.on("host:remove", ({ code, memberId }, cb = () => {}) => {
    const room = rooms.get(safeText(code, 10).toUpperCase());
    if (!room || room.hostId !== socket.id) return cb({ ok: false, error: "Host permission required." });
    if (memberId === room.hostId) return cb({ ok: false, error: "Cannot remove the host." });
    room.members.delete(memberId);
    room.pending.delete(memberId);
    const target = io.sockets.sockets.get(memberId);
    if (target) {
      target.leave(room.code);
      target.data.roomCode = null;
      target.emit("room:removed", { message: "The host removed you from this room." });
    }
    io.to(room.code).emit("room:members", memberList(room));
    io.to(room.hostId).emit("host:pending", pendingList(room));
    cb({ ok: true });
  });

  socket.on("room:leave", ({ code } = {}) => leaveRoom(socket, code));
  socket.on("disconnect", () => {
    for (const [code, room] of rooms) {
      if (room.hostId === socket.id) {
        io.to(code).emit("room:closed", { message: "The host closed the room." });
        for (const id of room.members.keys()) {
          const s = io.sockets.sockets.get(id);
          if (s) s.leave(code);
        }
        rooms.delete(code);
      } else {
        room.members.delete(socket.id);
        room.pending.delete(socket.id);
        io.to(room.hostId).emit("host:pending", pendingList(room));
        io.to(code).emit("room:members", memberList(room));
      }
    }
  });
});

function pendingList(room) {
  return [...room.pending.entries()].map(([id, p]) => ({ id, name: p.name }));
}
function memberList(room) {
  return [...room.members.entries()].map(([id, m]) => ({ id, name: m.name, role: m.role }));
}
function leaveRoom(socket, code) {
  const room = rooms.get(safeText(code, 10).toUpperCase());
  if (!room) return;
  if (room.hostId === socket.id) {
    io.to(room.code).emit("room:closed", { message: "The host closed the room." });
    rooms.delete(room.code);
  } else {
    room.members.delete(socket.id);
    room.pending.delete(socket.id);
    socket.leave(room.code);
    io.to(room.hostId).emit("host:pending", pendingList(room));
    io.to(room.code).emit("room:members", memberList(room));
  }
}

server.listen(PORT, "0.0.0.0", () => {
  console.log(`PrivateConnect Web running on http://localhost:${PORT}`);
  console.log("For other devices on your Wi-Fi, use this computer's LAN IP and port 3000.");
});
