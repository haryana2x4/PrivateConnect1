(() => {
  const socket = io();
  const $ = id => document.getElementById(id);
  const state = { role: null, code: null, name: null, phrase: null, hostId: null, pending: [], members: [], joined: false };
  const landing = $("landing"), roomView = $("roomView");
  const setStatus = (msg) => $("landingStatus").textContent = msg;
  const escapeText = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const showRoom = () => { landing.classList.add("hidden"); roomView.classList.remove("hidden"); $("activeCode").textContent = state.code; $("chatTitle").textContent = `Room ${state.code}`; };
  const showLanding = () => { roomView.classList.add("hidden"); landing.classList.remove("hidden"); };
  const logSystem = text => addBubble("System", text, false, true);

  // Browser-side AES-GCM. The server receives only {iv,data}; it cannot decrypt chat payloads.
  // A phrase-based demo is not a substitute for a reviewed protocol with identity verification.
  async function deriveKey(phrase, code) {
    if (phrase.length < 12) throw new Error("Encryption phrase must be at least 12 characters.");
    const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(phrase), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({
      name: "PBKDF2", salt: new TextEncoder().encode("PrivateConnect-v1:" + code), iterations: 250000, hash: "SHA-256"
    }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function encryptPayload(payload) {
    const key = await deriveKey(state.phrase, state.code);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = new TextEncoder().encode(JSON.stringify(payload));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);
    return { iv: toB64(iv), data: toB64(new Uint8Array(encrypted)) };
  }
  async function decryptPayload(packet) {
    const key = await deriveKey(state.phrase, state.code);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(packet.iv) }, key, fromB64(packet.data));
    return JSON.parse(new TextDecoder().decode(plain));
  }
  function toB64(bytes) { let s = ""; bytes.forEach(b => s += String.fromCharCode(b)); return btoa(s); }
  function fromB64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }

  $("hostForm").addEventListener("submit", e => {
    e.preventDefault();
    if (!window.crypto?.subtle) return setStatus("Secure browser crypto requires HTTPS or localhost.");
    const name = $("hostName").value.trim(), phrase = $("hostPhrase").value;
    if (phrase.length < 12) return setStatus("Choose an encryption phrase with at least 12 characters.");
    state.role = "host"; state.name = name; state.phrase = phrase;
    socket.emit("host:create", { name, roomPasscode: $("hostPass").value }, result => {
      if (!result?.ok) { setStatus(result?.error || "Could not create room."); return; }
      state.code = result.code; state.joined = true; state.hostId = socket.id;
      $("hostTools").classList.remove("hidden");
      showRoom(); renderMembers([{ id: socket.id, name, role: "host" }]); renderPending([]);
      logSystem("Room created. Share the room code and encryption phrase privately. Approve visitors in the sidebar.");
    });
  });

  $("joinForm").addEventListener("submit", e => {
    e.preventDefault();
    if (!window.crypto?.subtle) return setStatus("Secure browser crypto requires HTTPS or localhost.");
    const phrase = $("guestPhrase").value;
    if (phrase.length < 12) return setStatus("Enter the host's encryption phrase (at least 12 characters).");
    state.role = "guest"; state.name = $("guestName").value.trim(); state.code = $("roomCode").value.trim().toUpperCase(); state.phrase = phrase;
    socket.emit("room:request", { code: state.code, name: state.name, roomPasscode: $("guestPass").value }, result => {
      if (!result?.ok) return setStatus(result?.error || "Could not request access.");
      setStatus("Request sent. Keep this tab open while the host reviews it.");
    });
  });

  socket.on("room:pending", ({ code }) => {
    state.code = code;
    showRoom();
    $("composer").classList.add("hidden");
    logSystem("Your request is waiting for host approval.");
  });
  socket.on("host:pending", list => { state.pending = list || []; renderPending(state.pending); });
  socket.on("room:approved", () => {
    state.joined = true; $("composer").classList.remove("hidden");
    logSystem("The host approved your request. You can now chat.");
  });
  socket.on("room:rejected", ({ message }) => { logSystem(message || "Request rejected."); });
  socket.on("room:members", renderMembers);
  socket.on("room:removed", ({ message }) => { state.joined = false; $("composer").classList.add("hidden"); logSystem(message); });
  socket.on("room:closed", ({ message }) => { logSystem(message); state.joined = false; $("composer").classList.add("hidden"); });
  socket.on("chat:packet", async msg => {
    try {
      const payload = await decryptPayload(msg.packet);
      if (payload.type === "text") addBubble(msg.sender, payload.text, false);
      else if (payload.type === "photo") addPhoto(msg.sender, payload.name, payload.mime, payload.data, false);
    } catch (e) {
      logSystem("Received a message that could not be decrypted. Check that everyone has the same encryption phrase.");
    }
  });

  function renderPending(list) {
    $("pendingCount").textContent = list.length;
    $("pendingList").innerHTML = "";
    if (!list.length) { $("pendingList").innerHTML = '<div class="muted small">No pending requests.</div>'; return; }
    list.forEach(p => {
      const el = document.createElement("div"); el.className = "person";
      el.innerHTML = `<span class="mini-avatar">${escapeText((p.name || "?")[0].toUpperCase())}</span><span class="person-name">${escapeText(p.name)}</span><button class="allow">Allow</button><button>Reject</button>`;
      const buttons = el.querySelectorAll("button");
      buttons[0].onclick = () => socket.emit("host:decision", { code: state.code, guestId: p.id, allow: true }, r => { if (!r?.ok) logSystem(r?.error || "Action failed."); });
      buttons[1].onclick = () => socket.emit("host:decision", { code: state.code, guestId: p.id, allow: false });
      $("pendingList").appendChild(el);
    });
  }
  function renderMembers(list) {
    state.members = list || [];
    $("memberCount").textContent = state.members.length;
    $("memberList").innerHTML = "";
    state.members.forEach(m => {
      const el = document.createElement("div"); el.className = "person";
      const isHost = m.role === "host";
      el.innerHTML = `<span class="mini-avatar">${escapeText((m.name || "?")[0].toUpperCase())}</span><span class="person-name">${escapeText(m.name)}${isHost ? " · host" : ""}</span>`;
      if (state.role === "host" && !isHost) {
        const btn = document.createElement("button"); btn.textContent = "Remove";
        btn.onclick = () => socket.emit("host:remove", { code: state.code, memberId: m.id }, r => { if (!r?.ok) logSystem(r?.error || "Could not remove member."); });
        el.appendChild(btn);
      }
      $("memberList").appendChild(el);
    });
    $("chatSubtitle").textContent = `${state.members.length} participant${state.members.length === 1 ? "" : "s"}`;
  }

  function addBubble(sender, text, mine, system = false) {
    const empty = $("messages").querySelector(".empty"); if (empty) empty.remove();
    const wrapper = document.createElement("div"); wrapper.className = "msg" + (mine ? " mine" : "");
    const meta = document.createElement("div"); meta.className = "msg-meta"; meta.textContent = system ? "PrivateConnect" : (mine ? "You" : sender);
    const bubble = document.createElement("div"); bubble.className = "bubble"; bubble.textContent = text;
    wrapper.append(meta, bubble); $("messages").appendChild(wrapper); $("messages").scrollTop = $("messages").scrollHeight;
  }
  function addPhoto(sender, name, mime, b64, mine) {
    const empty = $("messages").querySelector(".empty"); if (empty) empty.remove();
    const wrapper = document.createElement("div"); wrapper.className = "msg" + (mine ? " mine" : "");
    const meta = document.createElement("div"); meta.className = "msg-meta"; meta.textContent = (mine ? "You" : sender) + " · " + name;
    const bubble = document.createElement("div"); bubble.className = "bubble";
    const img = document.createElement("img"); img.alt = name; img.src = `data:${mime};base64,${b64}`;
    bubble.appendChild(img); wrapper.append(meta, bubble); $("messages").appendChild(wrapper); $("messages").scrollTop = $("messages").scrollHeight;
  }
  async function sendPayload(payload) {
    if (!state.joined) return logSystem("Wait until the host approves you.");
    try {
      const packet = await encryptPayload(payload);
      socket.emit("chat:send", { code: state.code, packet }, result => {
        if (!result?.ok) logSystem(result?.error || "Message could not be sent.");
      });
      if (payload.type === "text") addBubble(state.name, payload.text, true);
      else if (payload.type === "photo") addPhoto(state.name, payload.name, payload.mime, payload.data, true);
    } catch (e) { logSystem("Encryption failed: " + e.message); }
  }
  $("sendBtn").onclick = async () => {
    const input = $("messageInput"), text = input.value.trim();
    if (!text) return;
    input.value = ""; await sendPayload({ type: "text", text });
  };
  $("messageInput").addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("sendBtn").click(); }
  });
  $("photoInput").addEventListener("change", async e => {
    const file = e.target.files?.[0]; e.target.value = "";
    if (!file) return;
    if (!file.type.startsWith("image/")) return logSystem("Choose an image file.");
    if (file.size > 2_500_000) return logSystem("Choose an image smaller than 2.5 MB for this prototype.");
    const reader = new FileReader();
    reader.onload = async () => {
      const b64 = String(reader.result).split(",")[1];
      await sendPayload({ type: "photo", name: file.name.slice(0, 100), mime: file.type, data: b64 });
    };
    reader.readAsDataURL(file);
  });
  $("copyCode").onclick = async () => {
    try { await navigator.clipboard.writeText(state.code); $("copyCode").textContent = "Copied"; }
    catch { logSystem("Room code: " + state.code); }
  };
  $("leaveBtn").onclick = () => {
    if (state.code) socket.emit("room:leave", { code: state.code });
    state.joined = false; state.role = null; state.code = null; state.phrase = null;
    $("messages").innerHTML = '<div class="empty"><div class="empty-icon">✉</div><h3>Your conversation starts here</h3><p>Approved members can send encrypted messages and photos.</p></div>';
    $("hostTools").classList.add("hidden"); $("composer").classList.remove("hidden"); showLanding();
  };
})();
