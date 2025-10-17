// chat.js - Final version with all features.
const GOOGLE_API_KEY = "PASTE_YOUR_GOOGLE_API_KEY_HERE";

// --- DOM Elements ---
const loginContainer = document.getElementById('login-container');
const loginTitle = document.getElementById('login-title');
const usernameInput = document.getElementById('username-input');
const passwordInput = document.getElementById('password-input');
const loginButton = document.getElementById('login-button');
const registerButton = document.getElementById('register-button');
const authButtons = document.getElementById('auth-buttons');
const authMessage = document.getElementById('auth-message');
const forgotPasswordLink = document.getElementById('forgot-password');
const appContainer = document.getElementById('app-container');
const conversationsList = document.getElementById('conversations-list');
const chatHeader = document.getElementById('chat-header');
const chatTitle = document.getElementById('chat-title');
const e2eBadge = document.getElementById('e2e-badge');
const statusDot = document.getElementById('status-dot');
const searchInput = document.getElementById('search-input');
const newChatButton = document.getElementById('new-chat-button');
const chatLog = document.getElementById('chat-log');
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const deleteAccountButton = document.getElementById('delete-account-button');
const fileInput = document.getElementById('file-input');
const loginBox = document.getElementById('login-box');

// --- Application State ---
let socket; let myUsername; let activeChatPartner = null; let chatHistory = {};
let myRsaKeyPair = {}; const sessionKeys = {}; const dhPrivateKeys = {}; const peerRsaPublicKeys = {};
const outgoingQueue = {};

// --- Persistence ---
function saveHistory() { localStorage.setItem(`chatHistory_${myUsername}`, JSON.stringify(chatHistory)); }
function loadHistory() { const savedHistory = localStorage.getItem(`chatHistory_${myUsername}`); if (savedHistory) { chatHistory = JSON.parse(savedHistory); } }
function saveSessionKey(recipient, rawKey) { const map = JSON.parse(sessionStorage.getItem(`sessions_${myUsername}`) || '{}'); map[recipient] = ab_to_b64(rawKey); sessionStorage.setItem(`sessions_${myUsername}`, JSON.stringify(map)); }
async function loadSessionKeys() { const map = JSON.parse(sessionStorage.getItem(`sessions_${myUsername}`) || '{}'); for (const [peer, b64] of Object.entries(map)) { try { const raw = b64_to_ab(b64); const key = await window.crypto.subtle.importKey('raw', raw, {name:'AES-GCM'}, true, ['encrypt','decrypt']); sessionKeys[peer] = key; } catch (_) {} } }
function updateE2EBadge() { const secure = activeChatPartner && sessionKeys[activeChatPartner]; if (secure) { e2eBadge.textContent = '🔒 E2E Active'; e2eBadge.style.borderColor = 'rgba(110,231,183,0.6)'; } else { e2eBadge.textContent = '⚠️ Unsecure'; e2eBadge.style.borderColor = 'rgba(248,113,113,0.6)'; } }
function setStatusOnline(isOnline) { if (!statusDot) return; statusDot.style.background = isOnline ? '#10b981' : '#f59e0b'; statusDot.style.boxShadow = isOnline ? '0 0 10px #10b981' : '0 0 10px #f59e0b'; }

// --- URL Safety Scanning ---
function extractUrls(text) { const urlRegex = /(https?:\/\/[^\s]+)/g; return text.match(urlRegex) || []; }
async function checkUrlSafety(url) {
    const scannerApiUrl = `http://127.0.0.1:5000/scan?url=${encodeURIComponent(url)}`;
    try {
        const response = await fetch(scannerApiUrl);
        if (!response.ok) { return { status: 'error' }; }
        return await response.json();
    } catch (error) { console.error("Could not connect to scanner service:", error); return { status: 'error' }; }
}

// --- UI Rendering ---
function renderConversationsList() {
    conversationsList.innerHTML = '';
    const term = (searchInput && searchInput.value || '').toLowerCase();
    Object.keys(chatHistory).forEach(username => {
        const li = document.createElement('li');
        li.id = `conv-list-item-${username}`;
        const nameSpan = document.createElement('span');
        nameSpan.className = 'name';
        const nameText = document.createElement('span');
        nameText.textContent = username;
        const unread = document.createElement('span');
        unread.className = 'unread-badge';
        unread.textContent = '•';
        nameSpan.appendChild(nameText);
        nameSpan.appendChild(unread);
        li.onclick = () => switchChat(username);
        const deleteBtn = document.createElement('span');
        deleteBtn.textContent = '×';
        deleteBtn.classList.add('delete-btn');
        deleteBtn.title = `Delete chat with ${username}`;
        deleteBtn.onclick = (e) => { e.stopPropagation(); deleteConversation(username); };
        li.appendChild(nameSpan);
        li.appendChild(deleteBtn);
        if (username === activeChatPartner) { li.classList.add('active'); }
        const matches = username.toLowerCase().includes(term) || (chatHistory[username]||[]).some(m => (m.text||'').toLowerCase().includes(term));
        if (matches) conversationsList.appendChild(li);
    });
}
async function renderChatLog() {
    chatLog.innerHTML = '';
    if (activeChatPartner && chatHistory[activeChatPartner]) {
        for (const msg of chatHistory[activeChatPartner]) {
            if (msg.isFile) {
                const link = document.createElement('a');
                link.href = msg.url;
                link.download = msg.filename;
                link.textContent = msg.text;
                const msgDiv = document.createElement('div');
                msgDiv.classList.add('message', msg.sender === myUsername ? 'sent' : 'received');
                msgDiv.appendChild(link);
                chatLog.appendChild(msgDiv);
            } else {
                await logMessage(msg.text, msg.sender === myUsername ? 'sent' : 'received', false);
            }
        }
    }
    if (chatLog.scrollTop !== undefined) chatLog.scrollTop = chatLog.scrollHeight;
}
async function switchChat(username) {
    activeChatPartner = username;
    if (chatTitle) chatTitle.textContent = `Chatting with: ${username}`;
    const listItem = document.getElementById(`conv-list-item-${username}`);
    if (listItem) listItem.classList.remove('has-new-message');
    renderConversationsList();
    await renderChatLog();
    messageInput.placeholder = `Message ${username}...`;
    messageInput.focus();
    updateE2EBadge();
}
async function logMessage(message, type = 'system', scroll = true) {
    const msgDiv = document.createElement('div');
    msgDiv.classList.add('message', type);
    const urls = extractUrls(message);
    if (type !== 'system' && urls.length > 0) {
        const parts = message.split(urls[0]);
        msgDiv.appendChild(document.createTextNode(parts[0]));
        const link = document.createElement('a');
        link.href = urls[0];
        link.textContent = urls[0];
        link.target = "_blank";
        const safetyResult = await checkUrlSafety(urls[0]);
        if (safetyResult.status === 'unsafe') { link.style.color = 'red'; link.textContent += ` [WARNING: ${safetyResult.threat}]`; link.title = `This link is flagged as unsafe! (${safetyResult.threat})`; }
        msgDiv.appendChild(link);
        msgDiv.appendChild(document.createTextNode(parts[1] || ''));
    } else {
        msgDiv.textContent = message;
    }
    chatLog.appendChild(msgDiv);
    if (scroll && chatLog.scrollTop !== undefined) chatLog.scrollTop = chatLog.scrollHeight;
}

// --- Data & File Management ---
function deleteConversation(username) { if (confirm(`Delete chat history with "${username}"?`)) { delete chatHistory[username]; delete sessionKeys[username]; delete dhPrivateKeys[username]; delete peerRsaPublicKeys[username]; if (activeChatPartner === username) { activeChatPartner = null; if (chatTitle) chatTitle.textContent = 'Select a conversation'; renderChatLog(); updateE2EBadge(); } saveHistory(); renderConversationsList(); logMessage(`Chat history with "${username}" deleted.`, 'system'); } }
function deleteAccount() { if (confirm('Permanently delete your account and all local data?')) { localStorage.removeItem(`chatHistory_${myUsername}`); logMessage('Account data deleted. Page will reload.', 'system'); setTimeout(() => { location.reload(); }, 2000); } }
async function handleFileSelect(event) { const file = event.target.files[0]; if (!file || !activeChatPartner) { if (!activeChatPartner) logMessage('[ERROR] Select a chat to send the file to.', 'system'); return; } if (file.size > 25 * 1024 * 1024) { logMessage('[ERROR] File too large. Max 25 MB.', 'system'); fileInput.value = ''; return; } logMessage(`Preparing to send file: ${file.name}...`, 'system'); try { const fileBuffer = await file.arrayBuffer(); const aesKey = sessionKeys[activeChatPartner]; if (!aesKey) { queueOutgoing(activeChatPartner, { type: 'file', fileName: file.name, fileType: file.type, buffer: fileBuffer }); logMessage(`[INFO] Queued file until secure session is ready.`, 'system'); return; } await sendEncryptedFile(activeChatPartner, aesKey, { type: 'file', fileName: file.name, fileType: file.type, buffer: fileBuffer }); } catch (e) { logMessage(`[ERROR] Failed to send file: ${e.message}`, 'system'); } fileInput.value = ''; }
async function sendEncryptedFile(recipient, aesKey, job) { const iv = window.crypto.getRandomValues(new Uint8Array(12)); const ciphertext = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, job.buffer); const filePayload = { filename: job.fileName, mimetype: job.fileType, data: ab_to_b64(ciphertext) }; socket.send(JSON.stringify({ type: 'encrypted_file', sender: myUsername, recipient, iv: ab_to_b64(iv), payload: filePayload })); const blob = new Blob([job.buffer], { type: job.fileType }); const text = `You sent file: ${job.fileName}`; const msgObject = { sender: myUsername, text, isFile: true, url: URL.createObjectURL(blob), filename: job.fileName, timestamp: Date.now() }; if (!chatHistory[recipient]) chatHistory[recipient] = []; chatHistory[recipient].push(msgObject); saveHistory(); await renderChatLog(); }

// --- Crypto Helpers ---
function ab_to_b64(ab) { return btoa(String.fromCharCode.apply(null, new Uint8Array(ab))); }
function b64_to_ab(b64) { const s = window.atob(b64); const len = s.length; const bytes = new Uint8Array(len); for (let i = 0; i < len; i++) { bytes[i] = s.charCodeAt(i); } return bytes.buffer; }

// --- Web Crypto API Implementation ---
async function generateRsaKeyPair() { myRsaKeyPair = await window.crypto.subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]); }
async function signData(data) { return await window.crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, myRsaKeyPair.privateKey, data); }
async function verifySignature(senderUsername, signature, data) { const publicKey = peerRsaPublicKeys[senderUsername]; if (!publicKey) throw new Error(`No public RSA key for ${senderUsername}.`); return await window.crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, publicKey, signature, data); }

// --- Message Handlers ---
async function handleServerMessage(event) { const message = JSON.parse(event.data); switch (message.type) { case 'rsa_public_key': await handleRsaPublicKey(message); break; case 'dh_initiate': await handleDhInitiate(message); break; case 'dh_response': await handleDhResponse(message); break; case 'encrypted_message': await handleEncryptedMessage(message); break; case 'encrypted_file': await handleEncryptedFile(message); break; } }
async function handleRsaPublicKey(message) { const sender = message.sender; peerRsaPublicKeys[sender] = await window.crypto.subtle.importKey('jwk', message.data, { name: "RSA-PSS", hash: "SHA-256" }, true, ["verify"]); logMessage(`[ID] Received public identity key from '${sender}'.`, 'system'); logMessage(`To complete the trust exchange, please type: sharekey ${sender}`, 'system'); if (sender !== activeChatPartner) { const listItem = document.getElementById(`conv-list-item-${sender}`); if (listItem) listItem.classList.add('has-new-message'); } }
async function initiateDhExchange(recipient) { if (!peerRsaPublicKeys[recipient]) { logMessage(`[ERROR] Trust not established. Use 'sharekey ${recipient}' first.`, 'system'); return; } logMessage(`[KEY XCHG] Initiating with '${recipient}'...`, 'system'); const keyPair = await window.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']); dhPrivateKeys[recipient] = keyPair.privateKey; const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey); const signature = await signData(new TextEncoder().encode(JSON.stringify(publicKeyJwk))); socket.send(JSON.stringify({ type: 'dh_initiate', sender: myUsername, recipient: recipient, data: publicKeyJwk, signature: ab_to_b64(signature) })); }
async function handleDhInitiate(message) { const sender = message.sender; notify('Key exchange requested'); logMessage(`[KEY XCHG] Request from '${sender}'. Verifying...`, 'system'); try { const isValid = await verifySignature(sender, b64_to_ab(message.signature), new TextEncoder().encode(JSON.stringify(message.data))); if (!isValid) throw new Error("Invalid signature! MITM ATTACK?!"); logMessage(`[KEY XCHG] Signature from '${sender}' is valid.`, 'system'); const peerPublicKey = await window.crypto.subtle.importKey('jwk', message.data, { name: 'ECDH', namedCurve: 'P-256' }, true, []); const keyPair = await window.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']); const aesKey = await window.crypto.subtle.deriveKey({ name: 'ECDH', public: peerPublicKey }, keyPair.privateKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); sessionKeys[sender] = aesKey; if (!chatHistory[sender]) chatHistory[sender] = []; logMessage(`[KEY XCHG] Shared secret with '${sender}' established.`, 'system'); renderConversationsList(); const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey); const signature = await signData(new TextEncoder().encode(JSON.stringify(publicKeyJwk))); socket.send(JSON.stringify({ type: 'dh_response', sender: myUsername, recipient: sender, data: publicKeyJwk, signature: ab_to_b64(signature) })); const raw = await window.crypto.subtle.exportKey('raw', aesKey); saveSessionKey(sender, raw); flushQueue(sender); updateE2EBadge(); notify('Secure session established'); } catch(e) { logMessage(`[CRITICAL ERROR] ${e.message}`, 'system'); } }
async function handleDhResponse(message) { const sender = message.sender; logMessage(`[KEY XCHG] Response from '${sender}'. Verifying...`, 'system'); try { const isValid = await verifySignature(sender, b64_to_ab(message.signature), new TextEncoder().encode(JSON.stringify(message.data))); if (!isValid) throw new Error("Invalid signature on DH response! MITM ATTACK?!"); logMessage(`[KEY XCHG] Signature from '${sender}' is valid.`, 'system'); const peerPublicKey = await window.crypto.subtle.importKey('jwk', message.data, { name: 'ECDH', namedCurve: 'P-256' }, true, []); const aesKey = await window.crypto.subtle.deriveKey({ name: 'ECDH', public: peerPublicKey }, dhPrivateKeys[sender], { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); sessionKeys[sender] = aesKey; if (!chatHistory[sender]) chatHistory[sender] = []; logMessage(`[KEY XCHG] Handshake with '${sender}' complete.`, 'system'); await switchChat(sender); renderConversationsList(); const raw = await window.crypto.subtle.exportKey('raw', aesKey); saveSessionKey(sender, raw); flushQueue(sender); updateE2EBadge(); notify('Secure session established'); } catch(e) { logMessage(`[CRITICAL ERROR] ${e.message}`, 'system'); } }
async function handleEncryptedMessage(message) { const sender = message.sender; const aesKey = sessionKeys[sender]; if (aesKey) { try { const plaintext = new TextDecoder().decode(await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64_to_ab(message.iv) }, aesKey, b64_to_ab(message.ciphertext))); const msgObject = { sender, text: plaintext, timestamp: Date.now() }; if (!chatHistory[sender]) chatHistory[sender] = []; chatHistory[sender].push(msgObject); saveHistory(); if (sender === activeChatPartner) { await logMessage(`${plaintext}\n`, 'received'); appendTimestamp(); } else { const listItem = document.getElementById(`conv-list-item-${sender}`); if (listItem) listItem.classList.add('has-new-message'); } notify('New secure message'); const urlsInMsg = extractUrls(plaintext); if (urlsInMsg && urlsInMsg.length > 0) { try { for (const u of urlsInMsg) { const res = await checkUrlSafety(u); if (res && res.status === 'unsafe') { await logMessage(`[WARNING] Unsafe link detected: ${u} [${res.threat}]`, 'system'); } } } catch (_) {} } } catch (e) { logMessage(`[ERROR] Decryption failed.`, 'system'); } } }
async function handleEncryptedFile(message) { const sender = message.sender; const aesKey = sessionKeys[sender]; logMessage(`Receiving file from '${sender}'...`, 'system'); if(aesKey) { try { const decryptedBuffer = await window.crypto.subtle.decrypt({name: 'AES-GCM', iv: b64_to_ab(message.iv)}, aesKey, b64_to_ab(message.payload.data)); const blob = new Blob([decryptedBuffer], {type: message.payload.mimetype}); const downloadUrl = URL.createObjectURL(blob); const text = `File received: ${message.payload.filename}`; const msgObject = {sender, text, isFile: true, url: downloadUrl, filename: message.payload.filename, timestamp: Date.now()}; if(!chatHistory[sender]) chatHistory[sender] = []; chatHistory[sender].push(msgObject); saveHistory(); if(sender === activeChatPartner) { await renderChatLog(); } else { const listItem = document.getElementById(`conv-list-item-${sender}`); if(listItem) listItem.classList.add('has-new-message'); } } catch (e) { logMessage(`[ERROR] File decryption failed.`, 'system'); console.error(e); }} }
async function sendChatMessage(recipient, text) { const aesKey = sessionKeys[recipient]; const job = { type: 'text', text }; if (!aesKey) { queueOutgoing(recipient, job); logMessage(`[INFO] Queued message until secure session with '${recipient}' is ready.`, 'system'); return; } const msgObject = { sender: myUsername, text, timestamp: Date.now() }; if (!chatHistory[recipient]) chatHistory[recipient] = []; chatHistory[recipient].push(msgObject); saveHistory(); await logMessage(`${text}\n`, 'sent'); appendTimestamp(); const iv = window.crypto.getRandomValues(new Uint8Array(12)); const ciphertext = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, new TextEncoder().encode(text)); socket.send(JSON.stringify({ type: 'encrypted_message', sender: myUsername, recipient, iv: ab_to_b64(iv), ciphertext: ab_to_b64(ciphertext) })); }
function queueOutgoing(recipient, job) { if (!outgoingQueue[recipient]) outgoingQueue[recipient] = []; outgoingQueue[recipient].push(job); }
async function flushQueue(recipient) { const aesKey = sessionKeys[recipient]; if (!aesKey || !outgoingQueue[recipient]) return; const jobs = outgoingQueue[recipient]; delete outgoingQueue[recipient]; for (const job of jobs) { if (job.type === 'text') { await sendChatMessage(recipient, job.text); } else if (job.type === 'file') { await sendEncryptedFile(recipient, aesKey, job); } } }
function appendTimestamp() { const last = chatLog.lastElementChild; if (!last) return; const ts = document.createElement('span'); ts.className = 'timestamp'; ts.textContent = new Date().toLocaleTimeString(); last.appendChild(ts); }

// --- Main Application Logic ---
function handleAuthResponse(message) { if (message.success) { authMessage.textContent = ''; loginContainer.style.display = 'none'; appContainer.style.display = 'flex'; loadHistory(); loadSessionKeys().then(() => { renderConversationsList(); logMessage(`Welcome, ${myUsername}! Logged in.`, 'system'); logMessage("Commands: 'sharekey <user>', 'talk <user>', 'reset ...'", 'system'); updateE2EBadge(); }); } else { authMessage.textContent = message.message; } }
async function connect(authType) { const username = usernameInput.value.trim(); const password = passwordInput.value.trim(); if (!username || !password && authType !== 'forgot_password') { authMessage.textContent = 'Username and password required.'; return; } myUsername = username; await generateRsaKeyPair(); const wsUrl = `ws://${window.location.hostname || '127.0.0.1'}:8765`; socket = new WebSocket(wsUrl); socket.onopen = () => { setStatusOnline(true); socket.send(JSON.stringify({ type: authType, username, password })); }; socket.onmessage = (event) => { const message = JSON.parse(event.data); if (message.type.endsWith('_response')) { if (message.type === 'auth_response') { handleAuthResponse(message); socket.onmessage = handleServerMessage; } else { authMessage.textContent = message.message; } } else { handleServerMessage(event); } }; socket.onclose = () => { setStatusOnline(false); logMessage('Disconnected.', 'system'); }; socket.onerror = () => { setStatusOnline(false); logMessage('Connection error.', 'system'); }; }
function handleSend() { const text = messageInput.value.trim(); if (!text) return; if (text.startsWith('talk ')) { const recipient = text.split(' ')[1]; if (recipient && recipient !== myUsername) initiateDhExchange(recipient); } else if (text.startsWith('sharekey ')) { const recipient = text.split(' ')[1]; if (recipient && recipient !== myUsername) { logMessage(`[ID] Sharing identity key with '${recipient}'...`, 'system'); window.crypto.subtle.exportKey('jwk', myRsaKeyPair.publicKey).then(jwk => { socket.send(JSON.stringify({ type: 'rsa_public_key', sender: myUsername, recipient, data: jwk })); notify('Key exchange requested'); }); } } else if (text.startsWith('reset ')) { const parts = text.split(' '); if (parts.length === 4) { const [_, username, token, newPassword] = parts; socket.send(JSON.stringify({ type: 'reset_password', username, token, password: newPassword })); } else { logMessage('Usage: reset <user> <token> <new_password>', 'system'); } } else { if (activeChatPartner) { sendChatMessage(activeChatPartner, text); } else { logMessage("Select a conversation or use a command.", 'system'); } } messageInput.value = ''; }
function setupForgotPassword() { loginTitle.textContent = 'Forgot Password'; passwordInput.style.display = 'none'; authButtons.style.display = 'none'; forgotPasswordLink.style.display = 'none'; const resetButton = document.createElement('button'); resetButton.textContent = 'Send Reset Instructions'; loginBox.insertBefore(resetButton, authMessage); resetButton.onclick = () => { const username = usernameInput.value.trim(); if (username) { if(!socket || socket.readyState !== WebSocket.OPEN) { const wsUrl = `ws://${window.location.hostname || '127.0.0.1'}:8765`; socket = new WebSocket(wsUrl); socket.onopen = () => { socket.send(JSON.stringify({ type: 'forgot_password', username })); }; socket.onmessage = (event) => { const message = JSON.parse(event.data); authMessage.textContent = message.message; }; } else { socket.send(JSON.stringify({ type: 'forgot_password', username })); }} else { authMessage.textContent = 'Please enter username.'; }}; }

// --- Event Listeners ---
loginButton.addEventListener('click', () => connect('login'));
registerButton.addEventListener('click', () => connect('register'));
sendButton.addEventListener('click', handleSend);
messageInput.addEventListener('keydown', (event) => { if (event.key === 'Enter') { handleSend(); } });
deleteAccountButton.addEventListener('click', deleteAccount);
forgotPasswordLink.addEventListener('click', setupForgotPassword);
fileInput.addEventListener('change', handleFileSelect);
if (searchInput) searchInput.addEventListener('input', renderConversationsList);
if (newChatButton) newChatButton.addEventListener('click', () => { const peer = prompt('Start chat with username:'); if (peer && peer !== myUsername) { if (!chatHistory[peer]) chatHistory[peer] = []; saveHistory(); renderConversationsList(); switchChat(peer); } });

// Notifications & sound
async function notify(text) { try { if (Notification.permission === 'default') await Notification.requestPermission(); if (Notification.permission === 'granted') new Notification('Secure Web Chat', { body: text }); } catch (_) {} playChime(); }
function playChime() { try { const ctx = new (window.AudioContext || window.webkitAudioContext)(); const osc = ctx.createOscillator(); const gain = ctx.createGain(); osc.type = 'sine'; osc.frequency.value = 880; gain.gain.setValueAtTime(0.2, ctx.currentTime); gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.2); osc.connect(gain).connect(ctx.destination); osc.start(); osc.stop(ctx.currentTime + 0.2); } catch (_) {} }

// Maintain badge on focus and after reconnect
window.addEventListener('focus', () => { try { updateE2EBadge(); } catch (_) {} });
