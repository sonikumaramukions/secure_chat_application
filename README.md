# Secure Web Chat Application

A fully secure, end-to-end encrypted web chat application with advanced security features including URL scanning, file sharing, and robust authentication.

## 🔒 Security Features

- **End-to-End Encryption**: All messages are encrypted using AES-GCM with 256-bit keys
- **RSA Digital Signatures**: Identity verification using RSA-PSS with SHA-256
- **Perfect Forward Secrecy**: ECDH key exchange for session keys
- **URL Safety Scanning**: Real-time URL scanning using VirusTotal and AlienVault OTX APIs
- **Secure File Sharing**: Encrypted file transfer up to 25MB
- **Password Security**: bcrypt hashing with secure password reset functionality
- **MITM Protection**: Cryptographic signatures prevent man-in-the-middle attacks

## 🚀 Features

- **Real-time Messaging**: WebSocket-based instant messaging
- **File Sharing**: Secure encrypted file transfer with download links
- **User Management**: Registration, login, and password reset
- **Chat History**: Persistent local storage of encrypted conversations
- **Modern UI**: Glass-morphism design with dark theme
- **Notifications**: Browser notifications and audio alerts
- **Search**: Search through conversations and messages
- **Account Management**: Delete conversations and account data

## 📋 Prerequisites

- Python 3.7+
- Modern web browser with Web Crypto API support
- API keys for security services (optional but recommended)

## 🛠️ Installation

1. **Clone or download the project files**

2. **Set up Python virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Python dependencies**:
   ```bash
   pip install websockets flask flask-cors bcrypt requests
   ```

4. **Configure API keys** (optional):
   - Get a VirusTotal API key from [virustotal.com](https://www.virustotal.com/)
   - Get an AlienVault OTX API key from [otx.alienvault.com](https://otx.alienvault.com/)
   - Set environment variables:
     ```bash
     export VT_API_KEY="your_virustotal_api_key"
     export OTX_API_KEY="your_otx_api_key"
     ```

## 🚀 Running the Application

1. **Start the WebSocket server**:
   ```bash
   python websocket_server.py
   ```
   The server will start on port 8765.

2. **Start the URL scanner service** (in a separate terminal):
   ```bash
   python scanner_service.py
   ```
   The scanner service will start on port 5000.

3. **Open the web application**:
   - Open `index.html` in your web browser
   - Or serve it using a local web server:
     ```bash
     python -m http.server 8000
     ```
     Then navigate to `http://localhost:8000`

## 📱 Usage

### Getting Started

1. **Register a new account** or **login** with existing credentials
2. **Start a new chat** by clicking "New" and entering a username
3. **Establish secure connection**:
   - Type `sharekey <username>` to share your identity key
   - Type `talk <username>` to initiate encrypted session
   - Wait for the "🔒 E2E Active" badge to appear

### Commands

- `sharekey <username>` - Share your RSA public key with another user
- `talk <username>` - Initiate encrypted session with another user
- `reset <username> <token> <new_password>` - Reset password using token

### Security Workflow

1. **Identity Exchange**: Users share RSA public keys for identity verification
2. **Session Establishment**: ECDH key exchange creates shared AES session keys
3. **Encrypted Communication**: All messages and files are encrypted with AES-GCM
4. **URL Scanning**: Links are automatically scanned for malware and threats

## 🔧 Configuration

### API Keys

The application includes placeholder API keys that may be expired. For production use:

1. **VirusTotal**: Sign up at [virustotal.com](https://www.virustotal.com/) and get your API key
2. **AlienVault OTX**: Sign up at [otx.alienvault.com](https://otx.alienvault.com/) and get your API key
3. **Set environment variables** or update the keys in `scanner_service.py`

### Database

The application uses SQLite for user storage. The database file `chat_users.db` is created automatically.

### File Limits

- Maximum file size: 25MB
- Supported file types: All types (encrypted transfer)

## 🏗️ Architecture

### Components

- **Frontend** (`index.html`, `chat.js`): Modern web interface with Web Crypto API
- **WebSocket Server** (`websocket_server.py`): Handles authentication and message relay
- **Scanner Service** (`scanner_service.py`): URL safety scanning using external APIs
- **Database** (`chat_users.db`): SQLite database for user credentials

### Security Model

1. **Authentication**: bcrypt password hashing with secure token-based password reset
2. **Key Exchange**: RSA for identity, ECDH for session keys
3. **Encryption**: AES-GCM for message and file encryption
4. **Integrity**: RSA-PSS signatures for message authentication
5. **URL Safety**: Multi-service scanning for malicious links

## 🔍 Security Considerations

- **Perfect Forward Secrecy**: Session keys are ephemeral and not stored
- **No Server-Side Decryption**: Server only relays encrypted messages
- **Local Storage**: Chat history is stored locally, not on server
- **API Rate Limits**: Scanner service respects API rate limits
- **MITM Protection**: Cryptographic signatures prevent key exchange attacks

## 🐛 Troubleshooting

### Common Issues

1. **"Connection error"**: Ensure WebSocket server is running on port 8765
2. **"Scanner service unavailable"**: Start `scanner_service.py` on port 5000
3. **"Invalid API key"**: Update API keys in `scanner_service.py`
4. **"E2E Unsecure"**: Complete the key exchange process with `sharekey` and `talk` commands

### Browser Compatibility

- Requires Web Crypto API support
- Modern browsers: Chrome 37+, Firefox 34+, Safari 7+, Edge 12+

## 📄 License

This project is for educational and demonstration purposes. Please ensure compliance with API terms of service for VirusTotal and AlienVault OTX.

## 🤝 Contributing

This is a demonstration project. For production use, consider:
- Implementing proper certificate pinning
- Adding message authentication codes
- Implementing perfect forward secrecy for file transfers
- Adding message retry mechanisms
- Implementing proper error handling and logging

## ⚠️ Disclaimer

This application is for educational purposes. While it implements strong cryptographic practices, it should not be used for sensitive communications without additional security audits and hardening.
