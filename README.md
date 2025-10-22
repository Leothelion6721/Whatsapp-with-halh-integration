# 🔐 Secure WhatsApp Clone - Private Messaging with Authentication

A **fully secure real-time messaging application** with user authentication, password protection, contact management, and file sharing. Only your approved contacts can message you!

## 🛡️ Security Features

- ✅ **User Authentication** - Secure login with username and password
- ✅ **Password Protection** - Passwords hashed with bcrypt
- ✅ **JWT Tokens** - Secure session management
- ✅ **Contact System** - Only approved contacts can message you
- ✅ **Private Conversations** - Messages only visible to participants
- ✅ **Data Persistence** - All data saved to disk
- ✅ **File Sharing** - Secure file uploads (up to 10MB)

## ✨ All Features

- 🔐 **Secure Registration & Login** - Create accounts with passwords
- 👥 **Contact Management** - Add/remove contacts
- 💬 **Real-time Messaging** - Instant message delivery
- 📎 **File Sharing** - Images, documents, videos
- 🟢 **Online Status** - See who's online
- ⌨️ **Typing Indicators** - See when contacts are typing
- 💾 **Persistent Storage** - Messages saved permanently
- 📱 **Responsive Design** - Works on all devices

## 🚀 Quick Start

### Prerequisites

- Node.js (v14 or higher)
- npm

### Installation

1. **Navigate to the project folder:**
```bash
cd whatsapp-secure
```

2. **Install dependencies:**
```bash
npm install
```

3. **Start the server:**
```bash
npm start
```

4. **Open your browser:**
```
http://localhost:3000
```

## 📖 How the Security Works - Example Scenario

### Create Test Accounts

**User 1 - Leo:**
- Username: `Leo`
- Password: `LeoOwen` (or any password you choose)
- Contacts: Will add Owen

**User 2 - Owen:**
- Username: `Owen`
- Password: `OwenLeo` (or any password you choose)
- Contacts: Will add Leo

**User 3 - Harry:**
- Username: `Harry`
- Password: `HarryLeo` (or any password you choose)
- Contacts: None (won't add Leo or Owen)

### Test the Privacy System

1. **Leo and Owen add each other as contacts**
   - They can now chat privately
   - Their messages are only visible to them

2. **Harry cannot see Leo and Owen's conversations**
   - Harry didn't add them as contacts
   - Even if Harry tries, the system blocks access

3. **Harry cannot message Leo or Owen**
   - Since they're not mutual contacts
   - The system prevents unauthorized messaging

This demonstrates that only users who have mutually added each other as contacts can communicate!

## 🔒 How the Contact System Works

### Privacy Rules:

1. **Both users must add each other** to chat
2. **One-way contacts can't message** (if Leo adds Sarah, but Sarah doesn't add Leo, they can't chat)
3. **Non-contacts are completely isolated** (can't see or access any conversations)
4. **Messages are private** to the participants only

### Example:

```
Leo's Contacts: [Owen, Sarah]
Owen's Contacts: [Leo]
Harry's Contacts: []

Results:
- Leo ↔ Owen: ✅ Can chat (mutual contacts)
- Leo ↔ Sarah: ❌ Can't chat (Sarah hasn't added Leo back)
- Leo ↔ Harry: ❌ Can't chat (not in contacts)
- Harry cannot see ANY conversations between Leo and Owen
```

## 📁 Data Storage

All data is persisted in the `data/` folder:

```
data/
├── users.json     # User accounts (passwords are hashed)
├── messages.json  # All messages
└── chats.json     # Chat metadata
```

- Data auto-saves every 30 seconds
- Data saves on server shutdown
- All passwords are bcrypt hashed

## 🔧 Windows Quick Start

For Windows users, just double-click `START.bat` after installing Node.js!

## 🌐 Deployment Notes

For production deployment:

1. **Set environment variables:**
```
JWT_SECRET=your-very-secure-random-string-here
NODE_ENV=production
```

2. **Use HTTPS** (required for production)
3. **Add rate limiting** to prevent attacks
4. **Use a proper database** (MongoDB, PostgreSQL)

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| "Username already exists" | Choose a different username |
| "Invalid credentials" | Check username and password |
| "User is not in your contacts" | Both users must add each other |
| "Cannot send message to non-contact" | Add user as contact first |
| Lost password | Delete user from `data/users.json` and re-register |

## 📝 License

MIT License - Free to use for any purpose!

---

**Security Note:** This is a demonstration app. For production use, always implement additional security measures including HTTPS, environment variables for secrets, input validation, rate limiting, and a proper database.
