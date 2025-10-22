const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling'],
    allowEIO3: true,
    maxHttpBufferSize: 10e6
});

// NEW: Constant for message pagination
const MESSAGE_LIMIT = 50; 

// JWT Secret (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Create necessary directories
const uploadsDir = path.join(__dirname, 'uploads');
const dataDir = path.join(__dirname, 'data');

if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir);
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')); // Sanitize filename
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip|mp4|mp3|webm/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (extname && mimetype) {
            return cb(null, true);
        } else {
            cb(new Error('Invalid file type'));
        }
    }
});

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// In-memory storage with persistence
let users = new Map();
let messages = new Map();
let chats = new Map();
let sessions = new Map();

// Load data from files if they exist
function loadData() {
    try {
        if (fs.existsSync(path.join(dataDir, 'users.json'))) {
            const usersData = JSON.parse(fs.readFileSync(path.join(dataDir, 'users.json'), 'utf8'));
            users = new Map(usersData);
        }
        if (fs.existsSync(path.join(dataDir, 'messages.json'))) {
            const messagesData = JSON.parse(fs.readFileSync(path.join(dataDir, 'messages.json'), 'utf8'));
            messages = new Map(messagesData);
        }
        if (fs.existsSync(path.join(dataDir, 'chats.json'))) {
            const chatsData = JSON.parse(fs.readFileSync(path.join(dataDir, 'chats.json'), 'utf8'));
            chats = new Map(chatsData);
        }
        console.log('📁 Data loaded successfully');
    } catch (error) {
        console.error('Error loading data:', error);
    }
}

// Save data to files
function saveData() {
    try {
        fs.writeFileSync(
            path.join(dataDir, 'users.json'), 
            JSON.stringify([...users], null, 2)
        );
        fs.writeFileSync(
            path.join(dataDir, 'messages.json'), 
            JSON.stringify([...messages], null, 2)
        );
        fs.writeFileSync(
            path.join(dataDir, 'chats.json'), 
            JSON.stringify([...chats], null, 2)
        );
    } catch (error) {
        console.error('Error saving data:', error);
    }
}

// Load data on startup
loadData();

// Save data periodically
setInterval(saveData, 30000);

// Helper functions
function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

function getChatId(user1, user2) {
    return [user1, user2].sort().join('-');
}

function generateToken(userId) {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return decoded.userId;
    } catch (error) {
        return null;
    }
}

// REST API Endpoints

// Register endpoint
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const cleanUsername = username.trim().toLowerCase();
    
    if (cleanUsername.length < 3 || cleanUsername.length > 20) {
        return res.status(400).json({ error: 'Username must be 3-20 characters' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    if (users.has(cleanUsername)) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = generateId();
    
    users.set(cleanUsername, {
        userId,
        password: hashedPassword,
        username: cleanUsername,
        contacts: [],
        createdAt: Date.now(),
        online: false,
        socketId: null
    });
    
    saveData();
    
    const token = generateToken(userId);
    sessions.set(token, userId);
    
    res.json({ 
        success: true, 
        token,
        userId,
        username: cleanUsername
    });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const cleanUsername = username.trim().toLowerCase();

    const user = users.get(cleanUsername);
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = generateToken(user.userId);
    sessions.set(token, user.userId);
    
    res.json({ 
        success: true, 
        token,
        userId: user.userId,
        username: user.username
    });
});

// Authentication Middleware (using Authorization header for robustness)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expecting 'Bearer <token>'

    if (token == null) {
        // Fallback to body token if Authorization header is missing (for older clients)
        if (req.body.token) {
            return next();
        }
        return res.status(401).json({ error: 'Authentication token required' });
    }

    const userId = verifyToken(token);
    if (!userId) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }

    let currentUser = null;
    for (const [username, user] of users.entries()) {
        if (user.userId === userId) {
            currentUser = user;
            break;
        }
    }
    
    if (!currentUser) {
        return res.status(404).json({ error: 'User not found' });
    }

    req.userId = userId;
    req.currentUser = currentUser;
    next();
};

// Add contact endpoint
app.post('/api/add-contact', authenticateToken, async (req, res) => {
    // If authenticateToken was used, req.currentUser is available
    let currentUser = req.currentUser;
    const { token, contactUsername } = req.body;
    
    // Fallback if token was in body
    if (!currentUser) {
        const userId = verifyToken(token);
        if (!userId) return res.status(401).json({ error: 'Invalid token' });
        for (const [username, user] of users.entries()) {
            if (user.userId === userId) {
                currentUser = user;
                break;
            }
        }
        if (!currentUser) return res.status(404).json({ error: 'User not found' });
    }

    const cleanContactUsername = contactUsername.trim().toLowerCase();
    
    if (!users.has(cleanContactUsername)) {
        return res.status(404).json({ error: 'Contact username does not exist' });
    }
    
    if (currentUser.username === cleanContactUsername) {
        return res.status(400).json({ error: 'Cannot add yourself as a contact' });
    }

    if (currentUser.contacts.includes(cleanContactUsername)) {
        return res.status(400).json({ error: 'Contact already added' });
    }
    
    currentUser.contacts.push(cleanContactUsername);
    saveData();
    
    res.json({ success: true, message: 'Contact added successfully' });
});

// Get contacts endpoint
app.post('/api/get-contacts', authenticateToken, async (req, res) => {
    let currentUser = req.currentUser;
    const { token } = req.body;
    
    // Fallback if token was in body
    if (!currentUser) {
        const userId = verifyToken(token);
        if (!userId) return res.status(401).json({ error: 'Invalid token' });
        for (const [username, user] of users.entries()) {
            if (user.userId === userId) {
                currentUser = user;
                break;
            }
        }
        if (!currentUser) return res.status(404).json({ error: 'User not found' });
    }

    const contacts = currentUser.contacts.map(contactUsername => {
        const contact = users.get(contactUsername);
        return {
            username: contactUsername,
            online: contact ? contact.online : false,
            userId: contact ? contact.userId : null
        };
    });
    
    res.json({ contacts });
});

// File upload endpoint (Assuming this was an endpoint from previous fix)
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const fileInfo = {
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        url: `/uploads/${req.file.filename}` 
    };

    res.json({ 
        success: true,
        file: fileInfo
    });
});


// Socket.io connection handling
io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);
    
    let currentUserId = null;
    let currentUsername = null;

    socket.on('authenticate', async (data) => {
        const { token } = data;
        
        const userId = verifyToken(token);
        if (!userId) {
            socket.emit('auth-failed', { error: 'Invalid token' });
            return;
        }
        
        let user = null;
        for (const [username, userData] of users.entries()) {
            if (userData.userId === userId) {
                user = userData;
                currentUsername = username;
                break;
            }
        }
        
        if (!user) {
            socket.emit('auth-failed', { error: 'User not found' });
            return;
        }
        
        // FIX: The user should join a room named after their username for reliable messaging across multiple tabs
        socket.join(currentUsername); 
        
        user.socketId = socket.id; // Keep for tracking one active socket if needed, but rely on rooms for delivery
        user.online = true;
        currentUserId = userId;
        
        const userChats = [];
        const contactUsernames = new Set(user.contacts); 
        
        for (const [chatId, chat] of chats.entries()) {
            if (chat.participants.includes(currentUsername)) {
                const otherParticipant = chat.participants.find(p => p !== currentUsername);
                
                // Only show chats with actual contacts
                if (contactUsernames.has(otherParticipant)) {
                    const chatMessages = messages.get(chatId) || [];
                    const lastMessage = chatMessages[chatMessages.length - 1];
                    const otherUser = users.get(otherParticipant);
                    
                    userChats.push({
                        chatId,
                        name: otherParticipant,
                        type: chat.type,
                        participants: chat.participants,
                        // Include the senderUsername for proper client-side message preview
                        lastMessage: lastMessage ? {
                            senderUsername: lastMessage.senderUsername, 
                            text: lastMessage.text,
                            file: lastMessage.file,
                            time: lastMessage.timestamp
                        } : null,
                        online: otherUser ? otherUser.online : false,
                        unread: 0 
                    });
                }
            }
        }
        
        socket.emit('auth-success', {
            userId,
            username: currentUsername,
            chats: userChats,
            contacts: user.contacts
        });
        
        // FIX: Broadcast online status to the contact's room, not just a single socketId
        user.contacts.forEach(contactUsername => {
            io.to(contactUsername).emit('contact-online', { 
                username: currentUsername 
            });
        });
        
        saveData();
        console.log(`User authenticated: ${currentUsername} (${userId})`);
    });

    // UPDATED: Handler for loading the latest batch of messages (initial load)
    socket.on('get-messages', (data) => {
        const { chatId } = data; 
        
        if (!currentUsername || !chatId) return;
        
        const chatMessages = messages.get(chatId) || [];
        
        const totalMessages = chatMessages.length;
        // Start index is the total number of messages minus the limit, ensuring we get the latest batch
        const startIndex = Math.max(0, totalMessages - MESSAGE_LIMIT);
        const messagesToSend = chatMessages.slice(startIndex, totalMessages);

        // Map messages for client consumption, ensuring 'sent' status is correct
        const mappedMessages = messagesToSend.map(msg => ({
            ...msg, 
            sent: msg.senderUsername === currentUsername
        }));

        socket.emit('messages-loaded', {
            chatId,
            messages: mappedMessages,
            totalMessages,
            hasMore: totalMessages > MESSAGE_LIMIT
        });
    });

    // NEW: Handler for loading older messages (scroll up functionality)
    socket.on('get-older-messages', (data) => {
        const { chatId, offset } = data; // offset is the number of messages already loaded (50, 100, 150, ...)
        
        if (!currentUsername || !chatId || typeof offset !== 'number') return;
        
        const chatMessages = messages.get(chatId) || [];
        const totalMessages = chatMessages.length;
        
        // Calculate the end index (total messages - messages already loaded)
        const endIndex = totalMessages - offset;
        
        // Calculate the start index for the next batch (endIndex - MESSAGE_LIMIT)
        const startIndex = Math.max(0, endIndex - MESSAGE_LIMIT);
        
        // Slice the messages for the batch
        const messagesToSend = chatMessages.slice(startIndex, endIndex);

        const mappedMessages = messagesToSend.map(msg => ({
            ...msg, 
            sent: msg.senderUsername === currentUsername
        }));

        socket.emit('older-messages-loaded', {
            chatId,
            messages: mappedMessages,
            // The new offset is the old offset plus the number of messages just sent
            offset: offset + messagesToSend.length, 
            // Are there messages before this batch? (Is the startIndex greater than 0?)
            hasMore: startIndex > 0 
        });
    });

    socket.on('send-message', (data) => {
        const { chatId, text, file } = data; 
        
        if (!currentUsername || !chatId) return;
        if (!text && !file) return;
        
        const chat = chats.get(chatId);
        if (!chat || !chat.participants.includes(currentUsername)) return;
        
        const currentUser = users.get(currentUsername);
        const otherParticipant = chat.participants.find(p => p !== currentUsername);
        
        // Security check: ensure participant is a contact
        if (!currentUser.contacts.includes(otherParticipant)) {
            socket.emit('message-error', { error: 'Cannot send message to non-contact' });
            return;
        }
        
        const message = {
            id: generateId(),
            chatId,
            senderUsername: currentUsername,
            text: text ? text.trim() : '',
            file: file,
            timestamp: Date.now(),
            read: false
        };
        
        const chatMessages = messages.get(chatId) || [];
        chatMessages.push(message);
        messages.set(chatId, chatMessages);
        saveData();
        
        // FIX: Broadcast the message to all participants' rooms (i.e., all their tabs)
        chat.participants.forEach(participantUsername => {
            const participant = users.get(participantUsername);
            
            if (participant && participant.online) {
                // Use room for sending message
                io.to(participantUsername).emit('new-message', { 
                    chatId,
                    message: {
                        id: message.id,
                        text: message.text,
                        file: message.file,
                        senderUsername: message.senderUsername,
                        timestamp: message.timestamp,
                        sent: participantUsername === currentUsername
                    }
                });
            }
        });
        
        console.log(`Message sent in chat ${chatId} by ${currentUsername}`);
    });

    socket.on('disconnect', () => {
        if (currentUsername) {
            const user = users.get(currentUsername);
            
            if (user) {
                // FIX: Leave the room
                socket.leave(currentUsername); 
                
                // Check if any other socket is still connected to the user's room
                // If there are no other sockets in the room, the user is truly offline
                const isStillOnline = io.sockets.adapter.rooms.get(currentUsername) && io.sockets.adapter.rooms.get(currentUsername).size > 0;

                if (!isStillOnline) {
                    user.online = false;
                    user.socketId = null; // Only clear if completely offline

                    // FIX: Broadcast offline status to contacts using rooms
                    user.contacts.forEach(contactUsername => {
                        io.to(contactUsername).emit('contact-offline', {
                            username: currentUsername
                        });
                    });
                    
                    saveData();
                    console.log(`User completely disconnected: ${currentUsername}`);
                } else {
                    console.log(`Tab disconnected for ${currentUsername}, but other tabs are still active.`);
                }
            }
        }
        console.log('Client disconnected:', socket.id);
    });

    socket.on('typing', (data) => {
        const { chatId, isTyping } = data;
        
        if (!currentUsername || !chatId) return;
        
        const chat = chats.get(chatId);
        if (!chat) return;
        
        chat.participants.forEach(participantUsername => {
            if (participantUsername !== currentUsername) {
                const participant = users.get(participantUsername);
                // FIX: Use room for sending typing indicator
                if (participant && participant.online && participant.contacts.includes(currentUsername)) {
                    io.to(participantUsername).emit('user-typing', {
                        chatId,
                        username: currentUsername,
                        isTyping
                    });
                }
            }
        });
    });

    socket.on('start-chat', (data) => {
        const { targetUsername } = data;
        
        if (!currentUsername || !targetUsername) return;
        
        const currentUser = users.get(currentUsername);
        const targetUser = users.get(targetUsername);
        
        if (!currentUser || !targetUser) return;
        
        if (!currentUser.contacts.includes(targetUsername)) {
            socket.emit('chat-error', { error: 'User is not in your contacts' });
            return;
        }
        
        const chatId = getChatId(currentUsername, targetUsername);
        
        let chat = chats.get(chatId);

        if (!chat) {
            chat = {
                participants: [currentUsername, targetUsername],
                type: 'private',
                createdAt: Date.now()
            };
            chats.set(chatId, chat);
            messages.set(chatId, []);
            saveData();
        }
        
        // Determine last message for the response
        const chatMessages = messages.get(chatId) || [];
        const lastMessage = chatMessages[chatMessages.length - 1];

        socket.emit('chat-started', {
            chatId,
            name: targetUsername,
            type: 'private',
            participants: [currentUsername, targetUsername],
            online: targetUser.online,
            // DO NOT send all messages here. The client will request them via 'get-messages'
            messages: [], 
            // Include last message in chat-started for consistency
            lastMessage: lastMessage ? {
                senderUsername: lastMessage.senderUsername,
                text: lastMessage.text,
                file: lastMessage.file,
                time: lastMessage.timestamp
            } : null
        });
        
        // Notify the target user using their room
        if (targetUser.contacts.includes(currentUsername)) {
             io.to(targetUser.username).emit('new-chat', {
                chatId,
                name: currentUsername,
                type: 'private',
                participants: [currentUsername, targetUsername],
                online: true,
                lastMessage: lastMessage ? {
                    senderUsername: lastMessage.senderUsername,
                    text: lastMessage.text,
                    file: lastMessage.file,
                    time: lastMessage.timestamp
                } : null
            });
        }
    });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok',
        users: users.size,
        chats: chats.size,
        messages: Array.from(messages.values()).reduce((sum, msgs) => sum + msgs.length, 0),
        authenticated: true
    });
});

// Serve the frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Express Error:', error.message);
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large. Maximum size is 10MB' });
        }
    }
    if (error.message === 'Invalid file type') {
         return res.status(400).json({ error: error.message });
    }
    res.status(500).json({ error: 'Server error: ' + error.message });
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n💾 Saving data before shutdown...');
    saveData();
    process.exit(0);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 WhatsApp Clone Server running on port ${PORT}`);
    console.log(`🔐 Authentication enabled with password protection`);
    console.log(`👥 Contact list feature enabled`);
    console.log(`💾 Data persistence enabled`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
});
