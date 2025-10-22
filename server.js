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

// JWT Secret (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
// Max file size for multer (10MB)
const MAX_FILE_SIZE = 10 * 1024 * 1024;

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
        // Ensure the path is correct
        cb(null, uploadsDir + '/') 
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')); // Sanitize filename
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: MAX_FILE_SIZE
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip|mp4|mp3|webm/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        // Stricter Mime-type check
        const allowedMime = allowedTypes.test(file.mimetype.toLowerCase()); 
        
        // Check for both extension and mimetype
        if (extname && allowedMime) {
            return cb(null, true);
        } else {
            cb(new Error('Invalid file type or format'));
        }
    }
});

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static(uploadsDir)); // Use uploadsDir variable

// In-memory storage with persistence
let users = new Map();
let messages = new Map();
let chats = new Map();
// NEW: A map for fast lookup by userId (for REST/middleware)
let usersByUserId = new Map(); 
// sessions map remains for JWT to userId mapping on server side (optional, but kept for consistency)
let sessions = new Map(); 

// Load data from files if they exist
function loadData() {
    try {
        if (fs.existsSync(path.join(dataDir, 'users.json'))) {
            const usersData = JSON.parse(fs.readFileSync(path.join(dataDir, 'users.json'), 'utf8'));
            users = new Map(usersData);
            // REBUILD usersByUserId map on load
            users.forEach(user => {
                usersByUserId.set(user.userId, user);
            });
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

// NEW: Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    // Extract token from 'Bearer <token>'
    const token = authHeader && authHeader.split(' ')[1]; 

    if (token == null) {
        return res.status(401).json({ error: 'Authentication token required' });
    }

    const userId = verifyToken(token);
    if (!userId) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }

    const currentUser = usersByUserId.get(userId);
    if (!currentUser) {
        return res.status(404).json({ error: 'User not found' });
    }

    req.userId = userId;
    req.currentUser = currentUser;
    next();
};

// REST API Endpoints

// Register endpoint
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Trim and normalize username
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
    
    const newUser = {
        userId,
        password: hashedPassword,
        username: cleanUsername,
        contacts: [],
        createdAt: Date.now(),
        online: false,
        socketId: null
    };

    users.set(cleanUsername, newUser);
    // NEW: Add to lookup map
    usersByUserId.set(userId, newUser); 
    
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

// NEW: File upload endpoint
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Construct the file information object
    const fileInfo = {
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        url: `/uploads/${req.file.filename}` // Client can access this URL
    };

    res.json({ 
        success: true,
        file: fileInfo
    });
});


// Add contact endpoint - NOW uses authenticateToken middleware
app.post('/api/add-contact', authenticateToken, async (req, res) => {
    const { contactUsername } = req.body;
    // User is available via req.currentUser from the middleware
    const currentUser = req.currentUser;
    
    if (!contactUsername) {
        return res.status(400).json({ error: 'Contact username is required' });
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

// Get contacts endpoint - NOW uses authenticateToken middleware
app.post('/api/get-contacts', authenticateToken, async (req, res) => {
    // User is available via req.currentUser from the middleware
    const currentUser = req.currentUser;
    
    const contacts = currentUser.contacts.map(contactUsername => {
        const contact = users.get(contactUsername);
        return {
            username: contactUsername,
            // Safety check for case where contact might have been deleted but user list not cleaned up
            online: contact ? contact.online : false, 
            userId: contact ? contact.userId : null
        };
    }).filter(contact => contact.userId !== null); // Filter out null contacts
    
    res.json({ contacts });
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
        
        // Use the new lookup map for O(1) performance
        const user = usersByUserId.get(userId);
        
        if (!user) {
            socket.emit('auth-failed', { error: 'User not found' });
            return;
        }
        
        // Set user details and status
        user.socketId = socket.id;
        user.online = true;
        currentUserId = userId;
        currentUsername = user.username; // Assign the username

        // Join a room specific to the user for easy direct messaging
        socket.join(currentUsername); 
        
        const userChats = [];
        // Use user.contacts for the filter
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
                        lastMessage: lastMessage ? {
                            text: lastMessage.text || (lastMessage.file ? '📎 File' : ''),
                            time: lastMessage.timestamp
                        } : null,
                        online: otherUser ? otherUser.online : false,
                        unread: 0 // In a real app, this would be calculated
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
        
        // Broadcast online status to contacts
        user.contacts.forEach(contactUsername => {
            // Use rooms for efficient broadcasting
            io.to(contactUsername).emit('contact-online', { 
                username: currentUsername 
            });
        });
        
        saveData();
        console.log(`User authenticated: ${currentUsername} (${userId})`);
    });

    socket.on('get-contacts', () => {
        if (!currentUsername) return;
        
        const user = users.get(currentUsername);
        if (!user) return;
        
        const contactsList = user.contacts.map(contactUsername => {
            const contact = users.get(contactUsername);
            return {
                username: contactUsername,
                online: contact ? contact.online : false,
                userId: contact ? contact.userId : null
            };
        }).filter(contact => contact.userId !== null);
        
        socket.emit('contacts-list', contactsList);
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
        
        if (!chats.has(chatId)) {
            chats.set(chatId, {
                participants: [currentUsername, targetUsername],
                type: 'private',
                createdAt: Date.now()
            });
            messages.set(chatId, []);
            saveData();
        }
        
        socket.emit('chat-started', {
            chatId,
            name: targetUsername,
            type: 'private',
            participants: [currentUsername, targetUsername],
            online: targetUser.online,
            messages: messages.get(chatId) || []
        });
        
        // Notify the target user using their room
        if (targetUser.contacts.includes(currentUsername)) {
             io.to(targetUser.username).emit('new-chat', {
                chatId,
                name: currentUsername,
                type: 'private',
                participants: [currentUsername, targetUsername],
                online: true
            });
        }
    });

    socket.on('send-message', (data) => {
        // file is now expected to be a fileInfo object (from REST upload) or null
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
        
        // Sanitize file object
        const finalFile = file && file.url && file.filename ? file : null;

        const message = {
            id: generateId(),
            chatId,
            senderUsername: currentUsername,
            text: text ? text.trim() : '',
            file: finalFile,
            timestamp: Date.now(),
            read: false
        };
        
        const chatMessages = messages.get(chatId) || [];
        chatMessages.push(message);
        messages.set(chatId, chatMessages);
        saveData();
        
        chat.participants.forEach(participantUsername => {
            const participant = users.get(participantUsername);
            // Use room for sending message
            if (participant && participant.online) {
                // Only send to participant if they are the sender, or if they have the sender as a contact
                if (participantUsername === currentUsername || participant.contacts.includes(currentUsername)) {
                    io.to(participant.username).emit('new-message', { 
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
            }
        });
        
        console.log(`Message sent in chat ${chatId} by ${currentUsername}`);
    });
    
    // REMOVED 'upload-file' event logic (now handled by REST API)

    socket.on('add-contact', async (data) => {
        const { contactUsername } = data;
        
        if (!currentUsername) return;
        
        const currentUser = users.get(currentUsername);
        if (!currentUser) return;
        
        const cleanContactUsername = contactUsername.trim().toLowerCase();
        
        if (!users.has(cleanContactUsername)) {
            socket.emit('contact-error', { error: 'User does not exist' });
            return;
        }
        
        if (currentUser.contacts.includes(cleanContactUsername)) {
            socket.emit('contact-error', { error: 'Already in contacts' });
            return;
        }
        
        if (currentUser.username === cleanContactUsername) {
            socket.emit('contact-error', { error: 'Cannot add yourself' });
            return;
        }

        currentUser.contacts.push(cleanContactUsername);
        saveData();
        
        const contact = users.get(cleanContactUsername);
        
        socket.emit('contact-added', {
            username: cleanContactUsername,
            online: contact ? contact.online : false,
            userId: contact ? contact.userId : null
        });

        // Notify the newly added contact if they are online and the sender is in their contacts
        if (contact && contact.online && contact.contacts.includes(currentUsername)) {
             io.to(contact.username).emit('contact-added-by-other', {
                username: currentUsername,
                online: currentUser.online,
                userId: currentUser.userId
            });
        }
        
        console.log(`${currentUsername} added ${cleanContactUsername} as contact`);
    });

    socket.on('remove-contact', async (data) => {
        const { contactUsername } = data;
        
        if (!currentUsername) return;
        
        const currentUser = users.get(currentUsername);
        if (!currentUser) return;
        
        const cleanContactUsername = contactUsername.trim().toLowerCase();

        currentUser.contacts = currentUser.contacts.filter(c => c !== cleanContactUsername);
        saveData();
        
        socket.emit('contact-removed', { username: cleanContactUsername });
        
        console.log(`${currentUsername} removed ${cleanContactUsername} from contacts`);
    });

    socket.on('typing', (data) => {
        const { chatId, isTyping } = data;
        
        if (!currentUsername || !chatId) return;
        
        const chat = chats.get(chatId);
        if (!chat) return;
        
        chat.participants.forEach(participantUsername => {
            if (participantUsername !== currentUsername) {
                const participant = users.get(participantUsername);
                // Use room for sending typing indicator
                if (participant && participant.online && participant.contacts.includes(currentUsername)) {
                    io.to(participant.username).emit('user-typing', {
                        chatId,
                        username: currentUsername,
                        isTyping
                    });
                }
            }
        });
    });

    socket.on('get-messages', (data) => {
        const { chatId } = data;
        
        if (!currentUsername || !chatId) return;
        
        const chat = chats.get(chatId);
        if (!chat || !chat.participants.includes(currentUsername)) return;
        
        const currentUser = users.get(currentUsername);
        const otherParticipant = chat.participants.find(p => p !== currentUsername);
        
        if (!currentUser.contacts.includes(otherParticipant)) {
            socket.emit('messages-error', { error: 'Cannot access messages with non-contact' });
            return;
        }
        
        const chatMessages = messages.get(chatId) || [];
        
        socket.emit('messages-loaded', {
            chatId,
            messages: chatMessages.map(msg => ({
                id: msg.id,
                text: msg.text,
                file: msg.file,
                senderUsername: msg.senderUsername,
                timestamp: msg.timestamp,
                sent: msg.senderUsername === currentUsername
            }))
        });
    });

    socket.on('disconnect', () => {
        if (currentUsername) {
            const user = users.get(currentUsername);
            if (user) {
                user.online = false;
                user.socketId = null;
                // Leave the room
                socket.leave(currentUsername); 
                
                // Broadcast offline status to contacts using rooms
                user.contacts.forEach(contactUsername => {
                    io.to(contactUsername).emit('contact-offline', {
                        username: currentUsername
                    });
                });
                
                saveData();
                console.log(`User disconnected: ${currentUsername}`);
            }
        }
        console.log('Client disconnected:', socket.id);
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
            return res.status(400).json({ error: `File too large. Maximum size is ${MAX_FILE_SIZE / (1024 * 1024)}MB` });
        }
    }
    // Handle the custom Invalid file type error
    if (error.message === 'Invalid file type' || error.message === 'Invalid file type or format') {
        return res.status(400).json({ error: error.message });
    }
    // Default to 500
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
    console.log(`📎 File upload feature enabled (REST API)`); // Updated
    console.log(`💾 Data persistence enabled`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
});
