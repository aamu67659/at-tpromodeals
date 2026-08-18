const fs = require('fs').promises;
const fssync = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Storage root — Render persistent disk at /data, else ./data
// ---------------------------------------------------------------------------
const PERSISTENT_DATA_DIR = '/data';
const LOCAL_DATA_DIR = path.join(__dirname, 'data');
const DATA_DIR = fssync.existsSync(PERSISTENT_DATA_DIR) ? PERSISTENT_DATA_DIR : LOCAL_DATA_DIR;

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ADMIN_BLOCKS_FILE = path.join(DATA_DIR, 'admin-blocklists.json');

// Files larger than this (8 MiB) are rejected to prevent OOM via crafted JSON.
const MAX_USERS_FILE_BYTES = 8 * 1024 * 1024;

console.log(`[DB] Using data directory: ${DATA_DIR}`);

if (!fssync.existsSync(DATA_DIR)) {
    try { fssync.mkdirSync(DATA_DIR, { recursive: true }); } catch (err) {
        console.error(`Error creating data directory ${DATA_DIR}:`, err);
    }
}

function ensureFile(file, fallback) {
    if (!fssync.existsSync(file)) {
        fssync.writeFileSync(file, JSON.stringify(fallback, null, 2));
    }
}
ensureFile(USERS_FILE, []);
ensureFile(ADMIN_BLOCKS_FILE, { ips: [], isps: [], countries: [] });

// ---------------------------------------------------------------------------
// Safe JSON parse: enforces byte cap + safe parse; returns fallback on any error.
// ---------------------------------------------------------------------------
function safeParseLimited(buf, fallback, maxBytes) {
    if (!buf || buf.length > maxBytes) return fallback;
    try {
        // `__proto__` is the canonical prototype-pollution sink. JSON.parse
        // (without reviver) sets it as an own data property which can leak
        // through spread into Object.prototype. Drop those keys explicitly.
        const parsed = JSON.parse(buf, (key, value) => {
            if (key === '__proto__' || key === 'prototype' || key === 'constructor') {
                return undefined;
            }
            return value;
        });
        return parsed == null || typeof parsed !== 'object' ? fallback : parsed;
    } catch (_) { return fallback; }
}

// ---------------------------------------------------------------------------
// Atomic write: write to .tmp + fsync + rename. Survives crashes mid-write.
// ---------------------------------------------------------------------------
async function atomicWriteJSON(filePath, value) {
    const tmp = filePath + '.tmp';
    const data = JSON.stringify(value); // minified payload, smaller + faster
    const fh = await fs.open(tmp, 'w');
    try {
        await fh.writeFile(data, 'utf8');
        await fh.sync();
    } finally {
        await fh.close();
    }
    await fs.rename(tmp, filePath);
}

// ---------------------------------------------------------------------------
// Write mutex: serializes file writes per file to prevent readers seeing
// torn writes during concurrent updates.
// ---------------------------------------------------------------------------
const _writeQueues = new Map();
function withFileLock(filePath, fn) {
    const prev = _writeQueues.get(filePath) || Promise.resolve();
    const next = prev.then(fn, fn);
    _writeQueues.set(filePath, next.catch(() => {}));
    return next;
}

// ---------------------------------------------------------------------------
// IP rule helpers: exact / wildcard / CIDR matching for IPv4 & IPv6
// ---------------------------------------------------------------------------
function ipv4ToInt(addr) {
    const parts = String(addr).split('.');
    if (parts.length !== 4) return null;
    let acc = 0;
    for (const p of parts) {
        if (p === '*') return null;
        const n = Number(p);
        if (!Number.isInteger(n) || n < 0 || n > 255) return null;
        acc = (acc * 256) + n;
    }
    return acc >>> 0;
}

function ipv6ToBigInt(addr) {
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
    if (typeof value !== 'string' || !value) return null;
    const v = value.trim();
    if (v.includes('*')) return /^\d{1,3}(\.\d{1,3}){3}$/.test(v.replace(/\*/g, '0')) ? 'wildcard' : null;
    if (v.includes('/')) {
        const [base, maskRaw] = v.split('/');
        if (!maskRaw || !/^\d{1,3}$/.test(maskRaw)) return null;
        const mask = parseInt(maskRaw, 10);
        if (!isValidIpLiteral(base)) return null;
        if (base.includes(':')) { if (mask < 0 || mask > 128) return null; }
        else { if (mask < 0 || mask > 32) return null; }
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

// ---------------------------------------------------------------------------
// IP block index: pre-categorise by rule kind for O(1) exact match + O(N) CIDR/wildcard
// ---------------------------------------------------------------------------
function buildIpBlockIndex(blocksArr) {
    const index = { exactSet: new Set(), cidr: [], wildcard: [] };
    if (!Array.isArray(blocksArr)) return index;
    for (const e of blocksArr) {
        if (!e || !e.value) continue;
        const kind = e.rule || ipRuleKind(e.value) || 'exact';
        if (kind === 'exact') index.exactSet.add(e.value);
        else if (kind === 'cidr') index.cidr.push(e);
        else if (kind === 'wildcard') index.wildcard.push(e);
    }
    return index;
}

function ipMatchesIndex(clientIp, index) {
    if (!clientIp || !index) return null;
    if (index.exactSet.has(clientIp)) return { value: clientIp, rule: 'exact' };
    for (const e of index.cidr) {
        if (ipMatchesRule(clientIp, e.value)) return e;
    }
    for (const e of index.wildcard) {
        if (ipMatchesRule(clientIp, e.value)) return e;
    }
    return null;
}

// ---------------------------------------------------------------------------
// ISO 3166-1 alpha-2 country registry
// ---------------------------------------------------------------------------
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
    ['ZA', 'South Africa'], ['ZW', 'Zimbabwe'], ['AO', 'Angola'], ['TZ', 'Tanzania'],
    ['UG', 'Uganda'], ['BR', 'Brazil'], ['AR', 'Argentina'], ['CL', 'Chile'], ['CO', 'Colombia'],
    ['PE', 'Peru'], ['VE', 'Venezuela'], ['EC', 'Ecuador'], ['BO', 'Bolivia'], ['UY', 'Uruguay'],
    ['PY', 'Paraguay'], ['MX', 'Mexico'], ['CR', 'Costa Rica'], ['PA', 'Panama'], ['CU', 'Cuba'],
    ['DO', 'Dominican Republic'], ['GT', 'Guatemala'], ['HN', 'Honduras'], ['SV', 'El Salvador'],
    ['NI', 'Nicaragua'], ['PR', 'Puerto Rico'], ['JM', 'Jamaica'], ['TT', 'Trinidad and Tobago'],
    ['BS', 'Bahamas'], ['BZ', 'Belize'], ['NZ', 'New Zealand'], ['FJ', 'Fiji'], ['PG', 'Papua New Guinea'],
    ['WS', 'Samoa'], ['TO', 'Tonga'], ['AD', 'Andorra'], ['MC', 'Monaco'], ['SM', 'San Marino'],
    ['VA', 'Vatican City'], ['LI', 'Liechtenstein'], ['AM', 'Armenia'], ['AZ', 'Azerbaijan'],
    ['GE', 'Georgia'], ['KZ', 'Kazakhstan'], ['UZ', 'Uzbekistan'], ['TM', 'Turkmenistan'],
    ['KG', 'Kyrgyzstan'], ['TJ', 'Tajikistan'], ['AF', 'Afghanistan'], ['MM', 'Myanmar'],
    ['KH', 'Cambodia'], ['LA', 'Laos'], ['BN', 'Brunei'], ['TL', 'Timor-Leste'], ['MV', 'Maldives'],
    ['BT', 'Bhutan'], ['PS', 'Palestine'], ['UN', 'Unknown']
].map(([code, name]) => ({ code, name }));

const ISO_COUNTRY_BY_CODE = (() => {
    const map = {};
    for (const c of ISO_COUNTRIES) map[c.code] = c.name;
    return map;
})();

// ---------------------------------------------------------------------------
// Admin blocklists — atomic, categorised index
// ---------------------------------------------------------------------------
const VALID_BLOCK_TYPES = new Set(['ips', 'isps', 'countries']);

let _blocksCacheRaw = null;
let _blocksCacheMtime = 0;
let _blocksCacheParsed = { ips: [], isps: [], countries: [] };
let _blockIndex = { ips: buildIpBlockIndex([]), countries: new Set(), ispsLower: [] };

async function readAdminBlocks({ skipCache = false } = {}) {
    const stat = await fs.stat(ADMIN_BLOCKS_FILE).catch(() => null);
    if (!skipCache && _blocksCacheRaw && stat && stat.mtimeMs === _blocksCacheMtime) {
        return _blocksCacheParsed;
    }
    const buf = await fs.readFile(ADMIN_BLOCKS_FILE, 'utf8');
    const parsed = safeParseLimited(buf, { ips: [], isps: [], countries: [] }, MAX_USERS_FILE_BYTES);
    const safe = {
        ips: Array.isArray(parsed.ips) ? parsed.ips : [],
        isps: Array.isArray(parsed.isps) ? parsed.isps : [],
        countries: Array.isArray(parsed.countries) ? parsed.countries : []
    };
    _blocksCacheRaw = safe;
    _blocksCacheMtime = stat ? stat.mtimeMs : 0;
    _blocksCacheParsed = safe;
    rebuildBlockIndex(safe);
    return safe;
}

function rebuildBlockIndex(blocks) {
    _blockIndex = {
        ips: buildIpBlockIndex(blocks.ips || []),
        countries: new Set((blocks.countries || []).map(c => String(c.value || '').toUpperCase())),
        ispsLower: (blocks.isps || []).map(b => String(b.value || '').toLowerCase())
    };
}

async function writeAdminBlocks(blocks) {
    const safe = {
        ips: Array.isArray(blocks.ips) ? blocks.ips : [],
        isps: Array.isArray(blocks.isps) ? blocks.isps : [],
        countries: Array.isArray(blocks.countries) ? blocks.countries : []
    };
    await withFileLock(ADMIN_BLOCKS_FILE, () => atomicWriteJSON(ADMIN_BLOCKS_FILE, safe));
    // Force a reload on next read so index stays accurate.
    _blocksCacheMtime = 0;
    _blocksCacheRaw = null;
    await readAdminBlocks();
}

async function addAdminBlock(type, value, reason, addedBy = 'ADMIN') {
    if (!VALID_BLOCK_TYPES.has(type)) throw new Error('Invalid block type');
    const blocks = await readAdminBlocks();
    const v = typeof value === 'string' ? value.trim() : '';
    if (!v) throw new Error('EMPTY_VALUE');
    const dup = blocks[type].some(b => String(b.value || '').toLowerCase() === v.toLowerCase());
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
    if (!VALID_BLOCK_TYPES.has(type)) throw new Error('Invalid block type');
    const blocks = await readAdminBlocks();
    blocks[type] = (blocks[type] || []).filter(b => b.id !== id);
    await writeAdminBlocks(blocks);
    return blocks;
}

function getAdminBlockIndex()         { return _blockIndex; }
async function getAdminBlocksSnapshot(){ return await readAdminBlocks(); }

// ---------------------------------------------------------------------------
// Users: in-memory snapshot + indexes + serialised writes
// ---------------------------------------------------------------------------
let _usersSnapshot = null;

function rebuildUserIndex(users) {
    const idx = {
        byId: new Map(),
        byEmail: new Map(),
        slug: new Map(),
        count: users.length
    };
    for (const u of users) {
        if (!u || !u.id) continue;
        // Strip password + pinHash from the index copy so accidental leaks through
        // clone+spread never expose hashes.
        const safeClone = stripSecrets(u);
        idx.byId.set(u.id, safeClone);
        if (u.email) idx.byEmail.set(String(u.email).toLowerCase(), safeClone);
        if (u.slug) idx.slug.set(u.slug, { userId: u.id, base: true });
        for (const l of (u.links || [])) {
            if (l && l.slug) idx.slug.set(l.slug, { userId: u.id, linkSlug: l.slug });
        }
    }
    return idx;
}

let _userIndex = null;

function stripSecrets(u) {
    if (!u || typeof u !== 'object') return u;
    const out = { ...u };
    delete out.password;
    delete out.pinHash;
    return out;
}

// ---------------------------------------------------------------------------
// Username: lower-cased, 3-20 chars, [a-z0-9._-], edge chars must be
// alphanumeric. Legacy users get a deterministic username derived from
// their email local-part (with collision suffix) at snapshot load.
// ---------------------------------------------------------------------------
const USERNAME_RESERVED = new Set([
    'admin', 'administrator', 'root', 'system', 'support', 'api',
    'null', 'undefined', 'signup', 'login', 'dashboard', 'help'
]);

function normalizeUsername(raw) {
    if (typeof raw !== 'string') return '';
    return raw.trim().toLowerCase();
}

function isValidUsername(s) {
    if (!s || typeof s !== 'string') return false;
    if (s.length < 3 || s.length > 20) return false;
    if (USERNAME_RESERVED.has(s)) return false;
    return /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/.test(s);
}

function deriveUsername(user) {
    let base = '';
    if (user && user.email && typeof user.email === 'string') {
        const at = user.email.indexOf('@');
        base = at > 0 ? user.email.slice(0, at) : user.email;
    }
    if (!base && user && user.name && typeof user.name === 'string') {
        base = user.name;
    }
    if (!base || !base.trim()) base = 'user';
    let slug = String(base).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!slug) slug = 'user';
    if (!/^[a-z0-9]/.test(slug)) slug = 'u' + slug;
    if (slug.length < 3) slug = (slug + 'useruseruser').slice(0, 3);
    if (slug.length > 16) slug = slug.slice(0, 16);
    return slug;
}

function backfillUsernames(arr) {
    const taken = Object.create(null);
    let mutated = false;
    for (const u of arr) {
        if (u && typeof u.username === 'string' && u.username) {
            taken[u.username.toLowerCase()] = true;
        }
    }
    for (const u of arr) {
        if (!u || typeof u.username === 'string' && u.username) continue;
        const seed = deriveUsername(u);
        let candidate = seed;
        let attempt = 0;
        // Keep the suffix short — usernames max 20 chars total.
        const maxAttempts = 999;
        while (taken[candidate.toLowerCase()] && attempt < maxAttempts) {
            attempt++;
            const room = Math.max(3, 20 - String(attempt).length);
            candidate = (seed.length > room ? seed.slice(0, room) : seed) + String(attempt);
        }
        u.username = candidate;
        taken[candidate.toLowerCase()] = true;
        mutated = true;
    }
    return mutated;
}

async function ensureUserSnapshot({ force = false } = {}) {
    if (_usersSnapshot && !force) return _usersSnapshot;
    const buf = await fs.readFile(USERS_FILE, 'utf8');
    const parsed = safeParseLimited(buf, [], MAX_USERS_FILE_BYTES);
    const arr = Array.isArray(parsed) ? parsed : [];
    // Backfill usernames for legacy records created before username support.
    const mutated = backfillUsernames(arr);
    // Strip secrets in-place so we never carry them around even if a caller forgets.
    for (const u of arr) stripSecrets(u);
    _usersSnapshot = arr;
    _userIndex = rebuildUserIndex(arr);
    if (mutated) {
        // Persist the new usernames so they survive a server restart and the
        // user can log in via username after deploys.
        try {
            await withFileLock(USERS_FILE, () => atomicWriteJSON(USERS_FILE, arr));
        } catch (err) {
            console.warn('[db] Could not persist backfilled usernames:', err && err.message);
        }
    }
    return _usersSnapshot;
}

async function getUsers() {
    const snap = await ensureUserSnapshot();
    return snap;
}

async function getUserIndex() {
    await ensureUserSnapshot();
    return _userIndex;
}

async function saveUsers(users) {
    await withFileLock(USERS_FILE, () => atomicWriteJSON(USERS_FILE, users));
    _usersSnapshot = users;
    _userIndex = rebuildUserIndex(users);
}

async function createUser(userData) {
    const users = await getUsers();
    const newUser = {
        id: uuidv4(),
        slug: crypto.randomBytes(8).toString('hex'),       // bumped from 4 -> 8 bytes (collision-proof)
        username: userData.username,                        // lower-cased, validated
        name: userData.name,
        email: userData.email,
        telegram: userData.telegram,
        password: userData.password,                       // already bcrypt-hashed
        pinHash: userData.pinHash || null,
        wallet: 0.0,
        isActive: true,
        expiryDate: null,
        links: [],
        settings: {
            nonRealLink: '',
            realLink: '',
            antiRed: true,
            ispFilter: true,
            botFilter: true,
            reallowVisited: true,
            allowAfrica: false,
            allowEurope: true,
            botToken: '',
            chatId: '',
            mobileIsps: (process.env.MOBILE_ISPS || 'ATT, VERIZON, T-MOBILE, SPRINT, CRICKET, METROPCS').split(',').map(s => s.trim()).filter(Boolean)
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

// Returns the raw on-disk record (with password/pinHash intact) so internal
// endpoints like /api/login, /api/profile/pin, /api/forgot/reset can verify
// credentials. Callers that want to send the user to the browser MUST run
// stripSecrets() first.
async function findUserByEmail(email) {
    if (!email || typeof email !== 'string') return null;
    await ensureUserSnapshot();
    const lower = String(email).toLowerCase();
    return _usersSnapshot.find(u => u && u.email && String(u.email).toLowerCase() === lower) || null;
}

async function findUserById(id) {
    if (!id) return null;
    await ensureUserSnapshot();
    return _usersSnapshot.find(u => u && u.id === id) || null;
}

async function findUserByUsername(username) {
    if (!username || typeof username !== 'string') return null;
    await ensureUserSnapshot();
    const lower = String(username).toLowerCase();
    return _usersSnapshot.find(u => u && u.username && String(u.username).toLowerCase() === lower) || null;
}

// Accepts either an email (containing '@') or a username. Used by /api/login
// so the login form can present a single "email or username" field.
async function findUserByIdentifier(identifier) {
    if (!identifier || typeof identifier !== 'string') return null;
    await ensureUserSnapshot();
    const trimmed = identifier.trim();
    if (!trimmed) return null;
    const lower = trimmed.toLowerCase();
    if (trimmed.includes('@')) {
        return _usersSnapshot.find(u => u && u.email && String(u.email).toLowerCase() === lower) || null;
    }
    return _usersSnapshot.find(u => u && u.username && String(u.username).toLowerCase() === lower) || null;
}

async function findUserBySlug(slug) {
    if (!slug) return null;
    await ensureUserSnapshot();
    const hit = _userIndex.slug.get(slug);
    if (!hit) return null;
    const user = _userIndex.byId.get(hit.userId);
    if (!user) return null;
    let link = null;
    if (hit.linkSlug) {
        link = (user.links || []).find(l => l.slug === hit.linkSlug) || null;
    }
    return { user, link };
}

// Mutator path: reads snapshot, mutates, writes atomic file, refreshes indexes.
// The mutex stops concurrent writers from each reading the same baseline and
// racing each other.
async function updateUser(id, updates) {
    return await withFileLock(USERS_FILE, async () => {
        const buf = await fs.readFile(USERS_FILE, 'utf8');
        const parsed = safeParseLimited(buf, [], MAX_USERS_FILE_BYTES);
        const users = Array.isArray(parsed) ? parsed : [];
        const index = users.findIndex(u => u.id === id);
        if (index === -1) return null;
        users[index] = { ...users[index], ...updates };
        await atomicWriteJSON(USERS_FILE, users);
        _usersSnapshot = users;
        _userIndex = rebuildUserIndex(users);
        return stripSecrets(users[index]);
    });
}

async function deleteUser(id) {
    return await withFileLock(USERS_FILE, async () => {
        const buf = await fs.readFile(USERS_FILE, 'utf8');
        const parsed = safeParseLimited(buf, [], MAX_USERS_FILE_BYTES);
        const users = Array.isArray(parsed) ? parsed : [];
        const index = users.findIndex(u => u.id === id);
        if (index === -1) return null;
        const removed = users.splice(index, 1)[0];
        await atomicWriteJSON(USERS_FILE, users);
        _usersSnapshot = users;
        _userIndex = rebuildUserIndex(users);
        return stripSecrets(removed);
    });
}

async function isUsernameTaken(username, { excludeUserId } = {}) {
    if (!username || typeof username !== 'string') return false;
    await ensureUserSnapshot();
    const lower = username.toLowerCase();
    return _usersSnapshot.some(u =>
        u && u.username && String(u.username).toLowerCase() === lower &&
        (!excludeUserId || u.id !== excludeUserId)
    );
}

// Pick a free username near the seed. Returns the chosen string or null if
// the search space is exhausted after `maxAttempts` tries.
async function suggestAvailableUsername(seed, { excludeUserId } = {}) {
    if (!seed || typeof seed !== 'string') return null;
    await ensureUserSnapshot();
    const taken = new Set();
    for (const u of _usersSnapshot) {
        if (!u || !u.username) continue;
        if (excludeUserId && u.id === excludeUserId) continue;
        taken.add(String(u.username).toLowerCase());
    }
    const trimmed = seed.trim().toLowerCase();
    if (!taken.has(trimmed)) return trimmed;
    for (let i = 1; i < 1000; i++) {
        const suffix = String(i);
        const room = Math.max(3, 20 - suffix.length);
        const candidate = (trimmed.length > room ? trimmed.slice(0, room) : trimmed) + suffix;
        if (!taken.has(candidate)) return candidate;
    }
    return null;
}

module.exports = {
    DATA_DIR,
    USERS_FILE,
    ADMIN_BLOCKS_FILE,
    MAX_USERS_FILE_BYTES,
    normalizeUsername,
    isValidUsername,
    isUsernameTaken,
    suggestAvailableUsername,
    createUser,
    getUsers,
    getUserIndex,
    findUserByEmail,
    findUserById,
    findUserByUsername,
    findUserByIdentifier,
    findUserBySlug,
    updateUser,
    deleteUser,
    readAdminBlocks,
    writeAdminBlocks,
    addAdminBlock,
    removeAdminBlock,
    getAdminBlockIndex,
    getAdminBlocksSnapshot,
    VALID_BLOCK_TYPES,
    ipRuleKind,
    ipMatchesRule,
    ipMatchesAnyBlock,
    buildIpBlockIndex,
    ipMatchesIndex,
    ISO_COUNTRIES,
    ISO_COUNTRY_BY_CODE
};
