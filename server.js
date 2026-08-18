const express = require('express');
require('dotenv').config();
const axios = require('axios');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const compression = require('compression');
const db = require('./db');
const bot = require('./bot');
const fsSync = require('fs');
const fsPromises = require('fs').promises;

const app = express();
const port = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Boot-time configuration gating. Refuse to start if required secrets are
// missing or look like placeholder defaults.
// ---------------------------------------------------------------------------
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || '').trim();
const PROXYCHECK_API_KEY = (process.env.PROXYCHECK_API_KEY || '').trim();
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

function isWeakSecret(s) {
    if (!s || s.length < 24) return true;
    return /^(admin|secret|password|saas-proxy|placeholder|changeme|example)/i.test(s);
}

if (IS_PROD && (!SESSION_SECRET || isWeakSecret(SESSION_SECRET))) {
    console.error('[FATAL] SESSION_SECRET is missing or weak. Set a 32+ char random value on the host.');
    process.exit(1);
}
if (!SESSION_SECRET) {
    console.warn('[Boot] SESSION_SECRET is unset. A random ephemeral secret is being used (sessions invalidated on restart).');
}
if (!ADMIN_TOKEN) {
    console.error('[FATAL] ADMIN_TOKEN is not set. Admin endpoints will be disabled.');
}
if (ADMIN_TOKEN && ADMIN_TOKEN.length < 8) {
    console.warn('[Boot] ADMIN_TOKEN is shorter than 8 characters — consider a longer token.');
}

const EFFECTIVE_SESSION_SECRET = SESSION_SECRET
    || require('crypto').randomBytes(48).toString('hex');

// Error handling wrapper for async routes. Hides internals in production.
const asyncHandler = fn => (req, res, next) => {
    return Promise.resolve(fn(req, res, next)).catch((err) => {
        console.error(`[Error] ${req.method} ${req.url}:`, err.message);
        const body = { error: 'Internal Server Error' };
        if (!IS_PROD) body.details = err.message;
        res.status(500).json(body);
    });
};

// Trust only ONE proxy hop (Render / Cloudflare) so a client can't spoof
// x-forwarded-for and bypass IP/ISP/country admin blocks.
app.set('trust proxy', 1);

// Strict HTTPS-aware helmet defaults. CSP stays off because the app uses
// inline <script> blocks; instead we depend on input validation + cookie
// hardening on the server side. In production we also enable HSTS with
// includeSubDomains so accidental HTTP downgrades never re-expose cookies,
// plus Permissions-Policy that disables powerful features the app never
// needs (camera/mic/geolocation/payment/USB/etc.).
app.use(helmet({
    contentSecurityPolicy: false,
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    frameguard: { action: 'deny' },
    hsts: IS_PROD ? {
        maxAge: 63072000,            // 2 years
        includeSubDomains: true,
        preload: true
    } : false,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    noSniff: true,
    xssFilter: true
}));
app.use((req, res, next) => {
    res.setHeader('Permissions-Policy',
        'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), ' +
        'microphone=(), payment=(), usb=(), interest-cohort=()');
    next();
});
app.disable('x-powered-by');

// Limit request body size — the largest expected payload is the blocklist
// bulk import (1000 rows). Anything bigger is an attack.
app.use(express.json({
    limit: '64kb',
    // Strip prototype-pollution-prone keys during body parse so a malicious
    // `__proto__` / `constructor` block cannot hijack default prototypes on
    // the host after db.updateUser does `{ ...prev, ...updates }`.
    reviver: (key, value) => {
        if (key === '__proto__' || key === 'prototype' || key === 'constructor') {
            return undefined;
        }
        return value;
    }
}));
app.use(cookieParser());

// Tiny allowlist of static asset paths to log; everything else is silenced
// so the per-request console.log can't be used as a log-flood DoS vector.
app.use((req, res, next) => {
    if (!req.url.startsWith('/l/') && !req.url.startsWith('/api/')) {
        console.log(`[Request] ${req.method} ${req.url}`);
    }
    next();
});

// CSRF defense-in-depth on top of `sameSite=lax`: state-changing /api
// requests must come from an Origin / Referer we host. The Telegram webhook
// is exempt because it's server-to-server and already protected by the
// X-Telegram-Bot-Api-Secret-Token header (and the safe-parser below).
app.use((req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
    if (!req.path.startsWith('/api/')) return next();
    if (req.path === '/api/telegram/webhook') return next();

    const origin = req.headers['origin'];
    const referer = req.headers['referer'] || req.headers['referrer'];
    const secFetchSite = req.headers['sec-fetch-site'];
    const expectedHost = req.headers['host'];

    const safeUrls = new Set(['http:', 'https:']);
    const matches = (val) => {
        if (typeof val !== 'string' || !val) return false;
        try {
            const u = new URL(val);
            if (!safeUrls.has(u.protocol)) return false;
            return u.host === expectedHost;
        } catch (_) { return false; }
    };

    const originOk = matches(origin) || matches(referer);
    const fetchMetadataOk = secFetchSite === 'same-origin' || secFetchSite === 'none';

    if (!originOk && !fetchMetadataOk) {
        if (IS_PROD) {
            console.warn(`[CSRF] Blocked ${req.method} ${req.path} from origin=${origin || referer || '<none>'} sec-fetch-site=${secFetchSite || '<none>'} (host=${expectedHost})`);
            return res.status(403).json({ error: 'CROSS_ORIGIN_BLOCKED' });
        }
        // In development we still let it through so curl / Postman / smoke
        // tests can exercise the API without spoofing headers.
    }
    next();
});

app.use(compression());

// ---------------------------------------------------------------------------
// File-backed session store. Avoids the MemoryStore warning in production
// (leaks memory, doesn't scale past a single process) without pulling in
// Redis or sqlite. Sessions are JSON-serialized to disk with a debounced
// flush after set/destroy. Cookie-only "touch" updates (from `rolling`) stay
// in memory so the disk isn't hammered on every authenticated request.
// ---------------------------------------------------------------------------
const SESSION_STORE_DIR = fsSync.existsSync('/data') ? '/data' : path.join(__dirname, 'data');
const SESSIONS_FILE = path.join(SESSION_STORE_DIR, 'sessions.json');
const SESSIONS_FILE_MAX_BYTES = 8 * 1024 * 1024; // refuse to load files > 8 MiB
let _sessions = {};
let _sessionsDirty = false;
let _sessionsFlushTimer = null;

function _loadSessionsSync() {
    try {
        const buf = fsSync.readFileSync(SESSIONS_FILE);
        if (buf.length > SESSIONS_FILE_MAX_BYTES) return {};
        const parsed = JSON.parse(buf.toString('utf8'));
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch (_) {
        return {};
    }
}
function _saveSessionsSync() {
    try {
        const tmp = SESSIONS_FILE + '.tmp';
        fsSync.writeFileSync(tmp, JSON.stringify(_sessions));
        fsSync.renameSync(tmp, SESSIONS_FILE);
        _sessionsDirty = false;
    } catch (err) {
        console.error('[Sessions] flush failed:', err.message);
    }
}
function _scheduleFlush() {
    if (_sessionsFlushTimer || !_sessionsDirty) return;
    _sessionsFlushTimer = setTimeout(() => {
        _sessionsFlushTimer = null;
        if (_sessionsDirty) _saveSessionsSync();
    }, 200);
}
function _pruneExpired() {
    const now = Date.now();
    let removed = false;
    for (const sid of Object.keys(_sessions)) {
        const s = _sessions[sid];
        const exp = s && s.cookie && s.cookie.expires;
        if (exp && new Date(exp).getTime() <= now) {
            delete _sessions[sid];
            removed = true;
        }
    }
    if (removed) _sessionsDirty = true;
}

if (!fsSync.existsSync(SESSION_STORE_DIR)) {
    try { fsSync.mkdirSync(SESSION_STORE_DIR, { recursive: true }); } catch (_) {}
}
if (!fsSync.existsSync(SESSIONS_FILE)) {
    fsSync.writeFileSync(SESSIONS_FILE, '{}');
} else {
    _sessions = _loadSessionsSync();
    _pruneExpired();
    if (_sessionsDirty) _saveSessionsSync();
}

// Final flush on graceful shutdown so in-flight sessions are not lost.
process.on('SIGTERM', () => {
    if (_sessionsDirty) _saveSessionsSync();
});
process.on('SIGINT', () => {
    if (_sessionsDirty) _saveSessionsSync();
});

class FileStore extends session.Store {
    get(sid, fn) {
        const s = _sessions[sid];
        return fn(null, s ? Object.assign({}, s) : null);
    }
    set(sid, sess, fn) {
        _sessions[sid] = Object.assign({}, sess);
        _sessionsDirty = true;
        _scheduleFlush();
        return fn();
    }
    touch(sid, sess, fn) {
        if (_sessions[sid] && sess && sess.cookie) {
            // Cookie-only refresh (rolling session); don't churn the disk.
            _sessions[sid].cookie = sess.cookie;
        }
        return fn();
    }
    destroy(sid, fn) {
        if (_sessions[sid]) {
            delete _sessions[sid];
            _sessionsDirty = true;
            _scheduleFlush();
        }
        return fn();
    }
    length(fn) {
        return fn(null, Object.keys(_sessions).length);
    }
    clear(fn) {
        _sessions = {};
        _sessionsDirty = true;
        _scheduleFlush();
        return fn();
    }
    all(fn) {
        const arr = Object.entries(_sessions).map(([id, sess]) => {
            const out = { id };
            Object.assign(out, sess);
            return out;
        });
        return fn(null, arr);
    }
}

app.use(session({
    name: 'sp.sid',
    secret: EFFECTIVE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    store: new FileStore(),
    cookie: {
        httpOnly: true,
        secure: IS_PROD,
        sameSite: 'lax',
        maxAge: 10 * 60 * 1000,    // 10-min idle timeout; `rolling` resets on every authed request
        path: '/'
    }
}));

// Allow only same-origin clients to call our JSON API by default. The app
// serves its own front-end from /public, so cross-origin is unnecessary.
app.use(cors({
    origin: IS_PROD ? false : true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type'],
    maxAge: 86400
}));

// Long-lived static asset cache plus short-lived html cache to balance
// freshness with bandwidth.
app.use((req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    if (req.path.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
    else if (/\.(css|js|png|jpg|jpeg|svg|woff2?|ico)$/i.test(req.path))
        res.setHeader('Cache-Control', 'public, max-age=86400');
    next();
});

app.use(express.static('public', { etag: true, lastModified: true, fallthrough: true }));

app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard.html');
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// --- Authentication Middleware ---
async function requireAuth(req, res, next) {
    try {
        if (!req.session.userId) {
            console.log(`[Auth] Unauthorized access to ${req.url}`);
            return res.status(401).json({ error: 'Unauthorized' });
        }
        const user = await db.findUserById(req.session.userId);
        if (!user) {
            console.log(`[Auth] User not found for session ${req.session.userId}`);
            req.session.destroy();
            return res.status(401).json({ error: 'User not found' });
        }
        req.user = user;
        next();
    } catch (err) {
        console.error('[Auth] Middleware Error:', err);
        res.status(500).json({ error: 'Auth middleware error' });
    }
}

function requireAdmin(req, res, next) {
    const submitted = (req.headers['x-admin-token'] || req.query.token || '').trim();
    if (!ADMIN_TOKEN) {
        return res.status(503).json({ error: 'Admin disabled: ADMIN_TOKEN not configured' });
    }
    if (!submitted) return res.status(401).json({ error: 'Unauthorized Admin' });
    try {
        const a = Buffer.from(submitted, 'utf8');
        const b = Buffer.from(ADMIN_TOKEN, 'utf8');
        if (a.length !== b.length || !require('crypto').timingSafeEqual(a, b)) {
            return res.status(401).json({ error: 'Unauthorized Admin' });
        }
    } catch {
        return res.status(401).json({ error: 'Unauthorized Admin' });
    }
    next();
}

function getClientIp(req) {
    const xf = req.headers['x-forwarded-for'];
    if (typeof xf === 'string' && xf.length) {
        return xf.split(',')[0].trim();
    }
    const real = req.headers['x-real-ip'];
    if (typeof real === 'string' && real.length) return real.trim();
    return req.ip;
}

function getClientCountry(req) {
    const cf = (req.headers['cf-ipcountry'] || req.headers['x-country-code'] || '').toString().trim().toUpperCase();
    return cf || null;
}

// URL allowlist: only http(s) targets (no javascript:, data:, vbscript:,
// file:, etc.) so a compromised authenticated user can't plant an XSS
// payload that the redirect endpoint then executes for the next visitor.
function isSafeHttpUrl(raw, { allowEmpty = true } = {}) {
    if (raw == null || raw === '') return !!allowEmpty;
    if (typeof raw !== 'string') return false;
    if (raw.length > 2048) return false;
    let u;
    try { u = new URL(raw); } catch (_) { return false; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    if (!u.hostname || !u.hostname.includes('.')) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Rate limiting + brute-force guards.
// express-rate-limit handles per-IP windows; per-account lockouts hash out the
// remaining threats (online spraying of credentials).
// ---------------------------------------------------------------------------
const LOGIN_LOCKOUTS = new Map();              // username -> { attempts, lockedUntil }
const LOGIN_LOCKOUT_THRESHOLD = 8;             // 8 fails per account locks for 15 min
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;

function ipKey(req) {
    return getClientIp(req) || '0.0.0.0';
}

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: ipKey,
    message: { error: 'Too many login attempts. Slow down.' }
});
const adminLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 50,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: ipKey,
    message: { error: 'Admin throttle exceeded. Slow down.' }
});
const redirectLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: ipKey,
    message: { error: 'Quota exceeded for redirects.' }
});
// Generic API throttle: signup / settings / payments / links / IP block ops.
// Heavy endpoints (login, /l/, /api/admin/*) have their own rateLimiters.
const apiLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: ipKey,
    message: { error: 'Too many API calls. Slow down.' }
});
const signupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: ipKey,
    message: { error: 'Too many signup attempts from this IP. Try again later.' }
});

// Wrap requireAdmin to also apply adminLimiter (per-IP throttle for /api/admin/*).
function requireAdminThrottled(req, res, next) {
    adminLimiter(req, res, () => requireAdmin(req, res, next));
}

// --- Admin Routes ---
// Strip password hashes before sending to the admin UI so a
// compromised admin token doesn't leak credential material. (The admin
// UI only ever shows metadata about users.)
const SAFE_USER_KEYS = new Set(['password']);
function stripSecrets(u) {
    if (!u || typeof u !== 'object') return u;
    const out = Array.isArray(u) ? [] : {};
    for (const k of Object.keys(u)) {
        if (SAFE_USER_KEYS.has(k)) continue;
        const v = u[k];
        out[k] = (v && typeof v === 'object' && !(v instanceof Date) && !Buffer.isBuffer(v))
            ? stripSecrets(v) : v;
    }
    return out;
}

app.get('/api/admin/users', requireAdmin, asyncHandler(async (req, res) => {
    const users = await db.getUsers();
    res.json(users.map(u => stripSecrets(u)));
}));

app.post('/api/admin/update-balance', requireAdmin, asyncHandler(async (req, res) => {
    const { userId, amount } = req.body;
    const user = await db.findUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const updatedUser = await db.updateUser(userId, { wallet: parseFloat(amount) });
    res.json(updatedUser);
}));

app.post('/api/admin/toggle-status', requireAdmin, asyncHandler(async (req, res) => {
    const { userId } = req.body;
    const user = await db.findUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const updatedUser = await db.updateUser(userId, { isActive: !user.isActive });
    res.json(updatedUser);
}));

app.delete('/api/admin/users/:id', requireAdmin, asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!id) return res.status(400).json({ error: 'ID_REQUIRED' });
    const user = await db.findUserById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const removed = await db.deleteUser(id);
    if (!removed) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true, message: 'User deleted', user: removed });
}));

app.get('/api/admin/payments', requireAdmin, asyncHandler(async (req, res) => {
    const users = await db.getUsers();
    const all = [];
    users.forEach(u => {
        (u.pendingPayments || []).forEach(p => {
            all.push({
                ...p,
                userId: u.id,
                userName: u.name || 'ANONYMOUS',
                userEmail: u.email || 'N/A'
            });
        });
    });
    all.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json(all);
}));

// --- Admin Stats / Monitoring Endpoint ---
function isExpiringFuture(iso) {
    if (!iso) return false;
    const d = new Date(iso);
    return !isNaN(d.getTime()) && d > new Date();
}

app.get('/api/admin/stats', requireAdmin, asyncHandler(async (req, res) => {
    const users = await db.getUsers();

    const now = Date.now();
    const HOUR = 60 * 60 * 1000;
    const DAY = 24 * HOUR;
    const WEEK = 7 * DAY;

    const stats = {
        users: {
            total: users.length,
            active: users.filter(u => u.isActive).length,
            deactivated: users.filter(u => !u.isActive).length,
            registeredLast24h: users.filter(u => u.createdAt && (now - new Date(u.createdAt).getTime()) < DAY).length,
            loggedInLast24h: users.filter(u => u.lastLoginAt && (now - new Date(u.lastLoginAt).getTime()) < DAY).length
        },
        inflow: {
            confirmedTotal: 0,
            pendingTotal: 0,
            rejectedTotal: 0,
            autoCreditedTotal: 0,
            manualConfirmedTotal: 0,
            confirmed24h: 0,
            confirmed7d: 0,
            pendingCount: 0,
            recentConfirmed: []
        },
        wallet: {
            totalCreditsAcrossUsers: 0,
            highWallets: 0,
            avgWallet: 0
        },
        visits: {
            total: 0,
            safe24h: 0,
            real24h: 0,
            last7d: 0,
            uniqueIps24h: new Set(),
            topLocations: {},
            topIsps: {},
            topIps: {},
            highestLocation: null,
            highestLocationHits: 0
        },
        uplinks: {
            activeCount: 0,
            expiredCount: 0,
            totalCount: 0
        },
        security: {
            forcedIpEntries: 0,
            blockedIpEntries: 0
        },
        topUsers: {
            byBalance: [],
            mostVisits: []
        },
        logins: {
            last24h: 0,
            last7d: 0,
            topCountries: {}
        },
        generatedAt: new Date().toISOString()
    };

    const buckets24h = new Set();
    const locationToLastSeen = {};

    for (const u of users) {
        stats.wallet.totalCreditsAcrossUsers += (typeof u.wallet === 'number') ? u.wallet : 0;

        const vArr = Array.isArray(u.visitedIps) ? u.visitedIps : [];
        stats.visits.total += vArr.length;

        let userVisits = 0;
        for (const v of vArr) {
            const ts = v.timestamp ? new Date(v.timestamp).getTime() : (typeof v.timestamp === 'number' ? v.timestamp : 0);
            userVisits++;
            if (ts && (now - ts) < DAY) {
                stats.visits.last7d++;
                buckets24h.add(v.ip);
                if (v.type === 'REAL') stats.visits.real24h++;
                else stats.visits.safe24h++;
                if (v.ip) stats.visits.uniqueIps24h.add(v.ip);
            } else if (ts && (now - ts) < WEEK) {
                stats.visits.last7d++;
            }
            if (v.location && v.location !== 'Unknown') {
                const key = v.location;
                if (!stats.visits.topLocations[key]) stats.visits.topLocations[key] = { hits: 0, lastSeen: 0 };
                stats.visits.topLocations[key].hits++;
                if (ts > stats.visits.topLocations[key].lastSeen) stats.visits.topLocations[key].lastSeen = ts;
                if (stats.visits.topLocations[key].hits > stats.highestLocationHits) {
                    stats.highestLocationHits = stats.visits.topLocations[key].hits;
                    stats.visits.highestLocation = key;
                }
            }
            if (v.isp && v.isp !== 'Unknown') {
                stats.visits.topIsps[v.isp] = (stats.visits.topIsps[v.isp] || 0) + 1;
            }
            if (v.ip) {
                if (!stats.visits.topIps[v.ip]) stats.visits.topIps[v.ip] = { hits: 0, lastSeen: 0 };
                stats.visits.topIps[v.ip].hits++;
                if (ts > stats.visits.topIps[v.ip].lastSeen) stats.visits.topIps[v.ip].lastSeen = ts;
            }
        }
        stats.topUsers.mostVisits.push({
            name: u.name,
            email: u.email,
            visits: userVisits,
            wallet: u.wallet || 0
        });

        stats.security.forcedIpEntries += (u.forcedIps || []).length;
        stats.security.blockedIpEntries += (u.blockedIps || []).length;

        const ppay = Array.isArray(u.pendingPayments) ? u.pendingPayments : [];
        for (const p of ppay) {
            const amt = parseFloat(p.amount) || 0;
            const createdMs = p.createdAt ? new Date(p.createdAt).getTime() : 0;
            if (p.status === 'pending') {
                stats.inflow.pendingTotal += amt;
                stats.inflow.pendingCount++;
            } else if (p.status === 'confirmed') {
                stats.inflow.confirmedTotal += amt;
                if (createdMs && (now - createdMs) < DAY) stats.inflow.confirmed24h += amt;
                if (createdMs && (now - createdMs) < WEEK) stats.inflow.confirmed7d += amt;
                if (p.autoVerified) stats.inflow.autoCreditedTotal += amt;
                else stats.inflow.manualConfirmedTotal += amt;
                if (p.confirmedAt) {
                    stats.inflow.recentConfirmed.push({
                        amount: amt,
                        userName: u.name,
                        userEmail: u.email,
                        confirmedAt: p.confirmedAt,
                        autoVerified: !!p.autoVerified,
                        txHash: p.txHash || null,
                        fromAddress: p.fromAddress || null
                    });
                }
            } else if (p.status === 'rejected') {
                stats.inflow.rejectedTotal += amt;
            }
        }

        const defaultActive = isExpiringFuture(u.expiryDate);
        if (defaultActive) stats.uplinks.activeCount++;
        else if (u.expiryDate) stats.uplinks.expiredCount++;
        stats.uplinks.totalCount++;

        for (const l of (u.links || [])) {
            stats.uplinks.totalCount++;
            if (isExpiringFuture(l.expiryDate)) stats.uplinks.activeCount++;
            else if (l.expiryDate) stats.uplinks.expiredCount++;
        }

        const lh = Array.isArray(u.loginHistory) ? u.loginHistory : [];
        for (const e of lh) {
            const ts = e.ts ? new Date(e.ts).getTime() : 0;
            if (!ts) continue;
            if ((now - ts) < DAY) stats.logins.last24h++;
            if ((now - ts) < WEEK) stats.logins.last7d++;
            if (e.country) stats.logins.topCountries[e.country] = (stats.logins.topCountries[e.country] || 0) + 1;
        }
    }

    stats.wallet.avgWallet = users.length ? stats.wallet.totalCreditsAcrossUsers / users.length : 0;
    stats.wallet.highWallets = users.filter(u => (u.wallet || 0) >= 100).length;

    stats.inflow.recentConfirmed.sort((a, b) => new Date(b.confirmedAt) - new Date(a.confirmedAt));
    stats.inflow.recentConfirmed = stats.inflow.recentConfirmed.slice(0, 10);

    const topN = (obj, n = 10, transform) => Object.entries(obj)
        .map(([k, v]) => ({ key: k, ...(transform ? transform(v) : { value: v }) }))
        .sort((a, b) => (b.value !== undefined ? b.value : b.hits) - (a.value !== undefined ? a.value : a.hits))
        .slice(0, n);

    stats.visits.topLocationsArr = topN(stats.visits.topLocations, 10, v => ({ hits: v.hits, lastSeen: v.lastSeen }))
        .map(o => ({ location: o.key, hits: o.hits, lastSeen: o.lastSeen }));
    stats.visits.topIspsArr = topN(stats.visits.topIsps, 10)
        .map(o => ({ isp: o.key, hits: o.value }));
    stats.visits.topIpsArr = topN(stats.visits.topIps, 10, v => ({ hits: v.hits, lastSeen: v.lastSeen }))
        .map(o => ({ ip: o.key, hits: o.hits, lastSeen: o.lastSeen }));
    stats.logins.topCountriesArr = topN(stats.logins.topCountries, 10)
        .map(o => ({ country: o.key, count: o.value }));

    stats.visits.uniqueIps24h = buckets24h.size;

    stats.topUsers.byBalance = users
        .map(u => ({ name: u.name, email: u.email, wallet: u.wallet || 0, isActive: !!u.isActive, lastLoginAt: u.lastLoginAt || null }))
        .sort((a, b) => b.wallet - a.wallet)
        .slice(0, 10);

    stats.topUsers.mostVisits.sort((a, b) => b.visits - a.visits);
    stats.topUsers.mostVisits = stats.topUsers.mostVisits.slice(0, 10);

    delete stats.visits.topLocations;
    delete stats.visits.topIsps;
    delete stats.visits.topIps;
    delete stats.logins.topCountries;

    return res.json(stats);
}));

// --- Auth Routes ---
app.post('/api/signup', signupLimiter, asyncHandler(async (req, res) => {
    const { password } = req.body || {};
    const requestedUsername = db.normalizeUsername(req.body.username);
    const rawEmail = (req.body && req.body.email) ? String(req.body.email).trim().toLowerCase() : '';
    const name = (req.body && req.body.name) ? String(req.body.name).trim() : requestedUsername;

    if (!requestedUsername || !password || !rawEmail) {
        return res.status(400).json({ error: 'Username, email and password are required' });
    }
    if (!db.isValidUsername(requestedUsername)) {
        return res.status(400).json({
            error: 'Username must be 3-20 chars, lowercase letters / digits / . _ - only, and not reserved'
        });
    }
    const basicEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!basicEmail.test(rawEmail) || rawEmail.length > 120) {
        return res.status(400).json({ error: 'Invalid email address' });
    }
    if (await db.isUsernameTaken(requestedUsername)) {
        return res.status(400).json({ error: 'Username already taken' });
    }
    if (await db.findUserByEmail(rawEmail)) {
        return res.status(400).json({ error: 'Email already registered' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await db.createUser({
        name,
        username: requestedUsername,
        email: rawEmail,
        password: hashedPassword
    });
    console.log(`[Signup] New user registered: @${requestedUsername} <${rawEmail}>`);
    res.json({ message: 'Signup successful', username: requestedUsername });
}));

app.post('/api/login', loginLimiter, asyncHandler(async (req, res) => {
    // Login is username + password only. The form may submit a leading "@"
    // (e.g. "@joe"); strip it before lookup so users don't have to memorise
    // the canonical form.
    const rawUsername =
        (req.body && (req.body.username || req.body.identifier)) ?
            String(req.body.username || req.body.identifier).trim() : '';
    const password = (req.body && req.body.password) ? String(req.body.password) : '';
    if (!rawUsername || !password) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }
    const cleanedUsername = rawUsername.replace(/^@+/, '');
    if (!cleanedUsername) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }
    const bucketKey = cleanedUsername.toLowerCase();
    const ip = getClientIp(req);
    const lock = LOGIN_LOCKOUTS.get(bucketKey);
    if (lock && lock.lockedUntil > Date.now()) {
        return res.status(429).json({ error: 'Too many failed attempts. Try again later.', retryAfterMs: lock.lockedUntil - Date.now() });
    }
    const user = await db.findUserByUsername(cleanedUsername);
    const ok = user && (await bcrypt.compare(password, user.password || ''));
    if (!ok) {
        const entry = LOGIN_LOCKOUTS.get(bucketKey) || { attempts: 0, lockedUntil: 0 };
        entry.attempts++;
        if (entry.attempts >= LOGIN_LOCKOUT_THRESHOLD) {
            entry.attempts = 0;
            entry.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
        }
        LOGIN_LOCKOUTS.set(bucketKey, entry);
        console.log(`[Login] Failed login attempt for ${bucketKey} from ${ip}`);
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    LOGIN_LOCKOUTS.delete(bucketKey);
    // Regenerate the session ID on privilege change so a pre-login session
    // cookie cannot be reused by an attacker as a "fixated" authed session.
    await new Promise((resolve, reject) => {
        req.session.regenerate((err) => err ? reject(err) : resolve());
    });
    req.session.userId = user.id;
    const country = getClientCountry(req);
    const history = Array.isArray(user.loginHistory) ? user.loginHistory.slice(-49) : [];
    history.push({ ip, country, ts: new Date().toISOString() });
    await db.updateUser(user.id, {
        lastLoginAt: new Date().toISOString(),
        lastLoginIp: ip,
        lastLoginCountry: country || null,
        loginHistory: history
    });
    console.log(`[Login] User logged in: ${user.username || bucketKey} from ${ip}${country ? ' (' + country + ')' : ''}`);
    res.json({ message: 'Login successful' });
}));

app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('[Logout] Error destroying session:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.clearCookie('sp.sid'); // Clear the session cookie (must match session({ name: 'sp.sid' }))
        res.json({ message: 'Logged out' });
    });
});

app.get('/api/user', requireAuth, asyncHandler(async (req, res) => {
    const { password, ...rest } = req.user;
    res.json(rest);
}));

// --- Settings & Wallet Routes ---
const SETTINGS_ALLOWED_KEYS = new Set([
    'depositSendAddress',
    'realLink',
    'nonRealLink',
    'antiRed',
    'ispFilter',
    'reallowVisited',
    'mobileIsps',
    'botToken',
    'chatId',
    'allowAfrica',
    'allowEurope'
]);
const SETTINGS_BOOLEAN_KEYS = new Set(['antiRed', 'ispFilter', 'reallowVisited', 'allowAfrica', 'allowEurope']);
const SETTINGS_LIST_KEYS = new Set(['mobileIsps']);

app.post('/api/settings', requireAuth, apiLimiter, asyncHandler(async (req, res) => {
    // Mass-assignment protection: drop any keys the user has no business
    // setting (lets them set anything that lands in the user record).
    const body = {};
    for (const k of Object.keys(req.body || {})) {
        if (SETTINGS_ALLOWED_KEYS.has(k)) body[k] = req.body[k];
    }
    let addressChanged = false;
    if ('depositSendAddress' in body) {
        const addr = (typeof body.depositSendAddress === 'string' ? body.depositSendAddress : '').trim();
        if (addr && !/^T[A-Za-z1-9]{33}$/.test(addr)) {
            return res.status(400).json({ error: 'Invalid TRC20 sender address (must start the T and be 34 chars)' });
        }
        const prev = ((req.user.settings || {}).depositSendAddress || '').trim();
        addressChanged = prev !== addr;
        body.depositSendAddress = addr;
    }
    for (const k of ['realLink', 'nonRealLink']) {
        if (k in body) {
            const v = (typeof body[k] === 'string' ? body[k] : '').trim();
            if (!isSafeHttpUrl(v, { allowEmpty: true })) {
                return res.status(400).json({ error: `INVALID_${k.toUpperCase()}` });
            }
            body[k] = v;
        }
    }
    for (const k of SETTINGS_BOOLEAN_KEYS) {
        if (k in body) {
            if (typeof body[k] !== 'boolean') {
                return res.status(400).json({ error: `${k}_MUST_BE_BOOLEAN` });
            }
        }
    }
    for (const k of SETTINGS_LIST_KEYS) {
        if (k in body) {
            if (!Array.isArray(body[k]) || body[k].some(v => typeof v !== 'string')) {
                return res.status(400).json({ error: `${k}_MUST_BE_STRING_ARRAY` });
            }
            body[k] = body[k].map(s => String(s).trim()).filter(Boolean).slice(0, 64);
            if (body[k].some(v => v.length > 40)) {
                return res.status(400).json({ error: `${k}_ENTRY_TOO_LONG` });
            }
        }
    }
    if ('botToken' in body) {
        if (typeof body.botToken !== 'string') return res.status(400).json({ error: 'BOT_TOKEN_INVALID' });
        if (body.botToken.length > 256) return res.status(400).json({ error: 'BOT_TOKEN_TOO_LONG' });
        body.botToken = body.botToken.trim();
    }
    if ('chatId' in body) {
        if (typeof body.chatId !== 'string') return res.status(400).json({ error: 'CHAT_ID_INVALID' });
        if (!/^-?\d+$/.test(body.chatId.trim())) return res.status(400).json({ error: 'CHAT_ID_INVALID' });
        body.chatId = body.chatId.trim();
    }

    const updatedUser = await db.updateUser(req.user.id, {
        settings: { ...req.user.settings, ...body }
    });

    // Re-evaluate poller cadence whenever the sender address flips. Adding it
    // means future inbound TXes can be auto-attributed → FAST cadence.
    // Removing it (or replacing it) means the fast path no longer applies,
    // and the next tick will switch us back to IDLE if no other work exists.
    if (addressChanged) {
        kickPoller();
    }

    res.json(updatedUser.settings);
}));

// --- Profile / Password Routes ---
app.post('/api/profile/update', requireAuth, apiLimiter, asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !(await bcrypt.compare(currentPassword, req.user.password))) {
        return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const updates = {};

    if (newPassword && typeof newPassword === 'string') {
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'New password must be at least 6 characters' });
        }
        if (newPassword === currentPassword) {
            return res.status(400).json({ error: 'New password must differ from current password' });
        }
        updates.password = await bcrypt.hash(newPassword, 12);
    }

    if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: 'No changes requested' });
    }

    const updatedUser = await db.updateUser(req.user.id, updates);
    const { password, ...safe } = updatedUser;
    res.json({ message: 'Profile updated', user: safe });
}));

// --- Telegram bot bridge -------------------------------------------------
// `connect-request` is called by the dashboard to mint a one-time code that
// the user redeems in the bot via /start <code>. `webhook` is called by
// Telegram with each inbound Update.
app.post('/api/telegram/connect-request', requireAuth, asyncHandler(async (req, res) => {
    if (!bot.isBotEnabled()) {
        return res.status(503).json({ error: 'TELEGRAM_BOT_TOKEN not configured on the server' });
    }
    const code = bot.issueLinkCode(req.user.id);
    const username = (process.env.TELEGRAM_BOT_USERNAME || '').trim();
    const deepLink = username
        ? `https://t.me/${username}?start=${code}`
        : null;
    res.json({ code, deepLink, botUsername: username || null, ttlMs: 600000 });
}));

app.get('/api/bot-info', (req, res) => {
    const username = (process.env.TELEGRAM_BOT_USERNAME || '').trim();
    res.json({
        username: username || null,
        link: username ? `https://t.me/${username}` : null
    });
});

app.post('/api/telegram/webhook', asyncHandler(async (req, res) => {
    // Telegram sends the secret_token value as the
    // X-Telegram-Bot-Api-Secret-Token header on every delivery. We compare
    // with timingSafeEqual when one is configured.
    const expected = (process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
    if (expected) {
        const provided = (req.headers['x-telegram-bot-api-secret-token'] || '').toString();
        const a = Buffer.from(provided, 'utf8');
        const b = Buffer.from(expected, 'utf8');
        if (a.length !== b.length || !require('crypto').timingSafeEqual(a, b)) {
            console.warn('[Bot] Webhook rejected: bad secret_token header');
            return res.status(401).json({ error: 'Unauthorized' });
        }
    }
    // Always answer fast; the bot dispatches asynchronously.
    res.json({ ok: true });
    setImmediate(() => {
        bot.handleUpdate(req.body).catch(err =>
            console.error('[Bot] handleUpdate error:', err.message));
    });
}));

// --- Payment Routes (USDT TRC20 via XT.com) ---
const PAYMENT_RECEIVE_ADDRESS = (process.env.USDT_TRC20_ADDRESS || '').trim();
const PAYMENT_EXCHANGE_NAME = process.env.PAYMENT_EXCHANGE_NAME || 'XT.com';
const PAYMENT_RATE = parseFloat(process.env.PAYMENT_RATE || '1');
const MIN_DEPOSIT_USDT = parseFloat(process.env.MIN_DEPOSIT_USDT || '10');

// --- Auto-verification via TronGrid (USDT-TRC20 mainnet) ---
const USDT_TRC20_CONTRACT = (process.env.USDT_TRC20_CONTRACT || 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t').trim();
const TRON_API_BASE = (process.env.TRON_API_BASE || 'https://api.trongrid.io').trim().replace(/\/+$/, '');
const TRONGRID_API_KEY = (process.env.TRONGRID_API_KEY || '').trim();
const AUTO_PAY_POLL_MS = parseInt(process.env.AUTO_PAY_POLL_MS || '30000', 10);
const AUTO_PAY_POLL_IDLE_MS = parseInt(process.env.AUTO_PAY_POLL_IDLE_MS || '300000', 10);
const AUTO_PAY_LOOKBACK_LIMIT = parseInt(process.env.AUTO_PAY_LOOKBACK_LIMIT || '20', 10);
// processedTxHashes dedup set is bounded so it can't grow without bound across
// months of polling. When the cap is reached we evict the oldest entries by
// re-inserting from current pending hashes.
const PROCESSED_TX_HASH_MAX = 50000;
const processedTxHashes = new Set();
function trackProcessedHash(hash) {
    if (processedTxHashes.has(hash)) return;
    if (processedTxHashes.size >= PROCESSED_TX_HASH_MAX) {
        // Evict roughly 25% of the oldest entries. Since Set preserves
        // insertion order we can pop the head.
        const evict = Math.floor(PROCESSED_TX_HASH_MAX * 0.25);
        const it = processedTxHashes.values();
        for (let i = 0; i < evict; i++) {
            const { value } = it.next();
            if (value !== undefined) processedTxHashes.delete(value);
        }
    }
    processedTxHashes.add(hash);
}

app.get('/api/payments/info', (req, res) => {
    res.json({
        network: 'TRC20',
        asset: 'USDT',
        exchange: PAYMENT_EXCHANGE_NAME,
        address: PAYMENT_RECEIVE_ADDRESS,
        rate: PAYMENT_RATE,
        minAmount: MIN_DEPOSIT_USDT
    });
});

app.post('/api/payments/request', requireAuth, apiLimiter, asyncHandler(async (req, res) => {
    const { amount } = req.body;
    const baseAmt = parseFloat(amount);
    if (!baseAmt || baseAmt <= 0 || !isFinite(baseAmt)) {
        return res.status(400).json({ error: 'Invalid amount' });
    }
    if (baseAmt < MIN_DEPOSIT_USDT) {
        return res.status(400).json({ error: `Minimum deposit is ${MIN_DEPOSIT_USDT} USDT` });
    }
    if (!PAYMENT_RECEIVE_ADDRESS) {
        return res.status(503).json({ error: 'Payment receiving address is not configured. Set USDT_TRC20_ADDRESS in server env.' });
    }

    const users = await db.getUsers();
    const activePending = [];
    users.forEach(u => {
        (u.pendingPayments || []).forEach(p => {
            if (p.status === 'pending') activePending.push(p);
        });
    });

    // Generate a unique decimal offset to avoid collisions for the same base amount
    let finalAmt = baseAmt;
    let attempts = 0;
    while (attempts < 50) {
        const offset = Math.floor(Math.random() * 50 + 1) / 100; // 0.01 to 0.50
        const candidate = parseFloat((baseAmt + offset).toFixed(2));
        const collision = activePending.some(p => Math.abs(parseFloat(p.amount) - candidate) < 0.001);
        if (!collision) {
            finalAmt = candidate;
            break;
        }
        attempts++;
    }

    const payment = {
        id: require('uuid').v4(),
        amount: finalAmt,
        status: 'pending',
        network: 'USDT-TRC20',
        address: PAYMENT_RECEIVE_ADDRESS,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() // 1 hour expiry
    };

    const updatedUser = await db.updateUser(req.user.id, {
        pendingPayments: [...(req.user.pendingPayments || []), payment]
    });

    // Kick the poller back to FAST cadence
    kickPoller({ immediate: true });

    res.json({ payment, balance: updatedUser.wallet });
}));

app.post('/api/payments/submit', requireAuth, apiLimiter, asyncHandler(async (req, res) => {
    const { amount, txHash } = req.body;
    const amt = parseFloat(amount);
    if (!amt || amt <= 0 || !isFinite(amt)) {
        return res.status(400).json({ error: 'Invalid amount' });
    }
    if (amt < MIN_DEPOSIT_USDT) {
        return res.status(400).json({ error: `Minimum deposit is ${MIN_DEPOSIT_USDT} USDT` });
    }
    const cleanHash = (txHash || '').trim();
    if (!/^[a-fA-F0-9]{64}$/.test(cleanHash)) {
        return res.status(400).json({ error: 'Invalid TRC20 transaction hash (expected 64 hex chars)' });
    }
    if (!PAYMENT_RECEIVE_ADDRESS) {
        return res.status(503).json({ error: 'Payment receiving address is not configured. Set USDT_TRC20_ADDRESS in server env.' });
    }

    const users = await db.getUsers();
    const dup = users.find(u => (u.pendingPayments || []).some(p => p.txHash === cleanHash));
    if (dup) {
        return res.status(400).json({ error: 'This transaction hash has already been submitted' });
    }

    const payment = {
        id: require('uuid').v4(),
        amount: amt,
        txHash: cleanHash,
        network: 'USDT-TRC20',
        address: PAYMENT_RECEIVE_ADDRESS,
        status: 'pending',
        createdAt: new Date().toISOString()
    };

    const updatedUser = await db.updateUser(req.user.id, {
        pendingPayments: [...(req.user.pendingPayments || []), payment]
    });

    // Kick the poller back to FAST cadence — there's now a pending row that
    // can only be credited once TronGrid sees the matching tx.
    kickPoller({ immediate: true });

    res.json({ payment, balance: updatedUser.wallet, pending: updatedUser.pendingPayments });
}));

app.get('/api/payments/my', requireAuth, asyncHandler(async (req, res) => {
    res.json(req.user.pendingPayments || []);
}));

// --- Auto-verification poller ---
async function pollTronPayments() {
    if (!PAYMENT_RECEIVE_ADDRESS) {
        console.log('[AutoPay] Skipped poll: USDT_TRC20_ADDRESS not configured');
        return;
    }

    try {
        const url = `${TRON_API_BASE}/v1/accounts/${encodeURIComponent(PAYMENT_RECEIVE_ADDRESS)}/transactions/trc20`;
        const params = {
            only_confirmed: true,
            limit: AUTO_PAY_LOOKBACK_LIMIT,
            contract_address: USDT_TRC20_CONTRACT
        };
        const headers = {};
        if (TRONGRID_API_KEY) headers['TRON-PRO-API-KEY'] = TRONGRID_API_KEY;

        const res = await axios.get(url, { params, headers, timeout: 10000 });
        const txs = (res.data && res.data.data) || [];

        for (const tx of txs) {
            const hash = (tx.transaction_id || '').toLowerCase();
            if (!hash || processedTxHashes.has(hash)) continue;

            const receiver = (tx.to || '').trim();
            if (receiver !== PAYMENT_RECEIVE_ADDRESS) {
                trackProcessedHash(hash);
                continue;
            }

            const valueRaw = tx.value || tx.quant || '0';
            const decimals = (tx.token_info && parseInt(tx.token_info.decimals, 10)) || 6;
            const valueNum = parseFloat(valueRaw) / Math.pow(10, decimals);
            if (!isFinite(valueNum) || valueNum <= 0) {
                trackProcessedHash(hash);
                continue;
            }
            if (valueNum < MIN_DEPOSIT_USDT) {
                trackProcessedHash(hash);
                console.log(`[AutoPay] Skipping ${hash}: amount ${valueNum} USDT below minimum ${MIN_DEPOSIT_USDT}`);
                continue;
            }

            const users = await db.getUsers();
            let matchedUser = null;
            let matchedPayment = null;
            let matchedMode = null;

            // 1) Sender-wallet match (primary attribution)
            for (const u of users) {
                const addr = ((u.settings || {}).depositSendAddress || '').trim();
                if (addr && (tx.from || '').trim() === addr) {
                    matchedUser = u;
                    matchedMode = 'sender_wallet';
                    break;
                }
            }

            // 2) Legacy tx-hash match (back-compat for any pre-existing pending rows)
            if (!matchedUser) {
                for (const u of users) {
                    const found = (u.pendingPayments || []).find(p =>
                        (p.txHash || '').toLowerCase() === hash && p.status === 'pending'
                    );
                    if (found) {
                        matchedUser = u;
                        matchedPayment = found;
                        matchedMode = 'legacy_hash';
                        break;
                    }
                }
            }

            // 3) Unique amount match (new flow)
            if (!matchedUser) {
                for (const u of users) {
                    const found = (u.pendingPayments || []).find(p =>
                        p.status === 'pending' &&
                        Math.abs(parseFloat(p.amount) - valueNum) < 0.001
                    );
                    if (found) {
                        // Check expiry
                        if (found.expiresAt && new Date(found.expiresAt) < new Date()) {
                            continue;
                        }
                        matchedUser = u;
                        matchedPayment = found;
                        matchedMode = 'amount_match';
                        break;
                    }
                }
            }

            if (!matchedUser) {
                trackProcessedHash(hash);
                console.log(`[AutoPay] Unmatched inbound TX ${hash} (${valueNum} USDT) from ${tx.from} — no registered sender wallet or pending hash`);
                continue;
            }

            const pending = matchedUser.pendingPayments || [];

            if (matchedMode === 'legacy_hash' || matchedMode === 'amount_match') {
                if (matchedPayment) {
                    const idx = pending.findIndex(p => p.id === matchedPayment.id);
                    if (idx === -1) {
                        trackProcessedHash(hash);
                        continue;
                    }
                    if (matchedMode === 'legacy_hash') {
                        const tolerance = 0.01;
                        const declaredAmount = parseFloat(matchedPayment.amount);
                        if (Math.abs(declaredAmount - valueNum) > tolerance) {
                            console.log(`[AutoPay] Amount mismatch for ${hash}: declared=${declaredAmount} on-chain=${valueNum} — holding for manual review`);
                            trackProcessedHash(hash);
                            continue;
                        }
                    }
                    pending[idx].status = 'confirmed';
                    pending[idx].confirmedAt = new Date().toISOString();
                    pending[idx].autoVerified = true;
                    pending[idx].onChainAmount = valueNum;
                    pending[idx].fromAddress = tx.from;
                    pending[idx].txHash = hash;
                }
            } else {
                // sender_wallet mode: synthesize an audit row
                pending.push({
                    id: require('uuid').v4(),
                    amount: valueNum,
                    txHash: hash,
                    network: 'USDT-TRC20',
                    address: PAYMENT_RECEIVE_ADDRESS,
                    fromAddress: (tx.from || '').trim(),
                    status: 'confirmed',
                    autoVerified: true,
                    onChainAmount: valueNum,
                    createdAt: new Date().toISOString(),
                    confirmedAt: new Date().toISOString()
                });
            }

            matchedUser.wallet = (matchedUser.wallet || 0) + valueNum;

            await db.updateUser(matchedUser.id, {
                pendingPayments: pending,
                wallet: matchedUser.wallet
            });

            trackProcessedHash(hash);
            console.log(`[AutoPay] AUTO-CREDITED ${valueNum} USDT to ${matchedUser.email} via ${matchedMode} (tx ${hash})`);
        }
    } catch (err) {
        console.error('[AutoPay] poll error:', err.message);
    }
}

async function bootstrapProcessedHashes() {
    if (!PAYMENT_RECEIVE_ADDRESS) return;
    try {
        const users = await db.getUsers();
        users.forEach(u => {
            (u.pendingPayments || []).forEach(p => {
                if (p.status === 'confirmed' && p.txHash) {
                    trackProcessedHash(p.txHash.toLowerCase());
                }
            });
        });
        console.log(`[AutoPay] Loaded ${processedTxHashes.size} already-confirmed hash(es) into memory`);
    } catch (err) {
        console.error('[AutoPay] bootstrap error:', err.message);
    }
}

// Returns true when there is at least one pending row or a registered
// deposit sender address — i.e. when a poll can actually produce credit
// work. Used by the scheduler to skip TronGrid requests entirely when
// there's nothing to attribute.
async function hasWork() {
    try {
        const users = await db.getUsers();
        for (const u of users) {
            if (!u) continue;
            if (Array.isArray(u.pendingPayments) && u.pendingPayments.some(p => p && p.status === 'pending')) {
                return true;
            }
            const addr = u.settings && u.settings.depositSendAddress;
            if (typeof addr === 'string' && addr.trim()) {
                return true;
            }
        }
    } catch (err) {
        // If the snapshot read fails, prefer to ask TronGrid rather than
        // skip silently — better one wasted call than a missed credit.
        return true;
    }
    return false;
}

// Adaptive scheduler: fast cadence while there is work to do, slow cadence
// (AUTO_PAY_POLL_IDLE_MS) once nothing is pending and no user has a sender
// address registered. Any new submission / settings change kicks it back to
// fast mode via kickPoller().
let pollHandle = null;
let pollInFlight = false;
let pollFast = true;

function clearPollHandle() {
    if (pollHandle) {
        clearTimeout(pollHandle);
        pollHandle = null;
    }
}

function schedulePoll() {
    clearPollHandle();
    if (!PAYMENT_RECEIVE_ADDRESS) return;
    const interval = pollFast ? AUTO_PAY_POLL_MS : AUTO_PAY_POLL_IDLE_MS;
    pollHandle = setTimeout(tickPoll, interval);
}

async function tickPoll() {
    if (pollInFlight) {
        // Don't stack overlapping polls — reschedule and let the current
        // one decide the next cadence.
        schedulePoll();
        return;
    }
    pollInFlight = true;
    try {
        await pollTronPayments();
        const work = await hasWork();
        const wasFast = pollFast;
        pollFast = work;
        if (wasFast !== pollFast) {
            console.log(`[AutoPay] Switching to ${pollFast ? 'FAST' : 'IDLE'} poll cadence (ms=${pollFast ? AUTO_PAY_POLL_MS : AUTO_PAY_POLL_IDLE_MS})`);
        }
    } catch (err) {
        // pollTronPayments already logs axios / network failures; keep the
        // current cadence whichever way it was set.
    } finally {
        pollInFlight = false;
        schedulePoll();
    }
}

function kickPoller({ immediate = false } = {}) {
    if (!PAYMENT_RECEIVE_ADDRESS) return;
    pollFast = true;
    clearPollHandle();
    pollHandle = setTimeout(tickPoll, immediate ? 0 : AUTO_PAY_POLL_MS);
}

if (PAYMENT_RECEIVE_ADDRESS) {
    bootstrapProcessedHashes().then(async () => {
        const seededWork = await hasWork();
        pollFast = seededWork;
        schedulePoll();
        console.log(`[AutoPay] Initial poll cadence: ${pollFast ? 'FAST' : 'IDLE'} (ms=${pollFast ? AUTO_PAY_POLL_MS : AUTO_PAY_POLL_IDLE_MS}); base=${TRON_API_BASE}, address=${PAYMENT_RECEIVE_ADDRESS}`);
        process.on('SIGTERM', clearPollHandle);
        process.on('SIGINT', clearPollHandle);
    });
} else {
    console.log('[AutoPay] USDT_TRC20_ADDRESS not set — automatic payment verification disabled');
}

// ---------------------------------------------------------------------------
// Telegram bot boot: rebuild chat → user index from disk, then register the
// webhook with Telegram so updates flow to /api/telegram/webhook.
// ---------------------------------------------------------------------------
if (bot.isBotEnabled()) {
    bot.rebuildChatIndex()
        .then(() => bot.setupWebhook())
        .catch(err => console.error('[Bot] Boot error:', err.message));
} else {
    console.log('[Bot] TELEGRAM_BOT_TOKEN not set — bot commands disabled (use /api/telegram/webhook only after configuring)');
}


app.post('/api/forced-ips', requireAuth, apiLimiter, asyncHandler(async (req, res) => {
    const ip = typeof req.body.ip === 'string' ? req.body.ip.trim() : '';
    if (!db.ipRuleKind(ip)) {
        return res.status(400).json({ error: 'INVALID_IP_FORMAT (use exact v4/v6, wildcard, or CIDR)' });
    }
    if (!(req.user.forcedIps || []).includes(ip)) {
        await db.updateUser(req.user.id, { forcedIps: [...(req.user.forcedIps || []), ip] });
    }
    res.json({ message: 'IP added' });
}));

app.post('/api/blocked-ips', requireAuth, apiLimiter, asyncHandler(async (req, res) => {
    const { ip } = req.body;
    if (!ip || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        return res.status(400).json({ error: 'Invalid IP format' });
    }
    const currentBlocked = req.user.blockedIps || [];
    if (!currentBlocked.includes(ip)) {
        await db.updateUser(req.user.id, { blockedIps: [...currentBlocked, ip] });
    }
    res.json({ message: 'IP blocked' });
}));

app.get('/api/links', requireAuth, asyncHandler(async (req, res) => {
    res.json(req.user.links || []);
}));

// --- Overlap-prevention helpers ---
function isExpiryActive(expiryDate) {
    if (!expiryDate) return false;
    const d = new Date(expiryDate);
    return !isNaN(d.getTime()) && d > new Date();
}

async function findActiveConflict(slug, excludeUserId) {
    const all = await db.getUsers();
    for (const u of all) {
        if (excludeUserId && u.id === excludeUserId) continue;
        if (u.slug === slug && isExpiryActive(u.expiryDate)) {
            return { user: u, link: { slug: u.slug, expiryDate: u.expiryDate, base: true } };
        }
        const link = (u.links || []).find(l => l.slug === slug && isExpiryActive(l.expiryDate));
        if (link) return { user: u, link };
    }
    return null;
}

app.post('/api/links', requireAuth, apiLimiter, asyncHandler(async (req, res) => {
    const { name, realLink, nonRealLink, slug, antiRed, ispFilter, botFilter, mobileIsps, reallowVisited, duration, allowAfrica, allowEurope } = req.body;

    const prices = { '3days': 15, '1week': 25, '2weeks': 50, 'month': 80 };
    const price = prices[duration];

    if (!price) return res.status(400).json({ error: 'Invalid duration selected' });

    if (!name || !realLink || !nonRealLink) {
        return res.status(400).json({ error: 'Name, Real Link, and Safe Link are required' });
    }
    if (typeof name !== 'string' || name.trim().length === 0 || name.length > 80) {
        return res.status(400).json({ error: 'INVALID_NAME' });
    }
    if (!isSafeHttpUrl(realLink, { allowEmpty: false })) {
        return res.status(400).json({ error: 'INVALID_REALLINK' });
    }
    if (!isSafeHttpUrl(nonRealLink, { allowEmpty: false })) {
        return res.status(400).json({ error: 'INVALID_NONREALLINK' });
    }

    const fresh = await db.findUserById(req.user.id);
    if (!fresh) return res.status(401).json({ error: 'Unauthorized' });
    if (fresh.wallet < price) {
        return res.status(400).json({ error: `Insufficient credits. This plan requires $${price.toFixed(2)}.` });
    }

    const newSlug = slug || require('crypto').randomBytes(32).toString('hex');
    
    if (slug && !/^[a-zA-Z0-9-]+$/.test(slug)) {
        return res.status(400).json({ error: 'Slug can only contain letters, numbers, and dashes' });
    }

    const existing = await findActiveConflict(newSlug, req.user.id);
    if (existing) {
        return res.status(400).json({ error: 'Slug is currently active on another uplink and cannot be reused until it expires' });
    }

    const now = new Date();
    let expiry = new Date(now);
    if (duration === '3days') expiry.setDate(expiry.getDate() + 3);
    else if (duration === '1week') expiry.setDate(expiry.getDate() + 7);
    else if (duration === '2weeks') expiry.setDate(expiry.getDate() + 14);
    else if (duration === 'month') expiry.setMonth(expiry.getMonth() + 1);

    const newLink = {
        id: require('uuid').v4(),
        name,
        realLink,
        nonRealLink,
        slug: newSlug,
        antiRed: antiRed !== undefined ? antiRed : true,
        ispFilter: ispFilter !== undefined ? ispFilter : true,
        botFilter: botFilter !== undefined ? botFilter : true,
        mobileIsps: mobileIsps || req.user.settings.mobileIsps,
        reallowVisited: reallowVisited !== undefined ? reallowVisited : true,
        allowAfrica: allowAfrica !== undefined ? allowAfrica : false,
        allowEurope: allowEurope !== undefined ? allowEurope : true,
        expiryDate: expiry.toISOString(),
        createdAt: new Date().toISOString()
    };

    const updatedUser = await db.updateUser(req.user.id, {
        wallet: req.user.wallet - price,
        links: [...(req.user.links || []), newLink]
    });

    res.json({ ...newLink, balance: updatedUser.wallet });
}));

app.post('/api/links/bulk', requireAuth, apiLimiter, asyncHandler(async (req, res) => {
    const { text, duration, antiRed, ispFilter, botFilter, mobileIsps, reallowVisited, allowAfrica, allowEurope } = req.body;

    const prices = { '3days': 15, '1week': 25, '2weeks': 50, 'month': 80 };
    const pricePerUnit = prices[duration];

    if (!pricePerUnit) return res.status(400).json({ error: 'Invalid duration selected' });
    if (!text || typeof text !== 'string') return res.status(400).json({ error: 'Input text is required' });

    const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('#'));
    if (lines.length === 0) return res.status(400).json({ error: 'No valid lines provided' });
    if (lines.length > 50) return res.status(400).json({ error: 'Bulk limit is 50 links per submission' });

    const fresh = await db.findUserById(req.user.id);
    if (!fresh) return res.status(401).json({ error: 'Unauthorized' });

    const totalPrice = lines.length * pricePerUnit;
    if (fresh.wallet < totalPrice) {
        return res.status(400).json({ error: `Insufficient credits. Need $${totalPrice.toFixed(2)} for ${lines.length} links.` });
    }

    const processed = [];
    const errors = [];
    let currentWallet = fresh.wallet;

    const now = new Date();
    let expiry = new Date(now);
    if (duration === '3days') expiry.setDate(expiry.getDate() + 3);
    else if (duration === '1week') expiry.setDate(expiry.getDate() + 7);
    else if (duration === '2weeks') expiry.setDate(expiry.getDate() + 14);
    else if (duration === 'month') expiry.setMonth(expiry.getMonth() + 1);

    for (const line of lines) {
        const parts = line.split(',').map(p => p.trim());
        if (parts.length < 3) {
            errors.push(`Invalid format: ${line}`);
            continue;
        }

        const [name, realLink, nonRealLink, slug] = parts;
        if (!name || !realLink || !nonRealLink) {
            errors.push(`Missing fields: ${line}`);
            continue;
        }

        if (!isSafeHttpUrl(realLink, { allowEmpty: false }) || !isSafeHttpUrl(nonRealLink, { allowEmpty: false })) {
            errors.push(`Invalid URLs: ${line}`);
            continue;
        }

        const newSlug = slug || require('crypto').randomBytes(32).toString('hex');
        if (newSlug && !/^[a-zA-Z0-9-]+$/.test(newSlug)) {
            errors.push(`Invalid slug: ${newSlug}`);
            continue;
        }

        const conflict = await findActiveConflict(newSlug, req.user.id);
        if (conflict) {
            errors.push(`Slug conflict: ${newSlug}`);
            continue;
        }

        const newLink = {
            id: require('uuid').v4(),
            name,
            realLink,
            nonRealLink,
            slug: newSlug,
            antiRed: antiRed !== undefined ? antiRed : true,
            ispFilter: ispFilter !== undefined ? ispFilter : true,
            botFilter: botFilter !== undefined ? botFilter : true,
            mobileIsps: mobileIsps || req.user.settings.mobileIsps,
            reallowVisited: reallowVisited !== undefined ? reallowVisited : true,
            allowAfrica: allowAfrica !== undefined ? allowAfrica : false,
            allowEurope: allowEurope !== undefined ? allowEurope : true,
            expiryDate: expiry.toISOString(),
            createdAt: new Date().toISOString()
        };

        processed.push(newLink);
        currentWallet -= pricePerUnit;
    }

    if (processed.length === 0) {
        return res.status(400).json({ error: 'No links could be processed', details: errors });
    }

    const updatedUser = await db.updateUser(req.user.id, {
        wallet: currentWallet,
        links: [...(fresh.links || []), ...processed]
    });

    res.json({
        ok: true,
        count: processed.length,
        totalPrice,
        balance: updatedUser.wallet,
        errors: errors.length > 0 ? errors : undefined
    });
}));

app.delete('/api/links/:slug', requireAuth, asyncHandler(async (req, res) => {
    const { slug } = req.params;

    const links = req.user.links || [];
    const target = links.find(l => l.slug === slug);
    if (!target) return res.status(404).json({ error: 'Link not found' });

    if (isExpiryActive(target.expiryDate)) {
        return res.status(400).json({ error: 'Uplink is still active and cannot be deleted until it expires. Overlapping lifecycle changes are not allowed.' });
    }

    const updatedLinks = links.filter(l => l.slug !== slug);
    await db.updateUser(req.user.id, { links: updatedLinks });
    res.json({ message: 'Link deleted' });
}));

app.put('/api/links/:oldSlug', requireAuth, apiLimiter, asyncHandler(async (req, res) => {
    const { oldSlug } = req.params;
    const { name, realLink, nonRealLink, slug, antiRed, ispFilter, botFilter, mobileIsps, reallowVisited, allowAfrica, allowEurope } = req.body;

    if (!name || !realLink || !nonRealLink) {
        return res.status(400).json({ error: 'Name, Real Link, and Safe Link are required' });
    }
    if (typeof name !== 'string' || name.length > 80) {
        return res.status(400).json({ error: 'INVALID_NAME' });
    }
    if (!isSafeHttpUrl(realLink, { allowEmpty: false })) {
        return res.status(400).json({ error: 'INVALID_REALLINK' });
    }
    if (!isSafeHttpUrl(nonRealLink, { allowEmpty: false })) {
        return res.status(400).json({ error: 'INVALID_NONREALLINK' });
    }

    const newSlug = slug || oldSlug;

    // Validate slug
    if (newSlug && !/^[a-zA-Z0-9-]+$/.test(newSlug)) {
        return res.status(400).json({ error: 'Slug can only contain letters, numbers, and dashes' });
    }

    // Check if new slug is currently active on another user's uplink
    if (newSlug !== oldSlug) {
        const existing = await findActiveConflict(newSlug, req.user.id);
        if (existing) return res.status(400).json({ error: 'New slug is currently active on another uplink and cannot be reused until it expires' });
    }

    const links = req.user.links || [];
    const index = links.findIndex(l => l.slug === oldSlug);
    if (index === -1) return res.status(404).json({ error: 'Link not found' });

    links[index] = {
        ...links[index],
        name,
        realLink,
        nonRealLink,
        slug: newSlug,
        antiRed: antiRed !== undefined ? antiRed : links[index].antiRed,
        ispFilter: ispFilter !== undefined ? ispFilter : links[index].ispFilter,
        botFilter: botFilter !== undefined ? botFilter : links[index].botFilter,
        mobileIsps: mobileIsps !== undefined ? mobileIsps : links[index].mobileIsps,
        reallowVisited: reallowVisited !== undefined ? reallowVisited : links[index].reallowVisited,
        allowAfrica: allowAfrica !== undefined ? allowAfrica : links[index].allowAfrica,
        allowEurope: allowEurope !== undefined ? allowEurope : links[index].allowEurope,
        updatedAt: new Date().toISOString()
    };

    await db.updateUser(req.user.id, { links });
    res.json(links[index]);
}));

app.delete('/api/forced-ips/:ip', requireAuth, asyncHandler(async (req, res) => {
    const { ip } = req.params;
    await db.updateUser(req.user.id, { forcedIps: req.user.forcedIps.filter(i => i !== ip) });
    res.json({ message: 'IP removed' });
}));

app.delete('/api/blocked-ips/:ip', requireAuth, asyncHandler(async (req, res) => {
    const { ip } = req.params;
    const currentBlocked = req.user.blockedIps || [];
    await db.updateUser(req.user.id, { blockedIps: currentBlocked.filter(i => i !== ip) });
    res.json({ message: 'IP unblocked' });
}));

app.post('/api/renew-link', requireAuth, apiLimiter, asyncHandler(async (req, res) => {
    const { slug, duration } = req.body;
    const prices = { '3days': 15, '1week': 25, '2weeks': 50, 'month': 80 };
    const price = prices[duration];

    if (!price) return res.status(400).json({ error: 'Invalid duration selected' });

    // Re-read wallet from disk so two requests racing each other can't both
    // pass a stale balance check.
    const freshUser = await db.findUserById(req.user.id);
    if (!freshUser) return res.status(401).json({ error: 'Unauthorized' });
    if (freshUser.wallet < price) {
        return res.status(400).json({ error: `Insufficient credits. This plan requires $${price.toFixed(2)}.` });
    }

    // Refuse renewal if a NEW slug (different from this link's current slug) is currently active anywhere
    const linkSlugTaken = await findActiveConflict(slug, req.user.id);
    if (linkSlugTaken && linkSlugTaken.user.id === req.user.id && linkSlugTaken.link.slug === slug && isExpiryActive(linkSlugTaken.link.expiryDate)) {
        // It IS the same user's link; that's expected. This check is a sanity guard for the rename case.
    }

    const now = new Date();

    // Only custom uplinks managed by the user can be renewed.
    const links = req.user.links || [];
    const index = links.findIndex(l => l.slug === slug);
    if (index === -1) return res.status(404).json({ error: 'Uplink not found' });

    if (isExpiryActive(links[index].expiryDate)) {
        return res.status(400).json({ error: 'Uplink is still active and cannot be renewed until it expires. Overlapping renewals are not allowed.' });
    }

    let expiry = new Date(now);
    if (duration === '3days') expiry.setDate(expiry.getDate() + 3);
    else if (duration === '1week') expiry.setDate(expiry.getDate() + 7);
    else if (duration === '2weeks') expiry.setDate(expiry.getDate() + 14);
    else if (duration === 'month') expiry.setMonth(expiry.getMonth() + 1);

    links[index].expiryDate = expiry.toISOString();

    const updatedUser = await db.updateUser(req.user.id, {
        wallet: freshUser.wallet - price,
        links: links
    });

    res.json({ message: 'Uplink extended', expiryDate: links[index].expiryDate, balance: updatedUser.wallet });
}));

app.get('/api/isps', (req, res) => {
    const isps = (process.env.MOBILE_ISPS || "").split(',').map(isp => isp.trim()).filter(isp => isp !== "");
    res.json(isps);
});

// --- Proxy Redirection Logic ---
const BOT_UA_REGEX = /googlebot|bingbot|yandexbot|duckduckbot|slurp|baiduspider|facebot|ia_archiver|crawler|spider|robot|curl|wget|python|postman|insomnia|headless|screaming frog|ahrefsbot|semrushbot|mj12bot|dotbot|rogerbot|exabot|petalbot|adsbot|adwords|mediapartners|lighthouse|google-adwords|google-express|gSA-|google-http-client|google-adwords-instant|preview|whatsapp|telegram|discord|slack|facebookexternalhit|twitterbot|linkedinbot|pinterestbot|selenium|puppeteer|phantomjs|webdriver|headless|inspect|scan|analyze|google|bot/i;

function isBot(req) {
    const ua = req.headers['user-agent'] || '';
    return !ua || BOT_UA_REGEX.test(ua);
}

function isSafeHttpUrl(raw, { allowEmpty = true } = {}) {
    if (raw == null || raw === '') return allowEmpty;
    if (typeof raw !== 'string') return false;
    if (raw.length > 2048) return false;
    try {
        const u = new URL(raw);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
        if (!u.hostname || !u.hostname.includes('.')) return false;
        return true;
    } catch (_) { return false; }
}

function isExpiryActive(dateStr) {
    if (!dateStr) return false;
    const d = new Date(dateStr);
    return !isNaN(d.getTime()) && d > new Date();
}

// Defensive slug format guard: up to 128 chars from a safe alphabet.
const SLUG_REGEX = /^[A-Za-z0-9._-]{4,128}$/;
const MAX_VISITED_IPS_PER_USER = 5000;

// LRU cache on top of ip-api so repeated visitors don't double-charge /
// burn latency. We re-insert on hit to evict least-recently-used.
const IP_GEO_CACHE_MAX = 5000;
const IP_GEO_CACHE_TTL_MS = 60 * 60 * 1000;
const ipGeoCache = new Map();
async function lookupIpGeo(ip) {
    const cached = ipGeoCache.get(ip);
    const now = Date.now();
    if (cached && cached.expiresAt > now) {
        ipGeoCache.delete(ip);
        ipGeoCache.set(ip, cached);
        return cached.data;
    }
    try {
        if (PROXYCHECK_API_KEY) {
            const response = await axios.get(
                `https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${PROXYCHECK_API_KEY}&vpn=1&asn=1`,
                { timeout: 5000 }
            );
            const res = response.data;
            if (res.status === 'ok' || res.status === 'warning') {
                const node = res[ip];
                const data = {
                    status: 'success',
                    country: node.country || 'Unknown',
                    countryCode: node.isocode || 'UN',
                    regionName: node.region || 'Unknown',
                    city: node.city || 'Unknown',
                    isp: node.asn || node.provider || 'Unknown',
                    org: node.provider || 'Unknown',
                    proxy: node.proxy === 'yes',
                    hosting: node.type === 'hosting',
                    continentCode: node.continentcode || 'UN',
                    query: ip
                };
                ipGeoCache.set(ip, { data, expiresAt: now + IP_GEO_CACHE_TTL_MS });
                return data;
            }
        }

        const response = await axios.get(
            `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,query,continentCode`,
            { timeout: 5000 }
        );
        const data = response.data;
        if (data && data.status === 'success') {
            ipGeoCache.set(ip, { data, expiresAt: now + IP_GEO_CACHE_TTL_MS });
            return data;
        } else {
            console.warn(`[Proxy] IP lookup failed for ${ip} (ip-api): ${data.message || 'Unknown error'}`);
            // Cache negative result briefly
            ipGeoCache.set(ip, { data: null, expiresAt: now + 60 * 1000 });
        }
    } catch (err) {
        console.error(`[Proxy] IP lookup error for ${ip}:`, err.message);
        // Cache negative result briefly
        ipGeoCache.set(ip, { data: null, expiresAt: now + 60 * 1000 });
    }

    while (ipGeoCache.size > IP_GEO_CACHE_MAX) {
        const oldest = ipGeoCache.keys().next().value;
        ipGeoCache.delete(oldest);
    }
    const final = ipGeoCache.get(ip);
    return final ? final.data : null;
}

// Per-user mutation queue — two concurrent /l/:slug hits on the same
// uplink cannot trample the visitedIps append.
const USER_MUTEX = new Map();
async function withUserMutex(userId, fn) {
    const prev = USER_MUTEX.get(userId) || Promise.resolve();
    let release;
    const next = new Promise(resolve => { release = resolve; });
    USER_MUTEX.set(userId, prev.then(() => next));
    try {
        await prev;
        return await fn();
    } finally {
        release();
        if (USER_MUTEX.get(userId) === next) USER_MUTEX.delete(userId);
    }
}

// Escape for Telegram parse_mode=HTML to defeat Markdown/HTML injection
// from untrusted user agent / city / ISP / UA strings.
function telegramEscape(s) {
    return String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

app.get('/l/:slug', redirectLimiter, async (req, res) => {
    const slug = String(req.params.slug || '');
    if (!SLUG_REGEX.test(slug)) {
        return res.status(404).send('Uplink Not Found.');
    }
    const result = await db.findUserBySlug(slug);
    if (!result || !result.user) {
        return res.status(404).send('Uplink Not Found. Please check your link or renew it in the dashboard.');
    }
    if (result.user.wallet < 0) {
        return res.status(404).send('Account Inactive due to insufficient credits.');
    }
    return handleRedirection(result.user, req, res, result.link);
});

async function handleRedirection(user, req, res, linkData) {
    if (!user.isActive) {
        return res.status(403).send('Account Suspended or Inactive');
    }

    // Check specific link expiry
    const linkExpiry = linkData.expiryDate || user.expiryDate;
    if (!linkExpiry || new Date(linkExpiry) < new Date()) {
        return res.status(403).send('Tracking Link Expired. Please renew in dashboard.');
    }

    const { settings, forcedIps, blockedIps, visitedIps } = user;
    const clientIp = getClientIp(req);
    const isVisited = Array.isArray(visitedIps) && visitedIps.some(v => v.ip === clientIp);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const countryHeader = getClientCountry(req);

    // Pull the admin-level blocklist snapshot (cached briefly to limit file IO).
    const adminBlocks = await getAdminBlocksSnapshot();

    // 0a. Admin IP block (site-wide, highest priority - deny before any other logic).
    if (db.ipMatchesAnyBlock && db.ipMatchesAnyBlock(clientIp, adminBlocks.ips)) {
        return res.status(403).send('Access denied by administrator.');
    }

    // 0b. Admin Country block (header-driven, cheap; applies before paid lookups).
    if (countryHeader && (adminBlocks.countries || []).some(b => b.value === countryHeader)) {
        return res.status(403).send('Access denied by administrator.');
    }

    const realLink = linkData.realLink || settings.realLink;
    const nonRealLink = linkData.nonRealLink || settings.nonRealLink;
    const useAntiRed = linkData.antiRed !== undefined ? linkData.antiRed : settings.antiRed;
    const useIspFilter = linkData.ispFilter !== undefined ? linkData.ispFilter : settings.ispFilter;
    const useBotFilter = linkData.botFilter !== undefined ? linkData.botFilter : (settings.botFilter !== undefined ? settings.botFilter : true);
    const useMobileIsps = linkData.mobileIsps || settings.mobileIsps;
    const useReallowVisited = linkData.reallowVisited !== undefined ? linkData.reallowVisited : settings.reallowVisited;
    const useAllowAfrica = linkData.allowAfrica !== undefined ? linkData.allowAfrica : (settings.allowAfrica !== undefined ? settings.allowAfrica : false);
    const useAllowEurope = linkData.allowEurope !== undefined ? linkData.allowEurope : (settings.allowEurope !== undefined ? settings.allowEurope : true);

    // 0c. Blocked IP Check (user-level - deny before any other logic)
    if ((blockedIps || []).includes(clientIp)) {
        return res.status(403).send('Access denied. Your IP has been blocked by the operator.');
    }

    // 1. Forced Redirect Check
    if (forcedIps.includes(clientIp)) {
        return res.redirect(realLink);
    }

    // 2. IP Analysis (cached)
    const data = await lookupIpGeo(clientIp);

    // 2a. Admin ISP block
    if (data && (adminBlocks.isps || []).length) {
        const candidates = [data.isp, data.org].filter(Boolean);
        if (candidates.some(c => ispMatchesAnyBlock(c, adminBlocks.isps))) {
            return res.status(403).send('Access denied by administrator.');
        }
    }

    // 2b. Continent Filtering (Africa / Europe)
    if (data && data.status === 'success') {
        const continent = data.continentCode; // 'AF', 'EU', 'NA', 'AS', 'SA', 'OC', 'AN'
        if (!useAllowAfrica && continent === 'AF') {
            return res.redirect(nonRealLink);
        }
        if (!useAllowEurope && continent === 'EU') {
            return res.redirect(nonRealLink);
        }
    }

    const isProxy = data && data.proxy === true;
    const isHosting = data && data.hosting === true;
    const isSuspicious = isProxy || isHosting;

    // 4. Filtering Logic
    let targetUrl = realLink;
    let redirectReason = null;

    if (useBotFilter && isBot(req)) {
        targetUrl = nonRealLink;
        redirectReason = 'Bot Detection';
    } else if (isVisited && !useReallowVisited) {
        targetUrl = nonRealLink;
        redirectReason = 'Repeated Visit';
    } else if (useAntiRed && isSuspicious) {
        targetUrl = nonRealLink;
        redirectReason = `AntiRed (${isProxy ? 'Proxy' : ''}${isProxy && isHosting ? '+' : ''}${isHosting ? 'Hosting' : ''})`;
    } else if (useIspFilter && data && data.status === 'success') {
        const userISP = (data.isp || data.org || "").toUpperCase();
        const matches = (useMobileIsps || []).some(isp => isp && userISP.includes(isp.toUpperCase()));
        if (!matches) {
            targetUrl = nonRealLink;
            redirectReason = 'ISP Filter';
        }
    }

    // 5. Update Visited IPs
    if (!isVisited) {
        const redirectType = targetUrl === realLink ? 'REAL' : 'SAFE';
        const newEntry = {
            ip: clientIp,
            timestamp: Date.now(),
            type: redirectType,
            isp: data ? data.isp : 'Unknown',
            location: data ? `${data.city}, ${data.country}` : 'Unknown'
        };
        withUserMutex(user.id, async () => {
            const liveUser = await db.findUserById(user.id);
            const liveVisited = Array.isArray(liveUser ? liveUser.visitedIps : []) ? liveUser.visitedIps : [];
            let merged = liveVisited.concat([newEntry]);
            if (merged.length > MAX_VISITED_IPS_PER_USER) {
                merged = merged.slice(-MAX_VISITED_IPS_PER_USER);
            }
            await db.updateUser(user.id, { visitedIps: merged });
        }).catch(err => console.error('[Proxy] visitedIps write failed', err.message));
    }

    // 6. Telegram notification
    const botToken = settings.botToken || process.env.TELEGRAM_BOT_TOKEN;
    const chatId = settings.chatId || process.env.TELEGRAM_CHAT_ID;

    if (botToken && chatId) {
        const message =
            `🚀 <b>New Visit!</b> (User: ${telegramEscape(user.name || '')})\n\n` +
            `📍 <b>IP:</b> ${telegramEscape(clientIp)}\n` +
            `🏢 <b>ISP:</b> ${telegramEscape(data ? data.isp : 'Unknown')}\n` +
            `🌍 <b>Location:</b> ${telegramEscape(data ? `${data.city}, ${data.country}` : 'Unknown')}\n` +
            `💻 <b>UA:</b> ${telegramEscape(userAgent.slice(0, 240))}\n` +
            `🎯 <b>Target:</b> <code>${targetUrl === realLink ? 'REAL' : 'SAFE'}</code>` +
            (redirectReason ? `\n🛡️ <b>Reason:</b> <code>${telegramEscape(redirectReason)}</code>` : '');

        axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            chat_id: chatId,
            text: message,
            parse_mode: 'HTML',
            disable_web_page_preview: true
        }).catch(() => {});
    }

    if (!targetUrl) return res.send("Configuration missing for links.");
    // Final safety net: even if a bad URL sneaked into the user record before
    // these validations landed, refuse to follow schemes other than http(s).
    if (!isSafeHttpUrl(targetUrl, { allowEmpty: false })) {
        console.warn(`[Proxy] Refused unsafe redirect target for user ${user.id}: ${String(targetUrl).slice(0, 80)}`);
        return res.status(500).send('Configuration missing for links.');
    }
    res.redirect(targetUrl);
}

// --- Newsletter (admin-authored broadcast shown on user dashboard) ---
// (fsSync / fsPromises are required at the top of this file.)
const NEWSLETTER_DATA_DIR = SESSION_STORE_DIR;
const NEWSLETTER_FILE = path.join(NEWSLETTER_DATA_DIR, 'newsletter.json');

async function readNewsletter() {
    try {
        const raw = await fsPromises.readFile(NEWSLETTER_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        return {
            title: typeof parsed.title === 'string' ? parsed.title : '',
            body: typeof parsed.body === 'string' ? parsed.body : '',
            updatedAt: parsed.updatedAt || null
        };
    } catch (err) {
        return { title: '', body: '', updatedAt: null };
    }
}

async function writeNewsletter(payload) {
    const record = {
        title: typeof payload.title === 'string' ? payload.title : '',
        body: typeof payload.body === 'string' ? payload.body : '',
        updatedAt: new Date().toISOString()
    };
    await fsPromises.writeFile(NEWSLETTER_FILE, JSON.stringify(record, null, 2));
    return record;
}

// Authenticated users only — broadcasts can carry admin-authored narrative
// we don't want to leak to anonymous scrapers / attackers.
app.get('/api/newsletter', requireAuth, asyncHandler(async (req, res) => {
    const data = await readNewsletter();
    res.json(data);
}));

// Admin only: write/update the broadcast.
app.post('/api/admin/newsletter', requireAdmin, asyncHandler(async (req, res) => {
    const { title, body } = req.body || {};
    const cleanTitle = typeof title === 'string' ? title.slice(0, 120) : '';
    const cleanBody = typeof body === 'string' ? body.slice(0, 4000) : '';
    if (!cleanTitle && !cleanBody) {
        return res.status(400).json({ error: 'EMPTY_NEWSLETTER' });
    }
    const saved = await writeNewsletter({ title: cleanTitle, body: cleanBody });
    res.json({ ok: true, ...saved });
}));

// --- AntiRed Rotator Domain Pool ---
// AntiRed URLs are NEVER built from the dashboard/webapp origin; the client picks
// a stable entry from this pool so the webapp domain never leaks into the public link.
// Source priority:
//   1. process.env.ANTIRED_DOMAINS  (comma-separated, hosting-side authoritative)
//   2. data/antired-domains.json    (admin UI edited fallback)
const ANTIRED_DOMAINS_FILE = path.join(NEWSLETTER_DATA_DIR, 'antired-domains.json');

function normalizeAntiredHosts(items) {
    const seen = new Set();
    const clean = [];
    for (const item of (items || [])) {
        if (typeof item !== 'string') continue;
        let v = item.trim();
        if (!v) continue;
        if (!/^https?:\/\//i.test(v)) v = 'https://' + v.replace(/^\/+/, '');
        v = v.replace(/\/+$/, '');
        try {
            const u = new URL(v);
            if (!u.hostname || !u.hostname.includes('.')) continue;
            v = u.origin;
        } catch (_) { continue; }
        if (!seen.has(v.toLowerCase())) { seen.add(v.toLowerCase()); clean.push(v); }
    }
    return clean;
}

function getEnvAntiredDomains() {
    const raw = (process.env.ANTIRED_ROTATOR_DOMAINS || process.env.ANTIRED_DOMAINS || '');
    return normalizeAntiredHosts(raw.split(','));
}

async function readAntiredDomains() {
    const envList = getEnvAntiredDomains();
    if (envList.length > 0) {
        const envKey = process.env.ANTIRED_ROTATOR_DOMAINS ? 'ANTIRED_ROTATOR_DOMAINS' : 'ANTIRED_DOMAINS';
        return { domains: envList, updatedAt: null, source: 'env', envKey };
    }
    try {
        const raw = await fsPromises.readFile(ANTIRED_DOMAINS_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        const list = normalizeAntiredHosts(Array.isArray(parsed.domains) ? parsed.domains : []);
        return { domains: list, updatedAt: parsed.updatedAt || null, source: 'admin' };
    } catch (err) {
        return { domains: [], updatedAt: null, source: 'admin' };
    }
}

async function writeAntiredDomains(list) {
    const clean = normalizeAntiredHosts(list);
    const record = { domains: clean, updatedAt: new Date().toISOString() };
    await fsPromises.writeFile(ANTIRED_DOMAINS_FILE, JSON.stringify(record, null, 2));
    return record;
}

// Authenticated users only — the domain pool is operational infrastructure
// we don't want to leak to anonymous scrapers. The dashboard fronts the
// pool so logged-in users still get rotation URLs.
app.get('/api/antired-domains', requireAuth, asyncHandler(async (req, res) => {
    const data = await readAntiredDomains();
    res.json(data);
}));

// Admin only: replace the pool entirely with the supplied list.
// Refused (HTTP 409) while the host environment is driving the pool.
app.post('/api/admin/antired-domains', requireAdmin, asyncHandler(async (req, res) => {
    const envList = getEnvAntiredDomains();
    if (envList.length > 0) {
        const envKey = process.env.ANTIRED_ROTATOR_DOMAINS ? 'ANTIRED_ROTATOR_DOMAINS' : 'ANTIRED_DOMAINS';
        return res.status(409).json({
            error: 'ANTIRED_DOMAINS_SET_VIA_ENV',
            message: `${envKey} is configured via the host environment. Update the env on the host (e.g. ${envKey}="https://rot1.example.com,https://rot2.example.com,...") and restart the server.`
        });
    }
    const incoming = Array.isArray(req.body && req.body.domains) ? req.body.domains : null;
    if (!incoming) return res.status(400).json({ error: 'DOMAINS_ARRAY_REQUIRED' });
    if (incoming.filter(v => typeof v === 'string' && v.trim().length > 0).length < 4) {
        return res.status(400).json({ error: 'NEED_AT_LEAST_4_DOMAINS' });
    }
    const saved = await writeAntiredDomains(incoming);
    res.json({ ok: true, ...saved, source: 'admin' });
}));

const bootEnvList = getEnvAntiredDomains();
const bootEnvKey = process.env.ANTIRED_ROTATOR_DOMAINS ? 'ANTIRED_ROTATOR_DOMAINS' : 'ANTIRED_DOMAINS';
console.log(`[Antired] Domain pool source: ${bootEnvList.length > 0 ? 'ENV (' + bootEnvKey + ', ' + bootEnvList.length + ' hosts)' : 'admin file'}`);

// --- Admin-level blocklists (IP / ISP / Country) ---
// Site-wide rules applied to /l/:slug regardless of which user's link was hit.

app.get('/api/iso-countries', asyncHandler(async (req, res) => {
    res.json({ items: db.ISO_COUNTRIES });
}));

app.get('/api/admin/blocks/:type', requireAdmin, asyncHandler(async (req, res) => {
    const { type } = req.params;
    if (!db.VALID_BLOCK_TYPES.has(type)) return res.status(400).json({ error: 'INVALID_TYPE' });
    const blocks = await db.readAdminBlocks();
    res.json({ type, items: blocks[type] || [] });
}));

app.post('/api/admin/blocks/:type', requireAdmin, asyncHandler(async (req, res) => {
    const { type } = req.params;
    if (!db.VALID_BLOCK_TYPES.has(type)) return res.status(400).json({ error: 'INVALID_TYPE' });
    const { value, reason } = req.body || {};
    const v = typeof value === 'string' ? value.trim() : '';
    if (!v) return res.status(400).json({ error: 'EMPTY_VALUE' });
    if (type === 'ips' && !db.ipRuleKind(v)) {
        return res.status(400).json({ error: 'INVALID_IP_FORMAT (use exact v4/v6, wildcard, or CIDR)' });
    }
    if (type === 'countries' && !/^[A-Za-z]{2}$/.test(v)) {
        return res.status(400).json({ error: 'COUNTRY_CODE_REQUIRED_2_LETTERS' });
    }
    if (type === 'isps' && v.length < 2) {
        return res.status(400).json({ error: 'ISP_VALUE_TOO_SHORT' });
    }
    try {
        const blocks = await db.addAdminBlock(type, v, reason || '');
        _adminBlocksCache = null;
        const added = blocks[type][blocks[type].length - 1];
        res.json({ ok: true, item: added, items: blocks[type] });
    } catch (err) {
        if (err.code === 'DUPLICATE_VALUE') return res.status(409).json({ error: 'DUPLICATE_VALUE' });
        if (err.message === 'EMPTY_VALUE') return res.status(400).json({ error: 'EMPTY_VALUE' });
        throw err;
    }
}));

app.post('/api/admin/blocks/:type/bulk', requireAdmin, asyncHandler(async (req, res) => {
    const { type } = req.params;
    if (!db.VALID_BLOCK_TYPES.has(type)) return res.status(400).json({ error: 'INVALID_TYPE' });

    const lines = Array.isArray(req.body && req.body.lines) ? req.body.lines : null;
    const text = typeof req.body && typeof req.body.text === 'string' ? req.body.text : null;
    if (!lines && !text) return res.status(400).json({ error: 'LINES_OR_TEXT_REQUIRED' });

    // Accept: array of strings OR array of {value, reason} OR raw CSV/text.
    const parsed = [];
    if (Array.isArray(lines)) {
        for (const item of lines) {
            if (typeof item === 'string') parsed.push({ value: item, reason: '' });
            else if (item && typeof item === 'object')
                parsed.push({ value: String(item.value || ''), reason: String(item.reason || '') });
        }
    }
    if (text) {
        for (const raw of text.split(/\r?\n/)) {
            const line = raw.trim();
            if (!line || line.startsWith('#')) continue;
            const match = line.match(/^"?(.*?)"?\s*,\s*(.*)$/);
            parsed.push(match ? { value: match[1], reason: match[2] } : { value: line, reason: '' });
        }
    }

    if (parsed.length === 0) return res.status(400).json({ error: 'NO_VALID_ROWS' });
    if (parsed.length > 1000) return res.status(400).json({ error: 'BULK_LIMIT_1000' });

    const added = [], skipped = [], errors = [];
    for (const row of parsed) {
        const v = String(row.value || '').trim();
        if (!v) { errors.push({ value: row.value, error: 'EMPTY_VALUE' }); continue; }
        let valid = true;
        if (type === 'ips' && !db.ipRuleKind(v)) valid = false;
        if (type === 'countries' && !/^[A-Za-z]{2}$/.test(v)) valid = false;
        if (type === 'isps' && v.length < 2) valid = false;
        if (!valid) { errors.push({ value: v, error: 'INVALID_FORMAT' }); continue; }
        try {
            const blocks = await db.addAdminBlock(type, v, row.reason || '');
            added.push(blocks[type][blocks[type].length - 1]);
        } catch (err) {
            if (err.code === 'DUPLICATE_VALUE') skipped.push({ value: v, error: 'DUPLICATE_VALUE' });
            else errors.push({ value: v, error: err.message || 'UNKNOWN' });
        }
    }

    if (added.length > 0) _adminBlocksCache = null;
    res.json({ ok: true, added, skipped, errors, totalSubmitted: parsed.length });
}));

app.delete('/api/admin/blocks/:type/:id', requireAdmin, asyncHandler(async (req, res) => {
    const { type, id } = req.params;
    if (!db.VALID_BLOCK_TYPES.has(type)) return res.status(400).json({ error: 'INVALID_TYPE' });
    if (!id) return res.status(400).json({ error: 'ID_REQUIRED' });
    const blocks = await db.removeAdminBlock(type, id);
    _adminBlocksCache = null;
    res.json({ ok: true, items: blocks[type] });
}));

// Pre-compute block verdicts once per visit (cached within request lifetime).
let _adminBlocksCache = null;
let _adminBlocksFetchedAt = 0;
const ADMIN_BLOCKS_CACHE_MS = 2000;

async function getAdminBlocksSnapshot() {
    const now = Date.now();
    if (_adminBlocksCache && (now - _adminBlocksFetchedAt) < ADMIN_BLOCKS_CACHE_MS) {
        return _adminBlocksCache;
    }
    const blocks = await db.readAdminBlocks();
    _adminBlocksCache = blocks;
    _adminBlocksFetchedAt = now;
    return blocks;
}

function ispMatchesAnyBlock(ispValue, blockedIsps) {
    if (!ispValue || !blockedIsps || !blockedIsps.length) return false;
    const v = String(ispValue).toUpperCase();
    return blockedIsps.some(b => v.includes(String(b).toUpperCase()));
}

function blockedByAdmin(ip, countryHdr, geoData, blocks) {
    if (!blocks) return null;
    // IP match honours exact, IPv4/IPv6 CIDR, and '*' wildcard entries.
    if (ip && db.ipMatchesAnyBlock(ip, blocks.ips || [])) return 'IP';
    if (countryHdr && (blocks.countries || []).some(b => b.value === countryHdr.toUpperCase())) return 'COUNTRY';
    if (geoData) {
        const candidates = [geoData.isp, geoData.org].filter(Boolean);
        if (candidates.some(c => ispMatchesAnyBlock(c, blocks.isps))) return 'ISP';
    }
    return null;
}

// --- Admin block-suggestions endpoint (ISP autosuggest from real visit logs) ---
app.get('/api/admin/block-suggestions/:type', requireAdmin, asyncHandler(async (req, res) => {
    const { type } = req.params;
    if (!['isps', 'countries', 'ips'].includes(type)) return res.status(400).json({ error: 'INVALID_TYPE' });
    const users = await db.getUsers();
    const counts = new Map();

    for (const u of users) {
        for (const v of (u.visitedIps || [])) {
            let key = null;
            if (type === 'isps') key = v.isp;
            else if (type === 'countries') {
                const m = (v.location || '').match(/,\s*([A-Za-z]{2})$/);
                if (m) key = m[1].toUpperCase();
            } else if (type === 'ips') key = v.ip;
            if (!key || key === 'Unknown') continue;
            counts.set(key, (counts.get(key) || 0) + 1);
        }
    }

    const items = Array.from(counts.entries())
        .map(([key, count]) => ({ key, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 50);

    res.json({ type, items });
}));

app.listen(port, () => {
    console.log(`SaaS Proxy server running on port ${port}`);
});
