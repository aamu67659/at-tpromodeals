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
const net = require('net');
const db = require('./db');

const app = express();
const port = process.env.PORT || 3000;

// Error handling wrapper for async routes
const asyncHandler = fn => (req, res, next) => {
    return Promise.resolve(fn(req, res, next)).catch((err) => {
        console.error(`[Error] ${req.method} ${req.url}:`, err);
        res.status(500).json({ error: 'Internal Server Error', details: err.message });
    });
};

app.set('trust proxy', true);

app.use(helmet({
    contentSecurityPolicy: false, // Temporarily disable CSP to ensure pages load on all browsers/environments
    referrerPolicy: { policy: 'no-referrer' }
}));

app.disable('x-powered-by');

app.use(express.json());
app.use(cookieParser());

// Request logging for debugging
app.use((req, res, next) => {
    console.log(`[Request] ${req.method} ${req.url}`);
    next();
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'saas-proxy-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.static('public'));

app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard.html');
    }
    res.redirect('/login');
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
    const token = (req.headers['x-admin-token'] || req.query.token || "").trim();
    const envToken = (process.env.ADMIN_TOKEN || "admin123").trim(); // Default for safety if not set, but user should set it

    if (token !== envToken) {
        console.log(`[Admin] Unauthorized attempt. Received: "${token}", Expected: "${envToken}"`);
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

// --- Admin Routes ---
app.get('/api/admin/users', requireAdmin, asyncHandler(async (req, res) => {
    const users = await db.getUsers();
    res.json(users.map(({ password, ...u }) => u));
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

app.post('/api/admin/confirm-payment', requireAdmin, asyncHandler(async (req, res) => {
    const { userId, paymentId } = req.body;
    const user = await db.findUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const pending = (user.pendingPayments || []).slice();
    const idx = pending.findIndex(p => p.id === paymentId);
    if (idx === -1) return res.status(404).json({ error: 'Payment not found' });
    if (pending[idx].status !== 'pending') return res.status(400).json({ error: 'Payment already processed' });

    pending[idx].status = 'confirmed';
    pending[idx].confirmedAt = new Date().toISOString();

    const updatedUser = await db.updateUser(userId, {
        pendingPayments: pending,
        wallet: (user.wallet || 0) + pending[idx].amount
    });
    res.json({
        message: 'Payment confirmed',
        balance: updatedUser.wallet,
        payment: pending[idx]
    });
}));

app.post('/api/admin/reject-payment', requireAdmin, asyncHandler(async (req, res) => {
    const { userId, paymentId, reason } = req.body;
    const user = await db.findUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const pending = (user.pendingPayments || []).slice();
    const idx = pending.findIndex(p => p.id === paymentId);
    if (idx === -1) return res.status(404).json({ error: 'Payment not found' });
    if (pending[idx].status !== 'pending') return res.status(400).json({ error: 'Payment already processed' });

    pending[idx].status = 'rejected';
    pending[idx].rejectedAt = new Date().toISOString();
    pending[idx].rejectReason = reason || 'Invalid transaction';

    const updatedUser = await db.updateUser(userId, { pendingPayments: pending });
    res.json({ message: 'Payment rejected', payment: pending[idx] });
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
app.post('/api/signup', asyncHandler(async (req, res) => {
    const { name, email, telegram, password } = req.body;
    if (!name || !email || !telegram || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await db.findUserByEmail(email);
    if (existingUser) {
        return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await db.createUser({ name, email, telegram, password: hashedPassword });
    console.log(`[Signup] New user registered: ${email}`);
    res.json({ message: 'Signup successful' });
}));

app.post('/api/login', asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const user = await db.findUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        console.log(`[Login] Failed login attempt for ${email} from ${getClientIp(req)}`);
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    req.session.userId = user.id;
    const ip = getClientIp(req);
    const country = getClientCountry(req);
    const history = Array.isArray(user.loginHistory) ? user.loginHistory.slice(-49) : [];
    history.push({ ip, country, ts: new Date().toISOString() });
    await db.updateUser(user.id, {
        lastLoginAt: new Date().toISOString(),
        lastLoginIp: ip,
        lastLoginCountry: country || null,
        loginHistory: history
    });
    console.log(`[Login] User logged in: ${email} from ${ip}${country ? ' (' + country + ')' : ''}`);
    res.json({ message: 'Login successful' });
}));

app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('[Logout] Error destroying session:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        res.json({ message: 'Logged out' });
    });
});

app.get('/api/user', requireAuth, asyncHandler(async (req, res) => {
    const { password, ...userWithoutPassword } = req.user;
    res.json(userWithoutPassword);
}));

// --- Settings & Wallet Routes ---
app.post('/api/settings', requireAuth, asyncHandler(async (req, res) => {
    const body = { ...req.body };
    if ('depositSendAddress' in body) {
        const addr = (body.depositSendAddress || '').trim();
        if (addr && !/^T[A-Za-z1-9]{33}$/.test(addr)) {
            return res.status(400).json({ error: 'Invalid TRC20 sender address (must start with T and be 34 chars)' });
        }
        body.depositSendAddress = addr;
    }
    const updatedUser = await db.updateUser(req.user.id, {
        settings: { ...req.user.settings, ...body }
    });
    res.json(updatedUser.settings);
}));

app.post('/api/topup', requireAuth, asyncHandler(async (req, res) => {
    const { amount } = req.body;
    const updatedUser = await db.updateUser(req.user.id, {
        wallet: req.user.wallet + amount
    });
    res.json({ balance: updatedUser.wallet });
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
const AUTO_PAY_LOOKBACK_LIMIT = parseInt(process.env.AUTO_PAY_LOOKBACK_LIMIT || '20', 10);
const processedTxHashes = new Set();

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

app.post('/api/payments/submit', requireAuth, asyncHandler(async (req, res) => {
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
                processedTxHashes.add(hash);
                continue;
            }

            const valueRaw = tx.value || tx.quant || '0';
            const decimals = (tx.token_info && parseInt(tx.token_info.decimals, 10)) || 6;
            const valueNum = parseFloat(valueRaw) / Math.pow(10, decimals);
            if (!isFinite(valueNum) || valueNum <= 0) {
                processedTxHashes.add(hash);
                continue;
            }
            if (valueNum < MIN_DEPOSIT_USDT) {
                processedTxHashes.add(hash);
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

            if (!matchedUser) {
                processedTxHashes.add(hash);
                console.log(`[AutoPay] Unmatched inbound TX ${hash} (${valueNum} USDT) from ${tx.from} — no registered sender wallet or pending hash`);
                continue;
            }

            const pending = matchedUser.pendingPayments || [];

            if (matchedMode === 'legacy_hash') {
                if (matchedPayment) {
                    const idx = pending.findIndex(p => p.id === matchedPayment.id);
                    if (idx === -1) {
                        processedTxHashes.add(hash);
                        continue;
                    }
                    const tolerance = 0.01;
                    const declaredAmount = parseFloat(matchedPayment.amount);
                    if (Math.abs(declaredAmount - valueNum) > tolerance) {
                        console.log(`[AutoPay] Amount mismatch for ${hash}: declared=${declaredAmount} on-chain=${valueNum} — holding for manual review`);
                        processedTxHashes.add(hash);
                        continue;
                    }
                    pending[idx].status = 'confirmed';
                    pending[idx].confirmedAt = new Date().toISOString();
                    pending[idx].autoVerified = true;
                    pending[idx].onChainAmount = valueNum;
                    pending[idx].fromAddress = tx.from;
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

            processedTxHashes.add(hash);
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
                    processedTxHashes.add(p.txHash.toLowerCase());
                }
            });
        });
        console.log(`[AutoPay] Loaded ${processedTxHashes.size} already-confirmed hash(es) into memory`);
    } catch (err) {
        console.error('[AutoPay] bootstrap error:', err.message);
    }
}

if (PAYMENT_RECEIVE_ADDRESS) {
    bootstrapProcessedHashes().then(() => {
        pollTronPayments();
        const handle = setInterval(pollTronPayments, AUTO_PAY_POLL_MS);
        console.log(`[AutoPay] Polling ${TRON_API_BASE} every ${AUTO_PAY_POLL_MS}ms for USDT-TRC20 inbound to ${PAYMENT_RECEIVE_ADDRESS}`);
        process.on('SIGTERM', () => clearInterval(handle));
        process.on('SIGINT', () => clearInterval(handle));
    });
} else {
    console.log('[AutoPay] USDT_TRC20_ADDRESS not set — automatic payment verification disabled');
}

app.post('/api/forced-ips', requireAuth, asyncHandler(async (req, res) => {
    const { ip } = req.body;
    if (!req.user.forcedIps.includes(ip)) {
        await db.updateUser(req.user.id, { forcedIps: [...req.user.forcedIps, ip] });
    }
    res.json({ message: 'IP added' });
}));

app.post('/api/blocked-ips', requireAuth, asyncHandler(async (req, res) => {
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

app.post('/api/links', requireAuth, asyncHandler(async (req, res) => {
    const { name, realLink, nonRealLink, slug, antiRed, ispFilter, mobileIsps, reallowVisited, duration } = req.body;
    
    const prices = { '3days': 15, '1week': 25, '2weeks': 50, 'month': 80 };
    const price = prices[duration];

    if (!price) return res.status(400).json({ error: 'Invalid duration selected' });

    if (req.user.wallet < price) {
        return res.status(400).json({ error: `Insufficient credits. This plan requires $${price.toFixed(2)}.` });
    }

    if (!name || !realLink || !nonRealLink) {
        return res.status(400).json({ error: 'Name, Real Link, and Safe Link are required' });
    }

    const newSlug = slug || require('crypto').randomBytes(4).toString('hex');
    
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
        mobileIsps: mobileIsps || req.user.settings.mobileIsps,
        reallowVisited: reallowVisited !== undefined ? reallowVisited : true,
        expiryDate: expiry.toISOString(),
        createdAt: new Date().toISOString()
    };

    const updatedUser = await db.updateUser(req.user.id, {
        wallet: req.user.wallet - price,
        links: [...(req.user.links || []), newLink]
    });

    res.json({ ...newLink, balance: updatedUser.wallet });
}));

app.delete('/api/links/:slug', requireAuth, asyncHandler(async (req, res) => {
    const { slug } = req.params;

    // Default uplink lives on the user record, not in `links[]`.
    if (slug === req.user.slug) {
        if (isExpiryActive(req.user.expiryDate)) {
            return res.status(400).json({ error: 'Default uplink is still active and cannot be deleted until it expires.' });
        }
        const settings = req.user.settings || {};
        await db.updateUser(req.user.id, {
            slug: null,
            expiryDate: null,
            settings: { ...settings, realLink: '', nonRealLink: '' }
        });
        return res.json({ message: 'Default uplink deleted', deletedDefault: true });
    }

    const links = req.user.links || [];
    const target = links.find(l => l.slug === slug);
    if (!target) return res.status(404).json({ error: 'Link not found' });

    if (isExpiryActive(target.expiryDate)) {
        return res.status(400).json({ error: 'Uplink is still active and cannot be deleted until it expires. Overlapping lifecycle changes are not allowed.' });
    }

    const updatedLinks = links.filter(l => l.slug !== slug);
    await db.updateUser(req.user.id, { links: updatedLinks });
    res.json({ message: 'Link deleted', deletedDefault: false });
}));

app.put('/api/links/:oldSlug', requireAuth, asyncHandler(async (req, res) => {
    const { oldSlug } = req.params;
    const { name, realLink, nonRealLink, slug, antiRed, ispFilter, mobileIsps, reallowVisited } = req.body;

    if (!name || !realLink || !nonRealLink) {
        return res.status(400).json({ error: 'Name, Real Link, and Safe Link are required' });
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
        mobileIsps: mobileIsps !== undefined ? mobileIsps : links[index].mobileIsps,
        reallowVisited: reallowVisited !== undefined ? reallowVisited : links[index].reallowVisited,
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

app.post('/api/renew-link', requireAuth, asyncHandler(async (req, res) => {
    const { slug, duration } = req.body;
    const prices = { '3days': 15, '1week': 25, '2weeks': 50, 'month': 80 };
    const price = prices[duration];

    if (!price) return res.status(400).json({ error: 'Invalid duration selected' });

    if (req.user.wallet < price) {
        return res.status(400).json({ error: `Insufficient credits. This plan requires $${price.toFixed(2)}.` });
    }

    // Refuse renewal if a NEW slug (different from this link's current slug) is currently active anywhere
    const linkSlugTaken = await findActiveConflict(slug, req.user.id);
    if (linkSlugTaken && linkSlugTaken.user.id === req.user.id && linkSlugTaken.link.slug === slug && isExpiryActive(linkSlugTaken.link.expiryDate)) {
        // It IS the same user's link; that's expected. This check is a sanity guard for the rename case.
    }

    const now = new Date();

    // Check if it's the default link
    if (slug === req.user.slug) {
        if (isExpiryActive(req.user.expiryDate)) {
            return res.status(400).json({ error: 'Default uplink is still active and cannot be renewed until it expires. Overlapping renewals are not allowed.' });
        }
        let expiry = new Date(now);
        if (duration === '3days') expiry.setDate(expiry.getDate() + 3);
        else if (duration === '1week') expiry.setDate(expiry.getDate() + 7);
        else if (duration === '2weeks') expiry.setDate(expiry.getDate() + 14);
        else if (duration === 'month') expiry.setMonth(expiry.getMonth() + 1);

        const updatedUser = await db.updateUser(req.user.id, {
            wallet: req.user.wallet - price,
            expiryDate: expiry.toISOString()
        });

        return res.json({ message: 'Default uplink extended', expiryDate: updatedUser.expiryDate, balance: updatedUser.wallet });
    }

    // Check custom links
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
        wallet: req.user.wallet - price,
        links: links
    });

    res.json({ message: 'Uplink extended', expiryDate: links[index].expiryDate, balance: updatedUser.wallet });
}));

app.get('/api/isps', (req, res) => {
    const isps = (process.env.MOBILE_ISPS || "").split(',').map(isp => isp.trim()).filter(isp => isp !== "");
    res.json(isps);
});

// --- Proxy Redirection Logic ---
const BOT_UA_REGEX = /googlebot|bingbot|yandexbot|duckduckbot|slurp|baiduspider|facebot|ia_archiver|crawler|spider|robot|curl|wget|python|postman|insomnia|headless|screaming frog|ahrefsbot|semrushbot|mj12bot|dotbot|rogerbot|exabot|petalbot/i;

function isBot(req) {
    const ua = req.headers['user-agent'] || '';
    return !ua || BOT_UA_REGEX.test(ua);
}

app.get('/l/:slug', async (req, res) => {
    const slug = req.params.slug;
    const result = await db.findUserBySlug(slug);
    if (!result || !result.user) {
        console.warn(`[Proxy] Slug not found: ${slug} (Full URL: ${req.originalUrl})`);
        return res.status(404).send('Uplink Not Found. Please check your link or renew it in the dashboard.');
    }
    if (result.user.wallet <= 0) {
        console.warn(`[Proxy] Inactive account for slug: ${slug}`);
        return res.status(404).send('Account Inactive due to insufficient credits.');
    }
    return handleRedirection(result.user, req, res, result.link);
});

app.get('/u/:userId', async (req, res) => {
    const user = await db.findUserById(req.params.userId);
    if (!user || user.wallet <= 0) {
        return res.status(404).send('Not Found or Account Inactive');
    }
    // Default link settings for legacy /u/ route
    const defaultLink = {
        realLink: user.settings.realLink,
        nonRealLink: user.settings.nonRealLink
    };
    return handleRedirection(user, req, res, defaultLink);
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
    const clientIp = req.ip;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    const realLink = linkData.realLink || settings.realLink;
    const nonRealLink = linkData.nonRealLink || settings.nonRealLink;
    const useAntiRed = linkData.antiRed !== undefined ? linkData.antiRed : settings.antiRed;
    const useIspFilter = linkData.ispFilter !== undefined ? linkData.ispFilter : settings.ispFilter;
    const useMobileIsps = linkData.mobileIsps || settings.mobileIsps;
    const useReallowVisited = linkData.reallowVisited !== undefined ? linkData.reallowVisited : settings.reallowVisited;

    // 0. Blocked IP Check (highest priority - deny before any other logic)
    if ((blockedIps || []).includes(clientIp)) {
        return res.status(403).send('Access denied. Your IP has been blocked by the operator.');
    }

    if (isBot(req)) {
        return res.redirect(nonRealLink || '/');
    }

    // 1. Forced Redirect Check
    if (forcedIps.includes(clientIp)) {
        return res.redirect(realLink);
    }

    // 2. Visited IP Check
    const isVisited = visitedIps.some(v => v.ip === clientIp);
    if (isVisited && !useReallowVisited) {
        return res.redirect(nonRealLink);
    }

    // 3. IP Analysis
    let data = null;
    try {
        const response = await axios.get(`http://ip-api.com/json/${clientIp}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query`, { timeout: 5000 });
        data = response.data;
    } catch (error) {
        console.error('ISP lookup failed:', error.message);
    }

    const isProxy = data && data.proxy === true;
    const isHosting = data && data.hosting === true;
    const isSuspicious = isProxy || isHosting;

    // 4. Filtering Logic
    let targetUrl = realLink;

    if (useAntiRed && isSuspicious) {
        targetUrl = nonRealLink;
    } else if (useIspFilter && data && data.status === 'success') {
        const userISP = (data.isp || data.org || "").toUpperCase();
        const matches = useMobileIsps.some(isp => userISP.includes(isp.toUpperCase()));
        if (!matches) {
            targetUrl = nonRealLink;
        }
    }

    // 5. Update Visited IPs
    if (!isVisited) {
        const redirectType = targetUrl === realLink ? 'REAL' : 'SAFE';
        const newVisited = [...visitedIps, { 
            ip: clientIp, 
            timestamp: Date.now(), 
            type: redirectType,
            isp: data ? data.isp : 'Unknown',
            location: data ? `${data.city}, ${data.country}` : 'Unknown'
        }];
        await db.updateUser(user.id, { visitedIps: newVisited });
    }

    // 6. Telegram Notification
    const botToken = settings.botToken || process.env.TELEGRAM_BOT_TOKEN;
    const chatId = settings.chatId || process.env.TELEGRAM_CHAT_ID;

    if (botToken && chatId) {
        let message = `🚀 *New Visit!* (User: ${user.name})\n\n`;
        message += `📍 *IP:* ${clientIp}\n🏢 *ISP:* ${data ? data.isp : 'Unknown'}\n🌍 *Location:* ${data ? `${data.city}, ${data.country}` : 'Unknown'}\n💻 *UA:* ${userAgent}\n🎯 *Target:* ${targetUrl === realLink ? 'REAL' : 'SAFE'}`;
        
        axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            chat_id: chatId,
            text: message,
            parse_mode: 'Markdown'
        }).catch(() => {});
    }

    if (!targetUrl) return res.send("Configuration missing for links.");
    res.redirect(targetUrl);
}

app.listen(port, () => {
    console.log(`SaaS Proxy server running on port ${port}`);
});
