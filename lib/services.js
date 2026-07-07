import axios from 'axios';

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

// Simple in-memory cache for ISP lookups (1 hour TTL)
const ispCache = new Map();
const CACHE_TTL = 60 * 60 * 1000;

export async function sendTelegramNotification(message) {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
        console.warn('[Telegram] Missing token or chat ID');
        return;
    }

    try {
        await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: TELEGRAM_CHAT_ID,
            text: message,
            parse_mode: 'Markdown'
        }, { timeout: 8000 });
        console.log('[Telegram] Notification sent');
    } catch (e) {
        console.error('[Telegram] Notification failed:', e.message);
    }
}

export async function lookupIsp(ip) {
    // Check cache first
    if (ispCache.has(ip)) {
        const { data, timestamp } = ispCache.get(ip);
        if (Date.now() - timestamp < CACHE_TTL) {
            console.log(`[ISP Lookup] Cache hit for ${ip}`);
            return data;
        }
        ispCache.delete(ip);
    }

    try {
        const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query`, { timeout: 4000 });
        const data = response.data;
        
        // Cache successful lookups
        if (data && data.status === 'success') {
            ispCache.set(ip, { data, timestamp: Date.now() });
            // Keep cache size manageable
            if (ispCache.size > 1000) {
                const firstKey = ispCache.keys().next().value;
                ispCache.delete(firstKey);
            }
        }
        
        return data;
    } catch (error) {
        console.error('[ISP Lookup] Failed:', error.message);
        return null;
    }
}

export function isBot(userAgent) {
    const BOT_USER_AGENTS = [
        'googlebot', 'bingbot', 'yandexbot', 'duckduckbot', 'slurp', 'baiduspider', 'facebot', 'ia_archiver',
        'crawler', 'spider', 'robot', 'curl', 'wget', 'python', 'postman', 'insomnia', 'headless'
    ];
    const ua = (userAgent || '').toLowerCase();
    if (!ua) return true;
    return BOT_USER_AGENTS.some(bot => ua.includes(bot));
}
