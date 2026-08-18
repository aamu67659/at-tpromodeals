// ---------------------------------------------------------------------------
// Telegram bot — inbound webhook + interactive commands.
//
// Auth model:
//   - One-time /start <code> linking (the dashboard issues the code).
//   - Inline /login <username> <password> linking (per-chat, persisted).
//   - /admin_login <ADMIN_TOKEN> grants a 30-min admin session per chat.
//
// Every command handler resolves a "user" (regular or admin) and replies via
// sendMessage. Long output (>4096 chars) is split into chunks.
// ---------------------------------------------------------------------------
const axios = require('axios');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('./db');

// ---- Config / state ------------------------------------------------------
const BOT_TOKEN = (process.env.TELEGRAM_BOT_TOKEN2 || '').trim();
const BOT_USERNAME = (process.env.TELEGRAM_BOT_USERNAME || '').trim();
const WEBHOOK_SECRET = (process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || '').trim();
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || '').trim().replace(/\/+$/, '');
const ADMIN_TTL_MS = parseInt(process.env.TELEGRAM_ADMIN_TTL_MS || '1800000', 10);
const LINK_CODE_TTL_MS = parseInt(process.env.TELEGRAM_LINK_TTL_MS || '600000', 10);

const PAYMENT_EXCHANGE_NAME = process.env.PAYMENT_EXCHANGE_NAME || 'XT.com';
const PAYMENT_RECEIVE_ADDRESS = (process.env.USDT_TRC20_ADDRESS || '').trim();
const PAYMENT_RATE = parseFloat(process.env.PAYMENT_RATE || '1');
const MIN_DEPOSIT_USDT = parseFloat(process.env.MIN_DEPOSIT_USDT || '10');
const PRICES = { '3days': 15, '1week': 25, '2weeks': 50, 'month': 80 };

// chatId -> { userId, isAdmin, adminUntil }
const chatSessions = new Map();
// code -> { userId, createdAt }
const pendingLinkCodes = new Map();

function isBotEnabled() { return BOT_TOKEN.length > 0; }

// ---- Bot API client ------------------------------------------------------
const TG_API = () => `https://api.telegram.org/bot${BOT_TOKEN}`;

async function tgCall(method, params) {
    if (!isBotEnabled()) return null;
    try {
        const res = await axios.post(`${TG_API()}/${method}`, params, { timeout: 12000 });
        return res.data;
    } catch (err) {
        const desc = err && err.response && err.response.data && err.response.data.description;
        console.warn(`[Bot] ${method} failed: ${desc || err.message}`);
        return null;
    }
}

async function reply(chatId, text, opts = {}) {
    if (!isBotEnabled() || chatId == null) return;
    const chunks = splitForTelegram(text);
    for (const chunk of chunks) {
        await tgCall('sendMessage', {
            chat_id: chatId,
            text: chunk,
            parse_mode: 'HTML',
            disable_web_page_preview: true,
            ...opts
        });
    }
}

function splitForTelegram(text, maxLen = 3900) {
    if (typeof text !== 'string') return [String(text)];
    if (text.length <= maxLen) return [text];
    const out = [];
    let cursor = 0;
    while (cursor < text.length) {
        out.push(text.slice(cursor, cursor + maxLen));
        cursor += maxLen;
    }
    return out;
}

function esc(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

// Same safety check the server uses. Bot commands would otherwise bypass it.
function isSafeHttpUrl(raw) {
    if (raw == null || raw === '') return false;
    if (typeof raw !== 'string') return false;
    if (raw.length > 2048) return false;
    try {
        const u = new URL(raw);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
        if (!u.hostname || !u.hostname.includes('.')) return false;
        return true;
    } catch (_) { return false; }
}

// ---- Webhook setup -------------------------------------------------------
async function setupWebhook() {
    if (!isBotEnabled()) {
        console.warn('[Bot] TELEGRAM_BOT_TOKEN2 not set — bot disabled');
        return false;
    }
    if (!PUBLIC_BASE_URL) {
        console.warn('[Bot] PUBLIC_BASE_URL not set — cannot auto-register webhook. Set it or call setWebhook manually.');
        return false;
    }
    const url = `${PUBLIC_BASE_URL}/api/telegram/webhook`;
    const params = { url, allowed_updates: ['message'] };
    if (WEBHOOK_SECRET) params.secret_token = WEBHOOK_SECRET;
    const res = await tgCall('setWebhook', params);
    if (res && res.ok) {
        console.log(`[Bot] Webhook set: ${url}${WEBHOOK_SECRET ? ' (with secret_token)' : ''}`);
        return true;
    }
    console.error('[Bot] setWebhook failed:', JSON.stringify(res || {}));
    return false;
}

async function deleteWebhook() {
    if (!isBotEnabled()) return;
    await tgCall('deleteWebhook', {});
}

// ---- One-time link codes (dashboard-side onboarding) --------------------
function issueLinkCode(userId) {
    const code = crypto.randomBytes(4).toString('hex');
    pendingLinkCodes.set(code, { userId, createdAt: Date.now() });
    sweepExpiredLinkCodes();
    return code;
}

function sweepExpiredLinkCodes() {
    const now = Date.now();
    for (const [code, entry] of pendingLinkCodes) {
        if (now - entry.createdAt > LINK_CODE_TTL_MS) pendingLinkCodes.delete(code);
    }
}

function consumeLinkCode(code) {
    sweepExpiredLinkCodes();
    const entry = pendingLinkCodes.get(code);
    if (!entry) return null;
    pendingLinkCodes.delete(code);
    return entry.userId;
}

// ---- chat -> user resolution --------------------------------------------
async function rebuildChatIndex() {
    chatSessions.clear();
    const users = await db.getUsers();
    for (const u of users) {
        if (!u || !Array.isArray(u.linkedTelegramChatIds)) continue;
        for (const chatId of u.linkedTelegramChatIds) {
            if (chatId != null) chatSessions.set(String(chatId), { userId: u.id, isAdmin: false, adminUntil: 0 });
        }
    }
}

async function linkChatToUser(chatId, userId) {
    chatSessions.set(String(chatId), { userId, isAdmin: false, adminUntil: 0 });
    const user = await db.findUserById(userId);
    if (!user) return;
    const list = Array.isArray(user.linkedTelegramChatIds) ? user.linkedTelegramChatIds.slice() : [];
    if (!list.includes(String(chatId))) list.push(String(chatId));
    await db.updateUser(userId, { linkedTelegramChatIds: list });
}

async function unlinkChat(chatId) {
    chatSessions.delete(String(chatId));
    const users = await db.getUsers();
    for (const u of users) {
        if (!u || !Array.isArray(u.linkedTelegramChatIds)) continue;
        const next = u.linkedTelegramChatIds.filter(c => c !== String(chatId));
        if (next.length !== u.linkedTelegramChatIds.length) {
            await db.updateUser(u.id, { linkedTelegramChatIds: next });
        }
    }
}

async function findUserByChatId(chatId) {
    const sess = chatSessions.get(String(chatId));
    if (!sess || !sess.userId) return null;
    return await db.findUserById(sess.userId);
}

function isAdminSession(chatId) {
    const sess = chatSessions.get(String(chatId));
    if (!sess || !sess.isAdmin) return false;
    if (sess.adminUntil && sess.adminUntil < Date.now()) {
        sess.isAdmin = false;
        return false;
    }
    return true;
}

function grantAdmin(chatId) {
    const sess = chatSessions.get(String(chatId)) || { userId: null, isAdmin: false, adminUntil: 0 };
    sess.isAdmin = true;
    sess.adminUntil = Date.now() + ADMIN_TTL_MS;
    chatSessions.set(String(chatId), sess);
}

// ---- Admin token compare ------------------------------------------------
function adminTokenMatches(submitted) {
    if (!ADMIN_TOKEN || !submitted) return false;
    try {
        const a = Buffer.from(String(submitted), 'utf8');
        const b = Buffer.from(ADMIN_TOKEN, 'utf8');
        return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch { return false; }
}

// ---- Update dispatcher ---------------------------------------------------
async function handleUpdate(update) {
    if (!update || typeof update !== 'object') return;
    const msg = update.message || update.edited_message;
    if (!msg || !msg.chat) return;

    const chatId = msg.chat.id;
    const text = (msg.text || msg.caption || '').trim();
    if (!text) return;

    let cmd = text;
    let args = [];
    if (text.startsWith('/')) {
        const parts = text.split(/\s+/);
        cmd = parts[0].split('@')[0].toLowerCase();
        args = parts.slice(1);
    } else {
        // Plain text → reprompt with help.
        return reply(chatId, 'Send a command, e.g. <code>/help</code>.');
    }

    try {
        await dispatch(chatId, cmd, args, msg);
    } catch (err) {
        console.error(`[Bot] handler error for ${cmd}:`, err.message);
        await reply(chatId, '!! <b>Internal error</b> while handling that command.');
    }
}

async function dispatch(chatId, cmd, args, msg) {
    // Public commands (work before /login).
    switch (cmd) {
        case '/start': return cmdStart(chatId, args, msg);
        case '/help': return cmdHelp(chatId);
        case '/deposit':
        case '/payment':
        case '/payments': return cmdDeposit(chatId);
        case '/isps': return cmdIsps(chatId);
        case '/countries': return cmdCountries(chatId);
        case '/antired': return cmdAntired(chatId);
        case '/newsletter': return cmdNewsletter(chatId);
    }

    // Auth-bound commands — require linked user (except /login and /logout).
    const user = await findUserByChatId(chatId);
    if (cmd === '/login') return cmdLogin(chatId, args);
    if (cmd === '/logout') return cmdLogout(chatId);
    if (!user) {
        return reply(chatId,
            '⚠️ <b>Not signed in.</b>\n\nUse <code>/login &lt;username&gt; &lt;password&gt;</code> ' +
            'or click the <b>Connect Telegram</b> button on the dashboard and press <code>/start &lt;code&gt;</code> here.');
    }

    switch (cmd) {
        case '/balance':
        case '/wallet': return cmdBalance(chatId, user);
        case '/links': return cmdLinks(chatId, user);
        case '/newlink': return cmdNewLink(chatId, user, args);
        case '/renew': return cmdRenew(chatId, user, args);
        case '/delete':
        case '/dellink': return cmdDeleteLink(chatId, user, args);
        case '/history':
        case '/payments_my': return cmdHistory(chatId, user);
        case '/visitors': return cmdVisitors(chatId, user, args);
        case '/block': return cmdBlockIp(chatId, user, args);
        case '/unblock': return cmdUnblockIp(chatId, user, args);
        case '/force': return cmdForceIp(chatId, user, args);
        case '/unforce': return cmdUnforceIp(chatId, user, args);
        case '/settings': return cmdSettings(chatId, user, args);
        case '/setsetting': return cmdSetSetting(chatId, user, args);
    }

    // Admin commands.
    if (cmd === '/admin_login') return cmdAdminLogin(chatId, args);
    if (cmd === '/admin_logout') {
        const sess = chatSessions.get(String(chatId));
        if (sess) { sess.isAdmin = false; sess.adminUntil = 0; }
        return reply(chatId, 'Admin session cleared.');
    }
    if (!isAdminSession(chatId)) {
        return reply(chatId, '⚠️ <b>Admin only.</b> Use <code>/admin_login &lt;ADMIN_TOKEN&gt;</code> first.');
    }
    switch (cmd) {
        case '/admin_stats': return cmdAdminStats(chatId);
        case '/admin_users': return cmdAdminUsers(chatId, args);
        case '/admin_user': return cmdAdminUser(chatId, args);
        case '/admin_upd_balance': return cmdAdminUpdBalance(chatId, args);
        case '/admin_toggle': return cmdAdminToggle(chatId, args);
        case '/admin_delete': return cmdAdminDelete(chatId, args);
        case '/admin_payments': return cmdAdminPayments(chatId);
        case '/admin_newsletter': return cmdAdminNewsletter(chatId, args);
        case '/admin_antired': return cmdAdminAntired(chatId, args);
        case '/admin_blocks': return cmdAdminBlocks(chatId, args);
    }

    return reply(chatId, `❓ Unknown command <code>${esc(cmd)}</code>. Try <code>/help</code>.`);
}

// ---- Command handlers (public) ------------------------------------------
async function cmdStart(chatId, args, msg) {
    const code = args[0];
    if (code) {
        const userId = consumeLinkCode(code);
        if (!userId) {
            return reply(chatId, '⚠️ <b>Code expired or invalid.</b> Go back to the dashboard and request a new <b>Connect Telegram</b> link.');
        }
        await linkChatToUser(chatId, userId);
        const user = await db.findUserById(userId);
        return reply(chatId, `✅ <b>Linked to @${esc(user ? user.username : userId)}.</b>\n\nSend <code>/help</code> to see commands.`);
    }
    const hello = BOT_USERNAME
        ? `👋 Send <code>/login &lt;username&gt; &lt;password&gt;</code> here, or open the dashboard, click <b>Connect Telegram</b>, then press the deep link to bind this chat.`
        : `👋 Send <code>/login &lt;username&gt; &lt;password&gt;</code> here, then <code>/help</code>.`;
    return reply(chatId, hello);
}

async function cmdHelp(chatId) {
    const user = await findUserByChatId(chatId);
    const base = [
        '<b>Public</b>',
        '  /deposit  — deposit address, exchange, min',
        '  /isps     — ISP allow-list',
        '  /countries — country code registry',
        '  /antired  — anti-red rotation pool',
        '  /newsletter — admin broadcast',
        '',
        '<b>Account</b>',
        '  /login &lt;user&gt; &lt;pass&gt;  — link this chat (or /start &lt;code&gt;)',
        '  /logout — unlink this chat',
    ];
    if (user) {
        base.push(
            '',
            '<b>Wallet / links</b>',
            '  /balance  — wallet credits',
            '  /links    — list active uplinks',
            '  /newlink &lt;name&gt; &lt;realUrl&gt; &lt;safeUrl&gt; &lt;duration&gt; [&lt;slug&gt;]',
            '      durations: 3days / 1week / 2weeks / month',
            '  /renew &lt;slug&gt; [&lt;duration&gt;]',
            '  /delete &lt;slug&gt;',
            '  /history  — payments',
            '  /visitors [N] — last N real visits',
            '  /block &lt;ip&gt;  /unblock &lt;ip&gt;',
            '  /force &lt;ip&gt;  /unforce &lt;ip&gt;',
            '  /settings [key]   — show settings',
            '  /setsetting &lt;key&gt; &lt;value&gt;'
        );
    }
    base.push(
        '',
        '<b>Admin</b>',
        '  /admin_login &lt;ADMIN_TOKEN&gt;',
        '  /admin_stats / /admin_users / /admin_user &lt;id&gt;',
        '  /admin_upd_balance &lt;id&gt; &lt;amount&gt;   /admin_toggle &lt;id&gt;',
        '  /admin_delete &lt;id&gt;',
        '  /admin_payments',
        '  /admin_newsletter &lt;title&gt; | &lt;body&gt;',
        '  /admin_antired &lt;host1&gt;,&lt;host2&gt;,...',
        '  /admin_blocks &lt;list|add|del&gt; &lt;ips|isps|countries&gt; [&lt;value&gt;]'
    );
    return reply(chatId, base.join('\n'));
}

async function cmdDeposit(_chatId) {
    if (!PAYMENT_RECEIVE_ADDRESS) {
        return reply(_chatId, '⚠️ Payments are not configured on this server yet.');
    }
    const msg =
        `💳 <b>Deposit</b>\n` +
        `<b>Network:</b> TRC20 (USDT)\n` +
        `<b>Exchange:</b> ${esc(PAYMENT_EXCHANGE_NAME)}\n` +
        `<b>Address:</b> <code>${esc(PAYMENT_RECEIVE_ADDRESS)}</code>\n` +
        `<b>Rate:</b> ${esc(String(PAYMENT_RATE))}\n` +
        `<b>Minimum:</b> ${esc(String(MIN_DEPOSIT_USDT))} USDT`;
    return reply(_chatId, msg);
}

async function cmdIsps(_chatId) {
    const isps = (process.env.MOBILE_ISPS || '').split(',').map(s => s.trim()).filter(Boolean);
    return reply(_chatId, isps.length ? `📡 <b>ISPs:</b>\n${isps.map(i => '  • ' + esc(i)).join('\n')}` : '⚠️ No ISPs configured.');
}

async function cmdCountries(_chatId) {
    const rows = db.ISO_COUNTRIES;
    const head = rows.slice(0, 200).map(c => `  • <b>${esc(c.code)}</b> — ${esc(c.name)}`).join('\n');
    const tail = rows.length > 200 ? `\n… (+${rows.length - 200} more, use /countries offset=N if you really need them all)` : '';
    return reply(_chatId, `🌍 <b>Countries</b>:\n${head}${tail}`);
}

async function cmdAntired(_chatId) {
    const envKey = process.env.ANTIRED_ROTATOR_DOMAINS ? 'ANTIRED_ROTATOR_DOMAINS' : 'ANTIRED_DOMAINS';
    const env = (process.env[envKey] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (env.length) {
        return reply(_chatId, `🛡 <b>Anti-red pool (${envKey})</b>:\n${env.map(d => '  • ' + esc(d)).join('\n')}`);
    }
    return reply(_chatId, '🛡 Anti-red pool is sourced from the admin panel file (no env override set).');
}

async function cmdNewsletter(_chatId) {
    // Read the on-disk newsletter file directly (kept private to admin write).
    const fs = require('fs').promises;
    const path = require('path');
    const dir = (() => {
        try { return require('fs').existsSync('/data') ? '/data' : path.join(__dirname, 'data'); }
        catch { return path.join(__dirname, 'data'); }
    })();
    try {
        const raw = await fs.readFile(path.join(dir, 'newsletter.json'), 'utf8');
        const parsed = JSON.parse(raw);
        const title = (parsed && parsed.title) || '';
        const body = (parsed && parsed.body) || '';
        if (!title && !body) return reply(_chatId, 'No newsletter published yet.');
        return reply(_chatId, `📰 <b>${esc(title)}</b>\n\n${esc(body)}`);
    } catch {
        return reply(_chatId, 'No newsletter published yet.');
    }
}

// ---- Auth-bound commands -------------------------------------------------
async function cmdLogin(chatId, args) {
    if (args.length < 2) {
        return reply(chatId, 'Usage: <code>/login &lt;username&gt; &lt;password&gt;</code>');
    }
    const username = db.normalizeUsername(args[0]);
    const password = args.slice(1).join(' ');
    if (!username) return reply(chatId, '⚠️ Username is required.');
    const user = await db.findUserByUsername(username);
    // Always run bcrypt.compare so a missing user has identical timing to a hit.
    const dummyHash = '$2b$12$0000000000000000000000000000000000000000000000000000';
    const candidate = user && user.password ? user.password : dummyHash;
    const ok = await bcrypt.compare(password, candidate);
    if (!user || !ok) {
        return reply(chatId, '❌ <b>Invalid credentials.</b>');
    }
    await linkChatToUser(chatId, user.id);
    return reply(chatId, `✅ Signed in as <b>@${esc(user.username)}</b>. Type <code>/help</code> for commands.`);
}

async function cmdLogout(chatId) {
    await unlinkChat(chatId);
    return reply(chatId, '🛑 Chat unlinked from your account.');
}

async function cmdBalance(_chatId, user) {
    return reply(_chatId, `💰 Balance: <b>$${Number(user.wallet || 0).toFixed(2)}</b>`);
}

async function cmdLinks(_chatId, user) {
    const links = Array.isArray(user.links) ? user.links : [];
    if (!links.length) return reply(_chatId, 'No uplinks deployed yet.');
    const rows = links.slice(0, 20).map(l => {
        const expiry = l.expiryDate ? new Date(l.expiryDate).toLocaleString() : '—';
        const active = l.expiryDate && new Date(l.expiryDate) > new Date() ? '🟢' : '⚪';
        return `${active} <b>${esc(l.name || l.slug)}</b>  <code>${esc(l.slug)}</code>\n   expires: ${esc(expiry)}`;
    });
    return reply(_chatId, `📡 <b>Uplinks</b>:\n${rows.join('\n\n')}`);
}

async function cmdNewLink(chatId, user, args) {
    if (args.length < 4) {
        return reply(chatId, 'Usage: <code>/newlink &lt;name&gt; &lt;realUrl&gt; &lt;safeUrl&gt; &lt;duration&gt; [&lt;slug&gt;]</code>');
    }
    const [name, realLink, nonRealLink, duration, slug] = args;
    const price = PRICES[duration];
    if (!price) return reply(chatId, '⚠️ Invalid duration. Use 3days / 1week / 2weeks / month.');
    if (!name || !realLink || !nonRealLink) return reply(chatId, '⚠️ name, realUrl and safeUrl are all required.');
    if (typeof name !== 'string' || name.length === 0 || name.length > 80) return reply(chatId, '⚠️ name must be 1–80 chars.');
    // Block javascript:, data:, vbscript:, file: and other non-http(s) URLs
    // that would execute via the redirect endpoint for the next visitor.
    if (!isSafeHttpUrl(realLink) || !isSafeHttpUrl(nonRealLink)) {
        return reply(chatId, '⚠️ realUrl / safeUrl must be absolute http(s) URLs.');
    }
    if (slug && !/^[a-zA-Z0-9-]+$/.test(slug)) return reply(chatId, '⚠️ Slug may only contain letters, numbers and dashes.');
    if ((user.wallet || 0) < price) return reply(chatId, `❌ Need $${price.toFixed(2)}, balance $${Number(user.wallet || 0).toFixed(2)}.`);

    // Slug conflict detection against other users' active links.
    const newSlug = slug || crypto.randomBytes(4).toString('hex');
    const users = await db.getUsers();
    const conflict = users.some(u => u.id !== user.id &&
        (u.slug === newSlug || (Array.isArray(u.links) && u.links.some(l => l.slug === newSlug))) &&
        ((u.slug === newSlug && u.expiryDate && new Date(u.expiryDate) > new Date()) ||
         (Array.isArray(u.links) && u.links.some(l => l.slug === newSlug && l.expiryDate && new Date(l.expiryDate) > new Date()))));
    if (conflict) return reply(chatId, '⚠️ Slug is in active use on another account.');

    const now = new Date();
    const expiry = new Date(now);
    if (duration === '3days') expiry.setDate(expiry.getDate() + 3);
    else if (duration === '1week') expiry.setDate(expiry.getDate() + 7);
    else if (duration === '2weeks') expiry.setDate(expiry.getDate() + 14);
    else if (duration === 'month') expiry.setMonth(expiry.getMonth() + 1);

    const link = {
        id: crypto.randomUUID(),
        name, realLink, nonRealLink, slug: newSlug,
        antiRed: true, ispFilter: true, mobileIsps: (user.settings && user.settings.mobileIsps) || [],
        reallowVisited: true,
        expiryDate: expiry.toISOString(),
        createdAt: now.toISOString()
    };
    const updated = await db.updateUser(user.id, {
        wallet: (user.wallet || 0) - price,
        links: [...(user.links || []), link]
    });
    return reply(chatId, `✅ Uplink <code>${esc(link.slug)}</code> deployed. New balance: <b>$${Number(updated.wallet || 0).toFixed(2)}</b>.`);
}

async function cmdRenew(chatId, user, args) {
    const slug = args[0];
    const duration = args[1] || '1week';
    if (!slug) return reply(chatId, 'Usage: <code>/renew &lt;slug&gt; [duration]</code>');
    const price = PRICES[duration];
    if (!price) return reply(chatId, '⚠️ Invalid duration.');
    if ((user.wallet || 0) < price) return reply(chatId, `❌ Need $${price.toFixed(2)}.`);

    const links = Array.isArray(user.links) ? user.links.slice() : [];
    const idx = links.findIndex(l => l.slug === slug);
    if (idx === -1) return reply(chatId, '⚠️ Uplink not found.');
    if (links[idx].expiryDate && new Date(links[idx].expiryDate) > new Date()) {
        return reply(chatId, '⚠️ Still active — wait until expiry before renewing.');
    }
    const expiry = new Date();
    if (duration === '3days') expiry.setDate(expiry.getDate() + 3);
    else if (duration === '1week') expiry.setDate(expiry.getDate() + 7);
    else if (duration === '2weeks') expiry.setDate(expiry.getDate() + 14);
    else if (duration === 'month') expiry.setMonth(expiry.getMonth() + 1);
    links[idx].expiryDate = expiry.toISOString();
    const updated = await db.updateUser(user.id, { links, wallet: (user.wallet || 0) - price });
    return reply(chatId, `🔁 <code>${esc(slug)}</code> renewed until <b>${expiry.toLocaleString()}</b>. New balance: <b>$${Number(updated.wallet || 0).toFixed(2)}</b>.`);
}

async function cmdDeleteLink(chatId, user, args) {
    const slug = args[0];
    if (!slug) return reply(chatId, 'Usage: <code>/delete &lt;slug&gt;</code>');
    const links = Array.isArray(user.links) ? user.links.slice() : [];
    const idx = links.findIndex(l => l.slug === slug);
    if (idx === -1) return reply(chatId, '⚠️ Uplink not found.');
    if (links[idx].expiryDate && new Date(links[idx].expiryDate) > new Date()) {
        return reply(chatId, '⚠️ Still active — wait until expiry before deleting.');
    }
    links.splice(idx, 1);
    await db.updateUser(user.id, { links });
    return reply(chatId, `🗑 <code>${esc(slug)}</code> removed.`);
}

async function cmdHistory(_chatId, user) {
    const payments = Array.isArray(user.pendingPayments) ? user.pendingPayments : [];
    if (!payments.length) return reply(_chatId, 'No payments on record.');
    const sorted = payments.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 20);
    const rows = sorted.map(p => {
        const status = p.status === 'confirmed' ? '✅' : (p.status === 'rejected' ? '❌' : '⏳');
        return `${status} $${Number(p.amount || 0).toFixed(2)}  ${esc(p.network || 'USDT-TRC20')}  ${esc(new Date(p.createdAt).toLocaleString())}`;
    });
    return reply(_chatId, `💸 <b>Payments</b>:\n${rows.join('\n')}`);
}

async function cmdVisitors(_chatId, user, args) {
    const n = Math.min(parseInt(args[0] || '10', 10) || 10, 50);
    const visits = Array.isArray(user.visitedIps) ? user.visitedIps.slice(-n).reverse() : [];
    if (!visits.length) return reply(_chatId, 'No recorded visits.');
    const rows = visits.map(v => {
        const ts = v.timestamp ? new Date(v.timestamp).toLocaleString() : '—';
        const flag = v.type === 'REAL' ? '🟢' : '🟡';
        return `${flag} ${esc(v.ip || '?')}  ${esc(v.location || 'Unknown')}  ← <i>${esc(ts)}</i>`;
    });
    return reply(_chatId, `👁 <b>Visits</b>:\n${rows.join('\n')}`);
}

async function cmdBlockIp(chatId, user, args) {
    const ip = args[0];
    if (!ip || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return reply(chatId, 'Usage: <code>/block &lt;ipv4&gt;</code>');
    const blocked = Array.isArray(user.blockedIps) ? user.blockedIps.slice() : [];
    if (!blocked.includes(ip)) blocked.push(ip);
    await db.updateUser(user.id, { blockedIps: blocked });
    return reply(chatId, `🚫 <code>${esc(ip)}</code> added to blocklist.`);
}

async function cmdUnblockIp(chatId, user, args) {
    const ip = args[0];
    if (!ip) return reply(chatId, 'Usage: <code>/unblock &lt;ipv4&gt;</code>');
    const blocked = (user.blockedIps || []).filter(i => i !== ip);
    await db.updateUser(user.id, { blockedIps: blocked });
    return reply(chatId, `✅ <code>${esc(ip)}</code> removed from blocklist.`);
}

async function cmdForceIp(chatId, user, args) {
    const ip = args[0];
    if (!ip || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return reply(chatId, 'Usage: <code>/force &lt;ipv4&gt;</code>');
    const forced = Array.isArray(user.forcedIps) ? user.forcedIps.slice() : [];
    if (!forced.includes(ip)) forced.push(ip);
    await db.updateUser(user.id, { forcedIps: forced });
    return reply(chatId, `🟢 <code>${esc(ip)}</code> added to forced allowlist.`);
}

async function cmdUnforceIp(chatId, user, args) {
    const ip = args[0];
    if (!ip) return reply(chatId, 'Usage: <code>/unforce &lt;ipv4&gt;</code>');
    const forced = (user.forcedIps || []).filter(i => i !== ip);
    await db.updateUser(user.id, { forcedIps: forced });
    return reply(chatId, `✅ <code>${esc(ip)}</code> removed from forced allowlist.`);
}

async function cmdSettings(_chatId, user, args) {
    const s = user.settings || {};
    const editable = {
        nonRealLink: s.nonRealLink || '',
        realLink: s.realLink || '',
        antiRed: s.antiRed !== false,
        ispFilter: s.ispFilter !== false,
        botFilter: s.botFilter !== false,
        reallowVisited: s.reallowVisited !== false,
        mobileIsps: (s.mobileIsps || []).join(','),
        depositSendAddress: s.depositSendAddress || '',
        botToken: s.botToken ? '<set>' : '',
        chatId: s.chatId || ''
    };
    const keys = Object.keys(editable);
    if (args[0]) {
        const k = args[0];
        if (keys.includes(k)) {
            return reply(_chatId, `<b>${k}</b> = <code>${esc(String(editable[k]))}</code>`);
        }
        return reply(_chatId, `⚠️ Unknown setting. Available:\n${keys.map(k => '  • ' + k).join('\n')}`);
    }
    const rows = keys.map(k => `  <b>${k}</b>: <code>${esc(String(editable[k]))}</code>`);
    return reply(_chatId, `⚙️ <b>Settings</b>:\n${rows.join('\n')}`);
}

async function cmdSetSetting(chatId, user, args) {
    if (args.length < 2) return reply(chatId, 'Usage: <code>/setsetting &lt;key&gt; &lt;value&gt;</code>');
    const [key, ...rest] = args;
    const value = rest.join(' ');
    const settings = { ...(user.settings || {}) };
    const booleanKeys = new Set(['antiRed', 'ispFilter', 'botFilter', 'reallowVisited']);
    const listKeys = new Set(['mobileIsps']);
    if (booleanKeys.has(key)) {
        if (!['true','false','1','0','yes','no','on','off'].includes(value.toLowerCase())) {
            return reply(chatId, '⚠️ Boolean setting — use true/false.');
        }
        settings[key] = ['true','1','yes','on'].includes(value.toLowerCase());
    } else if (listKeys.has(key)) {
        settings[key] = value.split(',').map(s => s.trim()).filter(Boolean);
    } else if (key === 'depositSendAddress') {
        const v = (value || '').trim();
        if (v && !/^T[A-Za-z1-9]{33}$/.test(v)) {
            return reply(chatId, '⚠️ Invalid TRC20 address (must start with T and be 34 chars).');
        }
        settings[key] = v;
    } else if (key === 'realLink' || key === 'nonRealLink') {
        if (value && !isSafeHttpUrl(value)) {
            return reply(chatId, '⚠️ Must be an absolute http(s) URL.');
        }
        settings[key] = (value || '').trim();
    } else if (key === 'botToken') {
        if (value && value.length > 256) return reply(chatId, '⚠️ botToken too long.');
        settings[key] = (value || '').trim();
    } else if (key === 'chatId') {
        if (value && !/^-?\d+$/.test(value.trim())) return reply(chatId, '⚠️ chatId must be numeric.');
        settings[key] = (value || '').trim();
    } else {
        return reply(chatId, `⚠️ Unknown or read-only setting. Mutable keys: antiRed, ispFilter, botFilter, reallowVisited, mobileIsps, depositSendAddress, botToken, chatId, nonRealLink, realLink.`);
    }
    await db.updateUser(user.id, { settings });
    return reply(chatId, `✅ Setting <b>${esc(key)}</b> updated.`);
}

// ---- Admin commands ------------------------------------------------------
async function cmdAdminLogin(chatId, args) {
    const token = args[0];
    if (!token) return reply(chatId, 'Usage: <code>/admin_login &lt;ADMIN_TOKEN&gt;</code>');
    if (!adminTokenMatches(token)) return reply(chatId, '❌ <b>Invalid token.</b>');
    grantAdmin(chatId);
    const mins = Math.round(ADMIN_TTL_MS / 60000);
    return reply(chatId, `🔐 Admin session granted for ~${mins} minutes. Use <code>/admin_logout</code> to end sooner.`);
}

async function cmdAdminStats(_chatId) {
    const users = await db.getUsers();
    const now = Date.now();
    const HOUR = 3600 * 1000, DAY = 24 * HOUR;
    const stats = {
        total: users.length,
        active: users.filter(u => u.isActive).length,
        deactivated: users.filter(u => !u.isActive).length,
        registeredLast24h: users.filter(u => u.createdAt && (now - new Date(u.createdAt).getTime()) < DAY).length,
        walletTotal: users.reduce((acc, u) => acc + (u.wallet || 0), 0)
    };
    const lines = [
        '📊 <b>Admin Stats</b>',
        `  Total users: <b>${stats.total}</b>`,
        `  Active: <b>${stats.active}</b> / Deactivated: <b>${stats.deactivated}</b>`,
        `  New (24h): <b>${stats.registeredLast24h}</b>`,
        `  Wallet total: <b>$${stats.walletTotal.toFixed(2)}</b>`
    ];
    return reply(_chatId, lines.join('\n'));
}

async function cmdAdminUsers(_chatId, args) {
    const users = await db.getUsers();
    const limit = Math.min(parseInt(args[0] || '20', 10) || 20, 50);
    const head = users.slice(0, limit).map(u =>
        `  • <b>@${esc(u.username)}</b>  id=<code>${esc(u.id)}</code>  <i>${u.isActive ? '✅' : '❌'}</i>  $${Number(u.wallet || 0).toFixed(2)}`);
    return reply(_chatId, `👥 <b>Users</b> (top ${limit}):\n${head.join('\n')}`);
}

async function cmdAdminUser(_chatId, args) {
    const id = args[0];
    if (!id) return reply(_chatId, 'Usage: <code>/admin_user &lt;userId&gt;</code>');
    const u = await db.findUserById(id);
    if (!u) return reply(_chatId, '⚠️ User not found.');
    const created = u.createdAt ? new Date(u.createdAt).toLocaleString() : '—';
    return reply(_chatId,
        `👤 <b>@${esc(u.username)}</b>\n` +
        `  id: <code>${esc(u.id)}</code>\n` +
        `  active: ${u.isActive ? '✅' : '❌'}\n` +
        `  wallet: $${Number(u.wallet || 0).toFixed(2)}\n` +
        `  links: ${(u.links || []).length}\n` +
        `  blockedIPs: ${(u.blockedIps || []).length}\n` +
        `  created: <i>${esc(created)}</i>`
    );
}

async function cmdAdminUpdBalance(chatId, args) {
    const id = args[0];
    const amount = parseFloat(args[1]);
    if (!id || !isFinite(amount)) return reply(chatId, 'Usage: <code>/admin_upd_balance &lt;userId&gt; &lt;amount&gt;</code>');
    const u = await db.findUserById(id);
    if (!u) return reply(chatId, '⚠️ User not found.');
    await db.updateUser(id, { wallet: amount });
    return reply(chatId, `✅ Wallet for <code>${esc(id)}</code> set to <b>$${amount.toFixed(2)}</b>.`);
}

async function cmdAdminToggle(chatId, args) {
    const id = args[0];
    if (!id) return reply(chatId, 'Usage: <code>/admin_toggle &lt;userId&gt;</code>');
    const u = await db.findUserById(id);
    if (!u) return reply(chatId, '⚠️ User not found.');
    await db.updateUser(id, { isActive: !u.isActive });
    return reply(chatId, `✅ <b>@${esc(u.username)}</b> is now <b>${!u.isActive ? 'ENABLED' : 'DISABLED'}</b>.`);
}

async function cmdAdminDelete(chatId, args) {
    const id = args[0];
    if (!id) return reply(chatId, 'Usage: <code>/admin_delete &lt;userId&gt;</code>');
    const removed = await db.deleteUser(id);
    if (!removed) return reply(chatId, '⚠️ User not found or already removed.');
    return reply(chatId, `🗑 User <code>${esc(id)}</code> deleted.`);
}

async function cmdAdminPayments(_chatId) {
    const users = await db.getUsers();
    const all = [];
    users.forEach(u => {
        (u.pendingPayments || []).forEach(p => {
            all.push({ ...p, userId: u.id, userName: u.username || '?' });
        });
    });
    if (!all.length) return reply(_chatId, 'No payments.');
    all.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const rows = all.slice(0, 30).map(p => {
        const st = p.status === 'confirmed' ? '✅' : (p.status === 'rejected' ? '❌' : '⏳');
        return `${st} @${esc(p.userName)}  $${Number(p.amount || 0).toFixed(2)}  ${esc(new Date(p.createdAt).toLocaleString())}`;
    });
    return reply(_chatId, `💳 <b>Payments</b>:\n${rows.join('\n')}`);
}

async function cmdAdminNewsletter(chatId, args) {
    if (!args.length) return reply(chatId, 'Usage: <code>/admin_newsletter &lt;title&gt; | &lt;body&gt;</code>');
    const joined = args.join(' ');
    const sep = joined.indexOf('|');
    if (sep < 0) return reply(chatId, 'Separate title and body with a pipe character: <code>Title | Body text</code>');
    const title = joined.slice(0, sep).trim();
    const body = joined.slice(sep + 1).trim();
    const fs = require('fs').promises;
    const path = require('path');
    const dir = (() => {
        try { return require('fs').existsSync('/data') ? '/data' : path.join(__dirname, 'data'); }
        catch { return path.join(__dirname, 'data'); }
    })();
    const record = { title, body, updatedAt: new Date().toISOString() };
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(path.join(dir, 'newsletter.json'), JSON.stringify(record, null, 2));
    return reply(chatId, `📰 Newsletter set: <b>${esc(title)}</b>`);
}

async function cmdAdminAntired(_chatId, args) {
    if (!args.length) return reply(_chatId, 'Usage: <code>/admin_antired &lt;host1&gt;,&lt;host2&gt;,…</code> (≥4 hosts)');
    const hosts = Array.from(new Set(args.join(',').split(',').map(s => s.trim()).filter(Boolean)));
    if (hosts.length < 4) return reply(_chatId, '⚠️ Need at least 4 hosts.');
    const envKey = process.env.ANTIRED_ROTATOR_DOMAINS ? 'ANTIRED_ROTATOR_DOMAINS' : 'ANTIRED_DOMAINS';
    if ((process.env[envKey] || '').trim().length > 0) {
        return reply(_chatId, `⚠️ ${envKey} is set via env — update the host env instead.`);
    }
    const fs = require('fs').promises;
    const path = require('path');
    const dir = (() => {
        try { return require('fs').existsSync('/data') ? '/data' : path.join(__dirname, 'data'); }
        catch { return path.join(__dirname, 'data'); }
    })();
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(path.join(dir, 'antired-domains.json'), JSON.stringify({ domains: hosts, updatedAt: new Date().toISOString() }, null, 2));
    return reply(_chatId, `🛡 Pool updated with ${hosts.length} hosts.`);
}

async function cmdAdminBlocks(chatId, args) {
    const action = args[0]; const type = args[1]; const value = args[2];
    if (!['list','add','del'].includes(action)) return reply(chatId, 'Usage: <code>/admin_blocks &lt;list|add|del&gt; &lt;ips|isps|countries&gt; [&lt;value&gt;]</code>');
    if (!['ips','isps','countries'].includes(type)) return reply(chatId, 'Type must be ips, isps or countries.');
    const blocks = await db.readAdminBlocks();
    if (action === 'list') {
        const items = blocks[type] || [];
        return reply(chatId, `📋 <b>${type}</b> (${items.length}):\n${items.slice(0, 50).map(b => '  • ' + esc(b.value) + (b.reason ? ' — ' + esc(b.reason) : '')).join('\n') || '(empty)'}`);
    }
    if (!value) return reply(chatId, 'Provide a value.');
    try {
        await db.addAdminBlock(type, value, '');
        return reply(chatId, `✅ Added <code>${esc(value)}</code> to <b>${type}</b>.`);
    } catch (err) {
        if (err.code === 'DUPLICATE_VALUE') return reply(chatId, '⚠️ Already present.');
        return reply(chatId, '❌ ' + esc(err.message));
    }
}

// ---- Exports -------------------------------------------------------------
module.exports = {
    isBotEnabled,
    setupWebhook,
    deleteWebhook,
    handleUpdate,
    issueLinkCode,
    consumeLinkCode,
    rebuildChatIndex,
    reply
};
