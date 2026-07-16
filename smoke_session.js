// Boot server.js from inside the project so it finds node_modules, then immediately close.
process.env.NODE_ENV = 'production';
process.env.SESSION_SECRET = 'x'.repeat(64);
process.env.ADMIN_TOKEN = 'smoketoken12345';
process.env.PUBLIC_BASE_URL = 'https://example.test';
process.env.PORT = '0';
process.env.TELEGRAM_BOT_TOKEN2 = 'placeholder';
process.env.TELEGRAM_BOT_USERNAME = 'SmokeBot';
process.env.TELEGRAM_WEBHOOK_SECRET = 'a'.repeat(64);
process.env.MOBILE_ISPS = 'ISP1, ISP2';
process.env.ATT_LANDING_PAGE = 'https://att.test';
process.env.NON_ATT_LANDING_PAGE = 'https://google.test';
process.env.USDT_TRC20_ADDRESS = 'Txxxxx';

const warnings = [];
const errors = [];
const origWarn = console.warn;
const origErr = console.error;
console.warn = (...a) => { warnings.push(a.join(' ')); origWarn.apply(console, a); };
console.error = (...a) => { errors.push(a.join(' ')); origErr.apply(console, a); };

try {
    const serverPath = require('path').resolve('server.js');
    const mod = require(serverPath);
    if (mod && typeof mod.close === 'function') mod.close();
    console.log('--- summary ---');
    console.log('Loaded OK');
    console.log('Warnings=' + warnings.length);
    console.log('Errors=' + errors.length);
    warnings.forEach((w, i) => console.log('WARN[' + i + ']: ' + w.substring(0, 500)));
    errors.forEach((e, i) => console.log('ERR[' + i + ']: ' + e.substring(0, 500)));
    const all = warnings.concat(errors).join('\n');
    console.log('MemoryStore warning present: ' + (/MemoryStore/i.test(all)));
} catch (e) {
    console.error('Failed to load:', e.message);
}
