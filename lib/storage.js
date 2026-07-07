import fs from 'fs/promises';
import path from 'path';
import { existsSync, writeFileSync } from 'fs';

const VISITED_IPS_FILE = path.join(process.cwd(), 'visited_ips.json');
const FORCED_IPS_FILE = path.join(process.cwd(), 'forced_ips.json');
const SETTINGS_FILE = path.join(process.cwd(), 'settings.json');

// Initialize files if they don't exist
if (!existsSync(VISITED_IPS_FILE)) writeFileSync(VISITED_IPS_FILE, JSON.stringify([]));
if (!existsSync(FORCED_IPS_FILE)) writeFileSync(FORCED_IPS_FILE, JSON.stringify([]));
if (!existsSync(SETTINGS_FILE)) {
    writeFileSync(SETTINGS_FILE, JSON.stringify({ 
        isSuspiciousEnabled: true,
        isIspFilterEnabled: true 
    }));
}

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

// In-memory cache
let cachedSettings = null;
let cachedForcedIps = null;

export async function getVisitedIps() {
    try {
        const data = await fs.readFile(VISITED_IPS_FILE, 'utf8');
        if (!data.trim()) return [];
        let ips = JSON.parse(data);
        const now = Date.now();
        const twentyFourHours = 24 * 60 * 60 * 1000;
        return Array.isArray(ips) ? ips.filter(entry => {
            const timestamp = typeof entry === 'object' ? entry.timestamp : 0;
            return (now - timestamp) < twentyFourHours;
        }) : [];
    } catch (e) {
        console.error('[Storage] getVisitedIps error:', e.message);
        return [];
    }
}

export async function addVisitedIp(ip) {
    await withLock(async () => {
        try {
            const ips = await getVisitedIps();
            const existingIndex = ips.findIndex(entry => (typeof entry === 'object' ? entry.ip : entry) === ip);
            
            if (existingIndex === -1) {
                ips.push({ ip, timestamp: Date.now() });
                await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(ips, null, 2));
            } else if (typeof ips[existingIndex] !== 'object') {
                ips[existingIndex] = { ip, timestamp: Date.now() };
                await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(ips, null, 2));
            }
        } catch (e) {
            console.error('[Storage] addVisitedIp error:', e.message);
        }
    });
}

export async function removeVisitedIp(ip) {
    await withLock(async () => {
        try {
            const ips = await getVisitedIps();
            const newIps = ips.filter(entry => (typeof entry === 'object' ? entry.ip : entry) !== ip);
            await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(newIps, null, 2));
        } catch (e) {
            console.error('[Storage] removeVisitedIp error:', e.message);
        }
    });
}

export async function clearVisitedIps() {
    await withLock(async () => {
        try {
            await fs.writeFile(VISITED_IPS_FILE, JSON.stringify([], null, 2));
        } catch (e) {
            console.error('[Storage] clearVisitedIps error:', e.message);
        }
    });
}

export async function getForcedIps() {
    if (cachedForcedIps) return cachedForcedIps;
    try {
        const data = await fs.readFile(FORCED_IPS_FILE, 'utf8');
        if (!data.trim()) {
            cachedForcedIps = [];
            return [];
        }
        const parsed = JSON.parse(data);
        cachedForcedIps = Array.isArray(parsed) ? parsed : [];
        return cachedForcedIps;
    } catch (e) {
        console.error('[Storage] getForcedIps error:', e.message);
        return [];
    }
}

export async function addForcedIp(ip) {
    await withLock(async () => {
        try {
            const ips = await getForcedIps();
            if (!ips.includes(ip)) {
                ips.push(ip);
                await fs.writeFile(FORCED_IPS_FILE, JSON.stringify(ips, null, 2));
                cachedForcedIps = [...ips];
            }
        } catch (e) {
            console.error('[Storage] addForcedIp error:', e.message);
        }
    });
}

export async function removeForcedIp(ip) {
    await withLock(async () => {
        try {
            const ips = await getForcedIps();
            const newIps = ips.filter(i => i !== ip);
            await fs.writeFile(FORCED_IPS_FILE, JSON.stringify(newIps, null, 2));
            cachedForcedIps = [...newIps];
        } catch (e) {
            console.error('[Storage] removeForcedIp error:', e.message);
        }
    });
}

export async function getSettings() {
    if (cachedSettings) return cachedSettings;
    try {
        const data = await fs.readFile(SETTINGS_FILE, 'utf8');
        if (!data.trim()) {
            cachedSettings = { isSuspiciousEnabled: true, isIspFilterEnabled: true };
            return cachedSettings;
        }
        const settings = JSON.parse(data);
        cachedSettings = {
            isSuspiciousEnabled: true,
            isIspFilterEnabled: true,
            ...settings
        };
        return cachedSettings;
    } catch (e) {
        return { isSuspiciousEnabled: true, isIspFilterEnabled: true };
    }
}

export async function updateSettings(newSettings) {
    return await withLock(async () => {
        try {
            const settings = await getSettings();
            const updated = { ...settings, ...newSettings };
            await fs.writeFile(SETTINGS_FILE, JSON.stringify(updated, null, 2));
            cachedSettings = updated;
            return updated;
        } catch (e) {
            console.error('[Storage] updateSettings error:', e.message);
            return newSettings;
        }
    });
}
