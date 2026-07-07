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

export async function getVisitedIps() {
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

export async function addVisitedIp(ip) {
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

export async function removeVisitedIp(ip) {
    await withLock(async () => {
        const ips = await getVisitedIps();
        const newIps = ips.filter(entry => (typeof entry === 'object' ? entry.ip : entry) !== ip);
        await fs.writeFile(VISITED_IPS_FILE, JSON.stringify(newIps, null, 2));
    });
}

export async function clearVisitedIps() {
    await withLock(async () => {
        await fs.writeFile(VISITED_IPS_FILE, JSON.stringify([], null, 2));
    });
}

export async function getForcedIps() {
    try {
        const data = await fs.readFile(FORCED_IPS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (e) {
        return [];
    }
}

export async function addForcedIp(ip) {
    await withLock(async () => {
        const ips = await getForcedIps();
        if (!ips.includes(ip)) {
            ips.push(ip);
            await fs.writeFile(FORCED_IPS_FILE, JSON.stringify(ips, null, 2));
        }
    });
}

export async function removeForcedIp(ip) {
    await withLock(async () => {
        const ips = await getForcedIps();
        const newIps = ips.filter(i => i !== ip);
        await fs.writeFile(FORCED_IPS_FILE, JSON.stringify(newIps, null, 2));
    });
}

export async function getSettings() {
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

export async function updateSettings(newSettings) {
    return await withLock(async () => {
        const settings = await getSettings();
        const updated = { ...settings, ...newSettings };
        await fs.writeFile(SETTINGS_FILE, JSON.stringify(updated, null, 2));
        return updated;
    });
}
