import { getForcedIps, addForcedIp, removeForcedIp } from '../../../../lib/storage';
import { isIP } from 'net';

export async function GET(req) {
    const { searchParams } = new URL(req.url);
    const token = searchParams.get('token') || req.headers.get('x-admin-token');
    
    if (token !== process.env.ADMIN_TOKEN) {
        return new Response('Unauthorized', { status: 401 });
    }

    const ips = await getForcedIps();
    return Response.json(ips);
}

export async function POST(req) {
    const token = req.headers.get('x-admin-token');
    if (token !== process.env.ADMIN_TOKEN) {
        return new Response('Unauthorized', { status: 401 });
    }

    const { ip, action } = await req.json();
    
    if (action === 'add') {
        if (!ip || !isIP(ip)) return new Response('Invalid IP', { status: 400 });
        await addForcedIp(ip);
    } else if (action === 'remove') {
        await removeForcedIp(ip);
    }

    return Response.json({ success: true });
}
