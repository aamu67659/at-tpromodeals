import { getVisitedIps, removeVisitedIp, clearVisitedIps } from '@/lib/storage';

export async function GET(req) {
    const { searchParams } = new URL(req.url);
    const token = searchParams.get('token') || req.headers.get('x-admin-token');
    
    if (token !== process.env.ADMIN_TOKEN) {
        return new Response('Unauthorized', { status: 401 });
    }

    const ips = await getVisitedIps();
    return Response.json(ips);
}

export async function POST(req) {
    const token = req.headers.get('x-admin-token');
    if (token !== process.env.ADMIN_TOKEN) {
        return new Response('Unauthorized', { status: 401 });
    }

    const { ip, action } = await req.json();
    
    if (action === 'remove') {
        await removeVisitedIp(ip);
    } else if (action === 'clear') {
        await clearVisitedIps();
    }

    return Response.json({ success: true });
}
