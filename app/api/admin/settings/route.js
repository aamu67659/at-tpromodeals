import { getSettings, updateSettings } from '../../../../lib/storage';

export async function GET(req) {
    const { searchParams } = new URL(req.url);
    const token = searchParams.get('token') || req.headers.get('x-admin-token');
    
    if (token !== process.env.ADMIN_TOKEN) {
        return new Response('Unauthorized', { status: 401 });
    }

    const settings = await getSettings();
    return Response.json(settings);
}

export async function POST(req) {
    const token = req.headers.get('x-admin-token');
    if (token !== process.env.ADMIN_TOKEN) {
        return new Response('Unauthorized', { status: 401 });
    }

    const body = await req.json();
    const updated = await updateSettings(body);
    return Response.json(updated);
}
