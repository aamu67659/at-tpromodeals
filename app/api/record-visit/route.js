import { addVisitedIp } from '../../../lib/storage';
import { redirect } from 'next/navigation';
import { headers } from 'next/headers';

export async function GET(req) {
    const headersList = headers();
    const forwarded = headersList.get('x-forwarded-for');
    const ip = forwarded ? forwarded.split(',')[0] : '127.0.0.1';
    
    await addVisitedIp(ip);
    
    const target = process.env.ATT_LANDING_PAGE || 'https://att.com';
    return Response.redirect(target);
}
