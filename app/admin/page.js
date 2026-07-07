'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { Trash2, UserPlus, ShieldAlert, Wifi, Globe, Clock, ShieldCheck } from 'lucide-react';

export default function AdminPanel() {
    const searchParams = useSearchParams();
    const token = searchParams.get('token');
    
    const [settings, setSettings] = useState({ isSuspiciousEnabled: true, isIspFilterEnabled: true });
    const [forcedIps, setForcedIps] = useState([]);
    const [visitedIps, setVisitedIps] = useState([]);
    const [newIp, setNewIp] = useState('');
    const [loading, setLoading] = useState(true);
    const [unauthorized, setUnauthorized] = useState(false);

    useEffect(() => {
        if (!token) {
            setUnauthorized(true);
            setLoading(false);
            return;
        }
        fetchData();
    }, [token]);

    const fetchData = async () => {
        try {
            const [sRes, fRes, vRes] = await Promise.all([
                fetch(`/api/admin/settings?token=${token}`),
                fetch(`/api/admin/forced?token=${token}`),
                fetch(`/api/admin/visited?token=${token}`)
            ]);

            if (sRes.status === 401) {
                setUnauthorized(true);
                return;
            }

            const [s, f, v] = await Promise.all([sRes.json(), fRes.json(), vRes.json()]);
            setSettings(s);
            setForcedIps(f);
            setVisitedIps(v);
        } catch (e) {
            console.error('Fetch failed', e);
        } finally {
            setLoading(false);
        }
    };

    const updateSetting = async (key, val) => {
        const newSettings = { ...settings, [key]: val };
        setSettings(newSettings);
        await fetch('/api/admin/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-admin-token': token },
            body: JSON.stringify(newSettings)
        });
    };

    const handleForced = async (ip, action) => {
        const res = await fetch('/api/admin/forced', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-admin-token': token },
            body: JSON.stringify({ ip, action })
        });
        if (res.ok) {
            setNewIp('');
            fetchData();
        } else {
            alert('Failed to update forced list');
        }
    };

    const handleVisited = async (ip, action) => {
        await fetch('/api/admin/visited', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-admin-token': token },
            body: JSON.stringify({ ip, action })
        });
        fetchData();
    };

    if (loading) return <div className="p-8 text-center">Loading Admin Panel...</div>;
    if (unauthorized) return <div className="p-8 text-center text-red-500 font-bold">Unauthorized: Invalid Admin Token</div>;

    return (
        <div className="min-h-screen bg-gray-50 p-4 md:p-8 font-sans">
            <div className="max-w-4xl mx-auto space-y-8">
                <header className="flex justify-between items-center">
                    <h1 className="text-3xl font-extrabold text-gray-900 flex items-center gap-2">
                        <ShieldCheck className="text-blue-600" size={32} /> Admin Dashboard
                    </h1>
                </header>

                {/* Settings Section */}
                <section className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 space-y-6">
                    <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                        <Globe size={20} className="text-gray-400" /> General Filters
                    </h2>
                    <div className="grid md:grid-cols-2 gap-6">
                        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                            <div>
                                <p className="font-semibold text-gray-700">Suspicious IP Filter</p>
                                <p className="text-xs text-gray-500">Blocks Proxy/VPN and Data Centers</p>
                            </div>
                            <button 
                                onClick={() => updateSetting('isSuspiciousEnabled', !settings.isSuspiciousEnabled)}
                                className={`w-12 h-6 rounded-full transition-colors relative ${settings.isSuspiciousEnabled ? 'bg-blue-600' : 'bg-gray-300'}`}
                            >
                                <span className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform ${settings.isSuspiciousEnabled ? 'translate-x-6' : ''}`} />
                            </button>
                        </div>
                        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                            <div>
                                <p className="font-semibold text-gray-700">Mobile ISP Filter</p>
                                <p className="text-xs text-gray-500">Only allow specific carrier traffic</p>
                            </div>
                            <button 
                                onClick={() => updateSetting('isIspFilterEnabled', !settings.isIspFilterEnabled)}
                                className={`w-12 h-6 rounded-full transition-colors relative ${settings.isIspFilterEnabled ? 'bg-blue-600' : 'bg-gray-300'}`}
                            >
                                <span className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform ${settings.isIspFilterEnabled ? 'translate-x-6' : ''}`} />
                            </button>
                        </div>
                    </div>
                </section>

                {/* Forced IPs */}
                <section className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 space-y-4">
                    <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                        <ShieldAlert size={20} className="text-red-400" /> Forced Redirect IPs
                    </h2>
                    <div className="flex gap-2">
                        <input 
                            type="text" 
                            value={newIp}
                            onChange={(e) => setNewIp(e.target.value)}
                            placeholder="Enter IP (e.g. 1.2.3.4)"
                            className="flex-1 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <button 
                            onClick={() => handleForced(newIp, 'add')}
                            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2"
                        >
                            <UserPlus size={18} /> Add
                        </button>
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="border-b text-gray-400 text-sm uppercase">
                                    <th className="py-3 px-2">IP Address</th>
                                    <th className="py-3 px-2 text-right">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {forcedIps.map(ip => (
                                    <tr key={ip} className="border-b last:border-0 hover:bg-gray-50">
                                        <td className="py-3 px-2 font-mono text-gray-600">{ip}</td>
                                        <td className="py-3 px-2 text-right">
                                            <button onClick={() => handleForced(ip, 'remove')} className="text-red-500 hover:text-red-700">
                                                <Trash2 size={18} />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                                {forcedIps.length === 0 && <tr><td colSpan="2" className="py-4 text-center text-gray-400 italic">No IPs in forced list</td></tr>}
                            </tbody>
                        </table>
                    </div>
                </section>

                {/* Visited IPs */}
                <section className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 space-y-4">
                    <div className="flex justify-between items-center">
                        <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                            <Clock size={20} className="text-orange-400" /> Recent Visits (Restricted)
                        </h2>
                        <button 
                            onClick={() => handleVisited(null, 'clear')}
                            className="text-xs bg-orange-50 text-orange-600 px-3 py-1 rounded hover:bg-orange-100 font-bold"
                        >
                            CLEAR ALL
                        </button>
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="border-b text-gray-400 text-sm uppercase">
                                    <th className="py-3 px-2">IP Address</th>
                                    <th className="py-3 px-2">Visited At</th>
                                    <th className="py-3 px-2 text-right">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {visitedIps.map(entry => {
                                    const ip = typeof entry === 'object' ? entry.ip : entry;
                                    const time = typeof entry === 'object' ? new Date(entry.timestamp).toLocaleString() : 'N/A';
                                    return (
                                        <tr key={ip} className="border-b last:border-0 hover:bg-gray-50">
                                            <td className="py-3 px-2 font-mono text-gray-600">{ip}</td>
                                            <td className="py-3 px-2 text-sm text-gray-500">{time}</td>
                                            <td className="py-3 px-2 text-right">
                                                <button onClick={() => handleVisited(ip, 'remove')} className="text-blue-500 hover:text-blue-700 font-bold text-xs">
                                                    ALLOW REVISIT
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                                {visitedIps.length === 0 && <tr><td colSpan="3" className="py-4 text-center text-gray-400 italic">No restricted visits in the last 24 hours</td></tr>}
                            </tbody>
                        </table>
                    </div>
                </section>
            </div>
        </div>
    );
}
