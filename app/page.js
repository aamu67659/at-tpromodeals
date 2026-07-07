'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function LoadingPage() {
  const router = useRouter();

  useEffect(() => {
    async function init() {
      try {
        const response = await fetch('/api/init');
        const data = await response.json();
        if (data.redirect) {
          if (data.redirect.startsWith('/')) {
            router.push(data.redirect);
          } else {
            window.location.href = data.redirect;
          }
        }
      } catch (error) {
        console.error('Initialization failed');
      }
    }
    init();
  }, [router]);

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="animate-spin rounded-full h-10 w-10 border-t-4 border-blue-500 border-opacity-50"></div>
    </div>
  );
}
