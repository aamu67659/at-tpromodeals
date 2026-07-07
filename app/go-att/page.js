'use client';

import { useEffect } from 'react';

export default function GoAttPage() {
  useEffect(() => {
    // We already recorded the visit in /api/init if the target was /go-att
    // but just to be sure we can hit a 'record' endpoint or just redirect.
    // The original app redirected to process.env.ATT_LANDING_PAGE
    window.location.href = '/api/record-visit';
  }, []);

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="animate-spin rounded-full h-10 w-10 border-t-4 border-blue-500 border-opacity-50"></div>
    </div>
  );
}
