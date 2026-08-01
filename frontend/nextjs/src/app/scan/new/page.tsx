'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

/** Scan launcher lives on the dashboard — keep this route as a friendly redirect. */
export default function NewScanRedirect() {
  const router = useRouter();
  useEffect(() => {
    router.replace('/');
  }, [router]);

  return (
    <p className="py-20 text-center text-sm text-muted">
      Opening the scan controller…
    </p>
  );
}
