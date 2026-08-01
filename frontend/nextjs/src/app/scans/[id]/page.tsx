'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { deleteScan, fetchScanDetails, ScanDetails } from '@/lib/api';
import { ProfessionalReport } from '@/components/report/ProfessionalReport';

export default function ScanDetailsPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const [scan, setScan] = useState<ScanDetails | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!params?.id) return;
    fetchScanDetails(params.id).then((data) => {
      setScan(data);
      setLoading(false);
    });
  }, [params?.id]);

  const remove = async () => {
    if (!scan) return;
    const ok = await deleteScan(scan.id);
    if (ok) router.push('/');
  };

  if (loading) {
    return <p className="py-20 text-center text-sm text-muted">Loading analysis report…</p>;
  }

  if (!scan) {
    return (
      <div className="py-20 text-center">
        <p className="text-sm text-muted">Report not found.</p>
        <Link href="/" className="mt-3 inline-block text-sm font-medium text-brand hover:underline">
          Back to dashboard
        </Link>
      </div>
    );
  }

  return <ProfessionalReport scan={scan} onDelete={remove} />;
}
