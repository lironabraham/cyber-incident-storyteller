import { useState, useCallback } from 'react';
import type { AnalysisResponse } from '../types';

type Status = 'idle' | 'loading' | 'done' | 'error';

interface UseAnalysisReturn {
  status: Status;
  data: AnalysisResponse | null;
  error: string | null;
  upload: (file: File) => Promise<void>;
  reset: () => void;
}

export function useAnalysis(): UseAnalysisReturn {
  const [status, setStatus] = useState<Status>('idle');
  const [data, setData]     = useState<AnalysisResponse | null>(null);
  const [error, setError]   = useState<string | null>(null);

  const upload = useCallback(async (file: File) => {
    setStatus('loading');
    setError(null);
    setData(null);

    const fd = new FormData();
    fd.append('file', file);

    try {
      const res  = await fetch('/api/upload', { method: 'POST', body: fd });
      const json = await res.json();
      if (!res.ok) throw new Error(json.detail ?? `HTTP ${res.status}`);
      setData(json as AnalysisResponse);
      setStatus('done');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setStatus('error');
    }
  }, []);

  const reset = useCallback(() => {
    setStatus('idle');
    setData(null);
    setError(null);
  }, []);

  return { status, data, error, upload, reset };
}
