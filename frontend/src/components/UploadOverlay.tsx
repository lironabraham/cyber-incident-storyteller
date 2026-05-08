import { useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { Upload, Shield, Loader2 } from 'lucide-react';

interface Props {
  loading: boolean;
  error: string | null;
  onUpload: (file: File) => void;
}

export default function UploadOverlay({ loading, error, onUpload }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  function handleFiles(files: FileList | null) {
    if (!files?.[0]) return;
    onUpload(files[0]);
  }

  return (
    <div style={{
      position: 'absolute', inset: 0,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'linear-gradient(135deg, #0A0A0B 0%, #0d1117 100%)',
      zIndex: 10,
    }}>
      <div style={{
        position: 'absolute', inset: 0, opacity: 0.35,
        backgroundImage: 'radial-gradient(circle, #2A2A2E 1px, transparent 1px)',
        backgroundSize: '24px 24px',
      }} />

      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: 'easeOut' }}
        style={{ position: 'relative', textAlign: 'center', maxWidth: 420, padding: '0 24px' }}
      >
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 24 }}>
          <div style={{
            width: 64, height: 64, borderRadius: 16,
            background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 32px rgba(59,130,246,0.15)',
          }}>
            <Shield size={32} color="#3B82F6" />
          </div>
        </div>

        <h1 style={{
          fontFamily: 'Inter, sans-serif', fontSize: 22, fontWeight: 700,
          color: '#E4E4E7', marginBottom: 6, letterSpacing: '-0.02em',
        }}>
          Cyber Incident Storyteller
        </h1>
        <p style={{ fontSize: 13, color: '#71717A', marginBottom: 32, lineHeight: 1.5 }}>
          Upload a Windows Event Log to visualize the attack chain
        </p>

        <div
          onClick={() => !loading && inputRef.current?.click()}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={e => {
            e.preventDefault(); setDragging(false);
            if (!loading) handleFiles(e.dataTransfer.files);
          }}
          style={{
            border:      `1px solid ${dragging ? '#3B82F6' : 'rgba(255,255,255,0.1)'}`,
            borderRadius: 12,
            padding:     '36px 24px',
            cursor:      loading ? 'default' : 'pointer',
            background:  dragging ? 'rgba(59,130,246,0.06)' : 'rgba(255,255,255,0.02)',
            transition:  'border-color 0.15s, background 0.15s',
            boxShadow:   dragging ? '0 0 0 1px rgba(59,130,246,0.3)' : 'none',
          }}
        >
          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
              <Loader2 size={28} color="#3B82F6" style={{ animation: 'spin 1s linear infinite' }} />
              <span style={{ fontSize: 13, color: '#71717A' }}>Analyzing attack chains…</span>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
              <Upload size={24} color={dragging ? '#3B82F6' : '#71717A'} />
              <div>
                <div style={{ fontSize: 14, color: '#E4E4E7', fontWeight: 500 }}>
                  {dragging ? 'Drop to analyze' : 'Drop .evtx file here'}
                </div>
                <div style={{ fontSize: 12, color: '#71717A', marginTop: 4 }}>
                  or click to browse · Windows Event Log
                </div>
              </div>
            </div>
          )}
        </div>

        {error && (
          <div style={{
            marginTop: 16, padding: '10px 14px', borderRadius: 8,
            background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)',
            fontSize: 13, color: '#EF4444', textAlign: 'left',
          }}>
            {error}
          </div>
        )}

        <input
          ref={inputRef} type="file" accept=".evtx" hidden
          onChange={e => handleFiles(e.target.files)}
        />

        <p style={{ marginTop: 20, fontSize: 11, color: '#3a3a3e' }}>
          Processed locally · No data leaves your machine
        </p>
      </motion.div>

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
