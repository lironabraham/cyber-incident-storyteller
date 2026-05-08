import { useState, useMemo } from 'react';

interface Props {
  eventTimestamps: string[];
  onTimeChange: (time: number | null) => void;
}

export default function TimelineScrubber({ eventTimestamps, onTimeChange }: Props) {
  const [active, setActive] = useState(false);
  const [value,  setValue]  = useState(100);

  const { minMs, maxMs, minLabel, maxLabel } = useMemo(() => {
    const ms = eventTimestamps.map(t => new Date(t).getTime()).filter(n => !isNaN(n));
    if (ms.length === 0) return { minMs: 0, maxMs: 0, minLabel: '', maxLabel: '' };
    const mn = Math.min(...ms), mx = Math.max(...ms);
    const fmt = (t: number) => new Date(t).toISOString().slice(11, 19);
    return { minMs: mn, maxMs: mx, minLabel: fmt(mn), maxLabel: fmt(mx) };
  }, [eventTimestamps]);

  function toggle() {
    const next = !active;
    setActive(next);
    if (!next) {
      setValue(100);
      onTimeChange(null);
    } else {
      onTimeChange(minMs + (value / 100) * (maxMs - minMs));
    }
  }

  function handleChange(v: number) {
    setValue(v);
    onTimeChange(minMs + (v / 100) * (maxMs - minMs));
  }

  if (eventTimestamps.length === 0) return null;

  const currentLabel = active
    ? new Date(minMs + (value / 100) * (maxMs - minMs)).toISOString().slice(11, 19)
    : null;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, minWidth: 0 }}>
      <label style={{
        display: 'flex', alignItems: 'center', gap: 5,
        cursor: 'pointer', flexShrink: 0, userSelect: 'none',
      }}>
        <input
          type="checkbox"
          checked={active}
          onChange={toggle}
          style={{ accentColor: '#3B82F6', cursor: 'pointer', width: 11, height: 11 }}
        />
        <span style={{
          fontSize: 9, letterSpacing: '0.07em', textTransform: 'uppercase',
          fontFamily: 'JetBrains Mono, monospace',
          color: active ? '#3B82F6' : '#52525B',
          transition: 'color 0.15s',
        }}>
          TIME FILTER
        </span>
      </label>

      {/* Scrubber only visible when the filter is enabled */}
      {active && (
        <>
          <span style={{ fontSize: 9, color: '#52525B', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>
            {minLabel}
          </span>
          <input
            type="range" min={0} max={100} value={value}
            onChange={e => handleChange(Number(e.target.value))}
            style={{ flex: 1, height: 2, accentColor: '#3B82F6', cursor: 'pointer' }}
          />
          <span style={{ fontSize: 9, color: '#52525B', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>
            {maxLabel}
          </span>
          {currentLabel && (
            <span style={{
              fontSize: 9, color: '#3B82F6', fontFamily: 'JetBrains Mono, monospace',
              flexShrink: 0, minWidth: 56,
            }}>
              ▶ {currentLabel}
            </span>
          )}
        </>
      )}
    </div>
  );
}
