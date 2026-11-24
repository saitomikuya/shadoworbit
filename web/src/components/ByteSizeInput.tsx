import { useEffect, useRef, useState } from 'react';
import { formatBytes } from '../utils/format';

type Unit = 'B' | 'MB' | 'GB' | 'TB';

const UNIT_FACTORS: Record<Unit, number> = {
  B: 1,
  MB: 1024 * 1024,
  GB: 1024 * 1024 * 1024,
  TB: 1024 * 1024 * 1024 * 1024,
};

function bestUnit(bytes: number): Unit {
  if (bytes === 0) return 'GB';
  if (bytes % UNIT_FACTORS.TB === 0) return 'TB';
  if (bytes % UNIT_FACTORS.GB === 0 || bytes >= UNIT_FACTORS.GB) return 'GB';
  if (bytes % UNIT_FACTORS.MB === 0 || bytes >= UNIT_FACTORS.MB) return 'MB';
  return 'B';
}

function formatDraft(bytes: number, unit: Unit): string {
  if (bytes === 0) return '0';
  return String(Number((bytes / UNIT_FACTORS[unit]).toFixed(4)));
}

export function ByteSizeInput({
  label,
  value,
  onChange,
  hint,
  zeroText = '0 = 不限制 / 关闭',
}: {
  label: string;
  value: number;
  onChange: (bytes: number) => void;
  hint?: string;
  zeroText?: string;
}) {
  const [unit, setUnit] = useState<Unit>(() => bestUnit(value));
  const [draft, setDraft] = useState<string>(() => formatDraft(value, bestUnit(value)));
  const lastEmittedRef = useRef<number>(value);

  useEffect(() => {
    if (value === lastEmittedRef.current) return;
    const nextUnit = bestUnit(value);
    lastEmittedRef.current = value;
    setUnit(nextUnit);
    setDraft(formatDraft(value, nextUnit));
  }, [value]);

  const handleNumberChange = (raw: string) => {
    setDraft(raw);
    if (raw.trim() === '') {
      lastEmittedRef.current = 0;
      onChange(0);
      return;
    }
    const num = Number(raw);
    if (!Number.isFinite(num) || num < 0) {
      lastEmittedRef.current = 0;
      onChange(0);
      return;
    }
    const nextBytes = Math.round(num * UNIT_FACTORS[unit]);
    lastEmittedRef.current = nextBytes;
    onChange(nextBytes);
  };

  const handleUnitChange = (nextUnit: Unit) => {
    setUnit(nextUnit);
    const trimmed = draft.trim();
    if (trimmed === '') {
      lastEmittedRef.current = 0;
      onChange(0);
      return;
    }
    const num = Number(trimmed);
    if (!Number.isFinite(num) || num < 0) {
      lastEmittedRef.current = 0;
      onChange(0);
      return;
    }
    const nextBytes = Math.round(num * UNIT_FACTORS[nextUnit]);
    lastEmittedRef.current = nextBytes;
    onChange(nextBytes);
  };

  const handleBlur = () => {
    if (draft.trim() === '') {
      setDraft('0');
    }
  };

  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">
        {label}
      </label>
      <div className="flex gap-2">
        <input
          type="number"
          min={0}
          step="any"
          className="input-field flex-1"
          value={draft}
          onChange={(e) => handleNumberChange(e.target.value)}
          onBlur={handleBlur}
        />
        <select
          className="input-field w-24 shrink-0"
          value={unit}
          onChange={(e) => handleUnitChange(e.target.value as Unit)}
        >
          <option value="GB">GB</option>
          <option value="TB">TB</option>
          <option value="MB">MB</option>
          <option value="B">字节</option>
        </select>
      </div>
      <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
        {value === 0 ? zeroText : `精确值: ${value.toLocaleString()} B (${formatBytes(value)})`}
        {hint ? ` · ${hint}` : ''}
      </p>
    </div>
  );
}
