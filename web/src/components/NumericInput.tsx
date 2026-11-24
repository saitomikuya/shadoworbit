import React, { useEffect, useRef, useState } from 'react';

interface NumericInputProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type' | 'value' | 'onChange'> {
  value: number;
  onChange: (next: number) => void;
}

export function NumericInput({ value, onChange, ...rest }: NumericInputProps) {
  const [draft, setDraft] = useState<string>(() => (Number.isFinite(value) ? String(value) : ''));
  const lastEmittedRef = useRef<number>(value);

  useEffect(() => {
    if (Object.is(value, lastEmittedRef.current)) return;
    lastEmittedRef.current = value;
    setDraft(Number.isFinite(value) ? String(value) : '');
  }, [value]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.value;
    setDraft(raw);
    if (raw.trim() === '') {
      lastEmittedRef.current = NaN;
      onChange(NaN);
      return;
    }
    const parsed = Number(raw);
    lastEmittedRef.current = parsed;
    onChange(parsed);
  };

  return <input type="number" {...rest} value={draft} onChange={handleChange} />;
}
