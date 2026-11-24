import type { NodeStatus } from '../types/api';

export function NodeStatusBadge({ status }: { status: NodeStatus }) {
  if (status === 'online') {
    return (
      <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-950/80 dark:text-emerald-300 dark:ring-1 dark:ring-emerald-800/70">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
        在线
      </span>
    );
  }
  if (status === 'traffic_paused') {
    return (
      <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full bg-amber-100 px-2.5 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-950/80 dark:text-amber-300 dark:ring-1 dark:ring-amber-800/70">
        <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
        流量暂停
      </span>
    );
  }
  return (
    <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full bg-rose-100 px-2.5 py-0.5 text-xs font-medium text-rose-800 dark:bg-rose-950/80 dark:text-rose-300 dark:ring-1 dark:ring-rose-800/70">
      <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />
      离线
    </span>
  );
}

export function HealthPill({ label, healthy }: { label: string; healthy: boolean }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium ${
        healthy
          ? 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:ring-emerald-800/60'
          : 'bg-slate-100 text-slate-500 ring-1 ring-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:ring-slate-700'
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${healthy ? 'bg-emerald-500' : 'bg-slate-400 dark:bg-slate-500'}`}
      />
      {label}
    </span>
  );
}
