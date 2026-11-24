import { useCallback, useEffect, useMemo, useState } from 'react';
import { BarChart3, RefreshCw, Save } from 'lucide-react';
import { api, ApiError } from '../../api/client';
import type { NodeDTO, TrafficUsageLog } from '../../types/api';
import { useToast } from '../../contexts/ToastContext';
import { NumericInput } from '../../components/NumericInput';
import {
  formatBytes,
  formatDateTimeMinute,
  localDateTimeToRFC3339,
  toLocalDateTimeOffset,
} from '../../utils/format';

export function TrafficPage() {
  const toast = useToast();
  const [entries, setEntries] = useState<TrafficUsageLog[]>([]);
  const [nodes, setNodes] = useState<NodeDTO[]>([]);
  const [loading, setLoading] = useState(true);
  const [totalStored, setTotalStored] = useState(0);
  const [maxEntries, setMaxEntries] = useState(10000);
  const [limitInput, setLimitInput] = useState(10000);
  const [savingLimit, setSavingLimit] = useState(false);

  const [nodeId, setNodeId] = useState<string>('');
  const [fromTime, setFromTime] = useState<string>(() => toLocalDateTimeOffset(-7 * 86400 * 1000));
  const [toTime, setToTime] = useState<string>(() => toLocalDateTimeOffset(60 * 1000));

  const loadMeta = useCallback(async () => {
    try {
      const n = await api.listNodes();
      setNodes(n);
    } catch {
      // ignore meta error
    }
  }, []);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    try {
      const parsedNodeId = nodeId ? Number(nodeId) : undefined;
      const fromISO = fromTime.trim() ? localDateTimeToRFC3339(fromTime) : null;
      const toISO = toTime.trim() ? localDateTimeToRFC3339(toTime) : null;
      const res = await api.getTrafficLogs({
        node_id: parsedNodeId && parsedNodeId > 0 ? parsedNodeId : undefined,
        from: fromISO || undefined,
        to: toISO || undefined,
        limit: 500,
      });
      setEntries(res.items || []);
      setTotalStored(res.total_stored ?? 0);
      setMaxEntries(res.max_entries ?? 10000);
      setLimitInput(res.max_entries ?? 10000);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载流量日志失败');
    } finally {
      setLoading(false);
    }
  }, [fromTime, nodeId, toTime, toast]);

  useEffect(() => {
    void loadMeta();
  }, [loadMeta]);

  useEffect(() => {
    void loadLogs();
  }, [loadLogs]);

  const handleSaveLimit = async () => {
    if (!Number.isInteger(limitInput) || limitInput < 100 || limitInput > 1000000) {
      toast.error('日志保存上限必须在 100 到 1,000,000 条之间');
      return;
    }
    setSavingLimit(true);
    try {
      const updated = await api.updateSettings({ traffic_log_max_entries: limitInput });
      setMaxEntries(updated.traffic_log_max_entries);
      setLimitInput(updated.traffic_log_max_entries);
      toast.success(`日志保存上限已更新为 ${updated.traffic_log_max_entries} 条`);
      await loadLogs();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '更新日志保存上限失败');
    } finally {
      setSavingLimit(false);
    }
  };

  const totals = useMemo(() => {
    let rx = 0;
    let tx = 0;
    let maxTotal = 0;
    for (const e of entries) {
      rx += e.rx_bytes;
      tx += e.tx_bytes;
      if (e.rx_bytes + e.tx_bytes > maxTotal) maxTotal = e.rx_bytes + e.tx_bytes;
    }
    return { rx, tx, total: rx + tx, maxTotal };
  }, [entries]);

  const applyPresetHours = (hours: number) => {
    setFromTime(toLocalDateTimeOffset(-hours * 3600 * 1000));
    setToTime(toLocalDateTimeOffset(60 * 1000));
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white">节点流量明细日志</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            按分钟粒度记录每个用户在各个节点上的访问与下行 / 上行流量消耗
          </p>
        </div>
        <button type="button" onClick={() => void loadLogs()} className="btn-secondary" disabled={loading}>
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          刷新
        </button>
      </div>

      {/* Filters & Retention Cap */}
      <div className="card space-y-4 p-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <label className="mb-1 block text-xs font-medium">筛选节点</label>
            <select
              className="input-field"
              value={nodeId}
              onChange={(e) => setNodeId(e.target.value)}
            >
              <option value="">全部节点</option>
              {nodes.map((n) => (
                <option key={n.id} value={String(n.id)}>
                  {n.name} (#{n.id})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium">开始时间</label>
            <input
              type="datetime-local"
              className="input-field text-xs"
              value={fromTime}
              onChange={(e) => setFromTime(e.target.value)}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium">结束时间</label>
            <input
              type="datetime-local"
              className="input-field text-xs"
              value={toTime}
              onChange={(e) => setToTime(e.target.value)}
            />
          </div>

          <div className="flex flex-col justify-end">
            <label className="mb-1 block text-xs font-medium text-slate-500 dark:text-slate-400">
              快捷时间范围
            </label>
            <div className="flex flex-wrap gap-1.5">
              <button type="button" onClick={() => applyPresetHours(1)} className="btn-secondary flex-1 px-2 py-1.5 text-xs">
                近 1 小时
              </button>
              <button type="button" onClick={() => applyPresetHours(24)} className="btn-secondary flex-1 px-2 py-1.5 text-xs">
                24 小时
              </button>
              <button type="button" onClick={() => applyPresetHours(24 * 7)} className="btn-secondary flex-1 px-2 py-1.5 text-xs">
                近 7 天
              </button>
              <button
                type="button"
                onClick={() => {
                  setFromTime('');
                  setToTime('');
                }}
                className="btn-secondary flex-1 px-2 py-1.5 text-xs"
              >
                全部
              </button>
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-3 border-t border-slate-100 pt-3 dark:border-slate-800 sm:flex-row sm:items-center sm:justify-between">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            数据库当前已保存{' '}
            <strong className="font-mono text-slate-800 dark:text-slate-200">{totalStored}</strong> /{' '}
            <strong className="font-mono text-slate-800 dark:text-slate-200">{maxEntries}</strong> 条日志（超出上限自动淘汰最早记录）
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="traffic-log-cap" className="text-xs font-medium text-slate-600 dark:text-slate-300">
              日志保存上限（条）：
            </label>
            <NumericInput
              id="traffic-log-cap"
              min={100}
              max={1000000}
              className="input-field w-28 py-1.5 font-mono text-xs"
              value={limitInput}
              onChange={(v) => setLimitInput(v)}
            />
            <button
              type="button"
              onClick={() => void handleSaveLimit()}
              disabled={savingLimit}
              className="btn-primary px-3 py-1.5 text-xs"
            >
              <Save className="h-3.5 w-3.5" />
              {savingLimit ? '保存中...' : '保存上限'}
            </button>
          </div>
        </div>
      </div>

      {/* Summary KPIs */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 sm:gap-4">
        <div className="card p-4">
          <span className="text-xs font-medium text-slate-500">当前结果下载 (RX)</span>
          <p className="mt-1 font-mono text-xl font-bold text-emerald-600 dark:text-emerald-400">
            {formatBytes(totals.rx)}
          </p>
        </div>
        <div className="card p-4">
          <span className="text-xs font-medium text-slate-500">当前结果上传 (TX)</span>
          <p className="mt-1 font-mono text-xl font-bold text-indigo-600 dark:text-indigo-400">
            {formatBytes(totals.tx)}
          </p>
        </div>
        <div className="card p-4">
          <span className="text-xs font-medium text-slate-500">双向合计（{entries.length} 条记录）</span>
          <p className="mt-1 font-mono text-xl font-bold text-slate-900 dark:text-white">
            {formatBytes(totals.total)}
          </p>
        </div>
      </div>

      {entries.length === 0 && !loading ? (
        <div className="card flex flex-col items-center justify-center py-14 text-center">
          <BarChart3 className="h-10 w-10 text-slate-300 dark:text-slate-600" />
          <p className="mt-3 text-sm font-medium text-slate-600 dark:text-slate-300">
            当前筛选条件下暂无流量日志
          </p>
          <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">
            仅在有用户通过 SS2022 + ShadowTLS 节点产生流量时按分钟记录明细。
          </p>
        </div>
      ) : (
        <>
          {/* Mobile Card List */}
          <div className="space-y-3 md:hidden">
            {entries.map((entry) => {
              const sum = entry.rx_bytes + entry.tx_bytes;
              const widthPct = totals.maxTotal > 0 ? Math.max(2, (sum / totals.maxTotal) * 100) : 0;
              return (
                <div key={entry.id} className="card space-y-2.5 p-4 text-xs">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono font-medium text-slate-600 dark:text-slate-300">
                      {formatDateTimeMinute(entry.log_minute)}
                    </span>
                    <span className="inline-flex items-center rounded-md bg-violet-100 px-2 py-0.5 text-[11px] font-semibold text-violet-700 dark:bg-violet-950/70 dark:text-violet-300">
                      {entry.user_id === 0
                        ? entry.username || '管理员 (Snell)'
                        : `用户：${entry.username} (#${entry.user_id})`}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="inline-flex items-center gap-1.5 rounded-md bg-sky-100 px-2 py-0.5 text-[11px] font-semibold text-sky-800 dark:bg-sky-950/70 dark:text-sky-300">
                      {entry.node_name}
                      {entry.region_tag ? ` · ${entry.region_tag}` : ''}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 rounded-lg bg-slate-50 p-2.5 dark:bg-slate-800/60">
                    <div>
                      <div className="text-[11px] text-slate-400">下载 (RX)</div>
                      <div className="mt-0.5 font-mono font-semibold text-emerald-600 dark:text-emerald-400">
                        {formatBytes(entry.rx_bytes)}
                      </div>
                    </div>
                    <div>
                      <div className="text-[11px] text-slate-400">上传 (TX)</div>
                      <div className="mt-0.5 font-mono font-semibold text-indigo-600 dark:text-indigo-400">
                        {formatBytes(entry.tx_bytes)}
                      </div>
                    </div>
                    <div>
                      <div className="text-[11px] text-slate-400">合计</div>
                      <div className="mt-0.5 font-mono font-semibold text-slate-900 dark:text-white">
                        {formatBytes(sum)}
                      </div>
                    </div>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                    <div className="h-full rounded-full bg-indigo-500" style={{ width: `${widthPct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Desktop Table */}
          <div className="card hidden overflow-hidden md:block">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
                <thead className="bg-slate-50 text-left text-xs font-semibold text-slate-500 dark:bg-slate-800/50 dark:text-slate-400">
                  <tr>
                    <th className="px-4 py-3">时间</th>
                    <th className="px-4 py-3">节点</th>
                    <th className="px-4 py-3">用户</th>
                    <th className="px-4 py-3">下载 (RX)</th>
                    <th className="px-4 py-3">上传 (TX)</th>
                    <th className="px-4 py-3">合计</th>
                    <th className="px-4 py-3">占比</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {entries.map((entry) => {
                    const sum = entry.rx_bytes + entry.tx_bytes;
                    const widthPct = totals.maxTotal > 0 ? Math.max(2, (sum / totals.maxTotal) * 100) : 0;
                    return (
                      <tr key={entry.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                        <td className="px-4 py-3 whitespace-nowrap font-mono text-xs text-slate-700 dark:text-slate-300">
                          {formatDateTimeMinute(entry.log_minute)}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-xs font-medium">
                          <span className="text-slate-900 dark:text-white">{entry.node_name}</span>
                          {entry.region_tag && (
                            <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-semibold uppercase text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                              {entry.region_tag}
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-xs">
                          <span className="inline-flex items-center gap-1 rounded-md bg-violet-50 px-2 py-0.5 font-medium text-violet-700 dark:bg-violet-950/60 dark:text-violet-300">
                            {entry.user_id === 0 ? (
                              <span>{entry.username || '管理员 (Snell)'}</span>
                            ) : (
                              <>
                                <span>{entry.username}</span>
                                <span className="font-mono text-[11px] opacity-70">#{entry.user_id}</span>
                              </>
                            )}
                          </span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap font-mono text-xs text-emerald-600 dark:text-emerald-400">
                          {formatBytes(entry.rx_bytes)}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap font-mono text-xs text-indigo-600 dark:text-indigo-400">
                          {formatBytes(entry.tx_bytes)}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap font-mono text-xs font-semibold">
                          {formatBytes(sum)}
                        </td>
                        <td className="w-36 px-4 py-3">
                          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                            <div className="h-full rounded-full bg-indigo-500" style={{ width: `${widthPct}%` }} />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
