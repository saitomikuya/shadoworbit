import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  ArrowDown,
  ArrowUp,
  Clock,
  Cpu,
  LayoutGrid,
  List,
  Megaphone,
  MemoryStick,
  Moon,
  RefreshCw,
  Server,
  Shield,
  Sun,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { api, buildPublicWsUrl } from '../../api/client';
import type { PublicNodeView, PublicStatusSnapshot } from '../../types/api';
import { useTheme } from '../../contexts/ThemeContext';
import { HealthPill, NodeStatusBadge } from '../../components/Badge';
import { formatBytes, formatSpeed, formatUptime } from '../../utils/format';

type ViewMode = 'cards' | 'table';
type WsState = 'connecting' | 'live' | 'reconnecting';

function TrafficBar({
  node,
  globalPercentageOnly,
  compact = false,
}: {
  node: PublicNodeView;
  globalPercentageOnly: boolean;
  compact?: boolean;
}) {
  const pctOnly = globalPercentageOnly || node.percentage_only;
  const unlimited = !pctOnly && node.traffic_limit_bytes === 0 && node.traffic_percent === 0;
  const thresholdOnly = !pctOnly && node.traffic_limit_bytes === 0 && node.traffic_percent > 0;
  const pct = Math.min(100, Math.max(0, node.traffic_percent));
  const barColor =
    pct >= 90 ? 'bg-rose-500' : pct >= 75 ? 'bg-amber-500' : 'bg-indigo-500 dark:bg-indigo-400';

  return (
    <div className={compact ? 'space-y-1' : 'space-y-1.5'}>
      <div className={`flex items-center justify-between gap-2 ${compact ? 'text-[11px]' : 'text-xs'}`}>
        <span className="shrink-0 text-slate-500 dark:text-slate-400">周期流量</span>
        {pctOnly ? (
          <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
            {pct.toFixed(2)}%
          </span>
        ) : unlimited ? (
          <span className="truncate font-medium text-emerald-700 dark:text-emerald-400">
            不限{node.traffic_used_bytes > 0 ? `（${formatBytes(node.traffic_used_bytes)}）` : ''}
          </span>
        ) : thresholdOnly ? (
          <span className="truncate font-mono text-slate-700 dark:text-slate-300">
            {formatBytes(node.traffic_used_bytes)}{' '}
            <span className="text-slate-400">({node.traffic_percent.toFixed(1)}%)</span>
          </span>
        ) : (
          <span className="truncate font-mono text-slate-700 dark:text-slate-300">
            {formatBytes(node.traffic_used_bytes)} / {formatBytes(node.traffic_limit_bytes)}{' '}
            <span className="text-slate-400">({pct.toFixed(1)}%)</span>
          </span>
        )}
      </div>
      <div className={`${compact ? 'h-1.5' : 'h-2'} w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800`}>
        <div
          className={`h-full rounded-full transition-all duration-300 ${unlimited ? 'bg-emerald-500/40 w-full' : barColor}`}
          style={unlimited ? undefined : { width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

function formatPausedReason(reason: string): string {
  if (!reason) return '';
  if (reason === 'traffic threshold reached') return '已达到流量阈值';
  return reason;
}

export function StatusPage() {
  const { theme, toggleTheme } = useTheme();
  const [snapshot, setSnapshot] = useState<PublicStatusSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [wsState, setWsState] = useState<WsState>('connecting');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('cards');
  const retryAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<number | null>(null);

  const fetchSnapshot = useCallback(async () => {
    try {
      const data = await api.getPublicStatus();
      setSnapshot(data);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : '加载状态失败');
    }
  }, []);

  useEffect(() => {
    if (snapshot?.site_title) {
      document.title = snapshot.site_title;
    }
  }, [snapshot?.site_title]);

  useEffect(() => {
    void fetchSnapshot();

    let disposed = false;
    let ws: WebSocket | null = null;

    const connectWs = () => {
      if (disposed) return;
      setWsState(retryAttemptRef.current === 0 ? 'connecting' : 'reconnecting');

      try {
        ws = new WebSocket(buildPublicWsUrl());
      } catch {
        scheduleReconnect();
        return;
      }

      ws.onopen = () => {
        if (disposed) return;
        retryAttemptRef.current = 0;
        setWsState('live');
      };

      ws.onmessage = (event) => {
        if (disposed) return;
        try {
          const parsed = JSON.parse(event.data) as PublicStatusSnapshot;
          if (parsed && Array.isArray(parsed.nodes)) {
            setSnapshot(parsed);
            setError(null);
            setLastUpdated(new Date());
          }
        } catch {
          // ignore malformed frames
        }
      };

      ws.onerror = () => {
        ws?.close();
      };

      ws.onclose = () => {
        if (disposed) return;
        scheduleReconnect();
      };
    };

    const scheduleReconnect = () => {
      if (disposed) return;
      setWsState('reconnecting');
      const attempt = retryAttemptRef.current;
      retryAttemptRef.current = Math.min(attempt + 1, 5);
      const delayMs = Math.min(1000 * Math.pow(2, attempt), 15000);
      reconnectTimerRef.current = window.setTimeout(connectWs, delayMs);
    };

    connectWs();

    // 30s REST fallback poll keeps metadata (site_title, announcement, percentage_only) & disconnected states fresh
    const pollTimer = window.setInterval(() => {
      void fetchSnapshot();
    }, 30000);

    return () => {
      disposed = true;
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
      }
      window.clearInterval(pollTimer);
      if (ws) {
        ws.onopen = null;
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;
        ws.close();
      }
    };
  }, [fetchSnapshot]);

  const stats = useMemo(() => {
    const nodes = snapshot?.nodes ?? [];
    let online = 0;
    let paused = 0;
    let offline = 0;
    let totalRxBps = 0;
    let totalTxBps = 0;
    let totalUsedBytes = 0;
    let totalCumulativeRxBytes = 0;
    let totalCumulativeTxBytes = 0;
    for (const n of nodes) {
      if (n.status === 'online') online++;
      else if (n.status === 'traffic_paused') paused++;
      else offline++;
      totalRxBps += n.rx_bps || 0;
      totalTxBps += n.tx_bps || 0;
      totalUsedBytes += n.traffic_used_bytes || 0;
      totalCumulativeRxBytes += n.total_rx_bytes || 0;
      totalCumulativeTxBytes += n.total_tx_bytes || 0;
    }
    return {
      total: nodes.length,
      online,
      paused,
      offline,
      totalRxBps,
      totalTxBps,
      totalUsedBytes,
      totalCumulativeRxBytes,
      totalCumulativeTxBytes,
      totalCumulativeBytes: totalCumulativeRxBytes + totalCumulativeTxBytes,
    };
  }, [snapshot]);

  const siteTitle = snapshot?.site_title || 'ShadowOrbit';
  const nodes = snapshot?.nodes ?? [];
  const pctOnly = Boolean(snapshot?.percentage_only);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      <header className="sticky top-0 z-30 border-b border-slate-200/80 bg-white/85 backdrop-blur dark:border-slate-800/80 dark:bg-slate-900/85">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-2 sm:gap-4 px-3 py-3 sm:px-6 sm:py-3.5 lg:px-8">
          <div className="flex min-w-0 items-center gap-2.5 sm:gap-3">
            <div className="flex h-8 w-8 sm:h-9 sm:w-9 shrink-0 items-center justify-center rounded-xl bg-indigo-600 text-white shadow-sm dark:bg-indigo-500">
              <Activity className="h-4 w-4 sm:h-5 sm:w-5" />
            </div>
            <div className="min-w-0">
              <h1 className="truncate text-sm font-bold tracking-tight sm:text-lg">{siteTitle}</h1>
              <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                <span className="inline-flex items-center gap-1 whitespace-nowrap">
                  {wsState === 'live' ? (
                    <>
                      <Wifi className="h-3.5 w-3.5 text-emerald-500" />
                      <span className="text-emerald-600 dark:text-emerald-400">实时推送</span>
                    </>
                  ) : (
                    <>
                      <WifiOff className="h-3.5 w-3.5 text-amber-500" />
                      <span>{wsState === 'connecting' ? '正在连接...' : '正在重连...'}</span>
                    </>
                  )}
                </span>
                {lastUpdated && (
                  <span className="hidden sm:inline">· 更新于 {lastUpdated.toLocaleTimeString('zh-CN')}</span>
                )}
              </div>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-1.5 sm:gap-2">
            <button
              type="button"
              onClick={() => void fetchSnapshot()}
              className="btn-secondary px-2 py-1.5 sm:px-2.5 sm:py-2"
              title="刷新状态"
              aria-label="刷新状态"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
            <button
              type="button"
              onClick={toggleTheme}
              className="btn-secondary px-2 py-1.5 sm:px-2.5 sm:py-2"
              title={theme === 'dark' ? '切换浅色模式' : '切换深色模式'}
              aria-label="切换主题"
            >
              {theme === 'dark' ? <Sun className="h-4 w-4 text-amber-400" /> : <Moon className="h-4 w-4" />}
            </button>
            <Link to="/admin" className="btn-primary px-2.5 py-1.5 text-xs sm:px-3.5 sm:py-2 sm:text-sm">
              <Shield className="h-4 w-4" />
              <span className="hidden sm:inline">管理后台</span>
              <span className="sm:hidden">后台</span>
            </Link>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6 lg:px-8">
        {snapshot?.announcement && snapshot.announcement.trim() !== '' && (
          <div className="flex items-start gap-3 rounded-xl border border-indigo-200 bg-indigo-50/90 px-4 py-3 text-sm text-indigo-950 dark:border-indigo-900/70 dark:bg-indigo-950/50 dark:text-indigo-100">
            <Megaphone className="mt-0.5 h-4 w-4 shrink-0 text-indigo-600 dark:text-indigo-400" />
            <p className="whitespace-pre-wrap leading-relaxed">{snapshot.announcement}</p>
          </div>
        )}

        {error && (
          <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/60 dark:bg-rose-950/40 dark:text-rose-200">
            {error}
          </div>
        )}

        {/* Summary KPI Grid */}
        <section className="grid grid-cols-2 gap-3 lg:grid-cols-5 sm:gap-4">
          <div className="card p-4">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">在线节点</p>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-2xl font-bold text-slate-900 dark:text-white">{stats.online}</span>
              <span className="text-xs text-slate-500 dark:text-slate-400">/ {stats.total} 总数</span>
            </div>
            {(stats.paused > 0 || stats.offline > 0) && (
              <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                {stats.paused > 0 ? `${stats.paused} 暂停` : ''}
                {stats.paused > 0 && stats.offline > 0 ? ' · ' : ''}
                {stats.offline > 0 ? `${stats.offline} 离线` : ''}
              </p>
            )}
          </div>

          <div className="card p-4">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">实时下载</p>
            <div className="mt-1.5 flex items-center gap-1.5 text-2xl font-bold text-emerald-600 dark:text-emerald-400">
              <ArrowDown className="h-4 w-4 shrink-0" />
              <span className="truncate text-lg sm:text-xl font-mono">{formatSpeed(stats.totalRxBps)}</span>
            </div>
          </div>

          <div className="card p-4">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">实时上传</p>
            <div className="mt-1.5 flex items-center gap-1.5 text-2xl font-bold text-indigo-600 dark:text-indigo-400">
              <ArrowUp className="h-4 w-4 shrink-0" />
              <span className="truncate text-lg sm:text-xl font-mono">{formatSpeed(stats.totalTxBps)}</span>
            </div>
          </div>

          <div className="card p-4">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">周期流量</p>
            <p className="mt-1.5 font-mono text-lg font-bold text-slate-900 dark:text-white sm:text-xl">
              {pctOnly ? '已隐藏' : formatBytes(stats.totalUsedBytes)}
            </p>
            <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
              {pctOnly ? '仅百分比模式' : '全部启用节点汇总'}
            </p>
          </div>

          <div className="card col-span-2 p-4 lg:col-span-1">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">累计总流量</p>
            <p className="mt-1.5 font-mono text-lg font-bold text-slate-900 dark:text-white sm:text-xl">
              {pctOnly ? '已隐藏' : formatBytes(stats.totalCumulativeBytes)}
            </p>
            <p className="mt-0.5 truncate font-mono text-[11px] text-slate-500 dark:text-slate-400">
              {pctOnly
                ? '仅百分比模式'
                : `↓ ${formatBytes(stats.totalCumulativeRxBytes)} / ↑ ${formatBytes(stats.totalCumulativeTxBytes)}`}
            </p>
          </div>
        </section>

        {/* Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="flex items-center gap-2 text-sm font-semibold tracking-wider text-slate-500 dark:text-slate-400">
            <Server className="h-4 w-4" />
            服务节点 ({nodes.length})
          </h2>
          <div className="inline-flex rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-800 dark:bg-slate-900">
            <button
              type="button"
              onClick={() => setViewMode('cards')}
              className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium ${
                viewMode === 'cards'
                  ? 'bg-indigo-600 text-white dark:bg-indigo-500'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
              }`}
            >
              <LayoutGrid className="h-3.5 w-3.5" />
              卡片视图
            </button>
            <button
              type="button"
              onClick={() => setViewMode('table')}
              className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium ${
                viewMode === 'table'
                  ? 'bg-indigo-600 text-white dark:bg-indigo-500'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
              }`}
            >
              <List className="h-3.5 w-3.5" />
              表格视图
            </button>
          </div>
        </div>

        {/* Empty State */}
        {nodes.length === 0 ? (
          <div className="card flex flex-col items-center justify-center py-16 text-center">
            <Server className="h-10 w-10 text-slate-300 dark:text-slate-600" />
            <p className="mt-3 text-sm font-medium text-slate-600 dark:text-slate-300">
              暂无已发布的节点
            </p>
            <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">
              请登录管理后台添加并启用节点。
            </p>
          </div>
        ) : viewMode === 'cards' ? (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
            {nodes.map((node) => {
              const memPct =
                node.mem_total_bytes > 0
                  ? Math.min(100, (node.mem_used_bytes / node.mem_total_bytes) * 100)
                  : 0;
              const nodePctOnly = pctOnly || node.percentage_only;
              return (
                <div key={node.id} className="card flex flex-col justify-between p-3.5">
                  <div className="space-y-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5">
                          <h3 className="truncate text-sm font-semibold text-slate-900 dark:text-white">
                            {node.name}
                          </h3>
                          {node.region_tag && (
                            <span className="shrink-0 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                              {node.region_tag}
                            </span>
                          )}
                        </div>
                        <div className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                          <Clock className="h-3 w-3 shrink-0" />
                          <span>运行时长：{formatUptime(node.uptime_seconds)}</span>
                          <span>·</span>
                          <span>每月 {node.billing_reset_day} 日重置</span>
                        </div>
                      </div>
                      <NodeStatusBadge status={node.status} />
                    </div>

                    {node.status === 'traffic_paused' && (
                      <div className="rounded-lg border border-amber-200 bg-amber-50/80 px-2.5 py-1.5 text-[11px] text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-200">
                        <span className="font-medium">将于每月 {node.billing_reset_day} 日自动恢复</span>
                        {node.paused_reason && (
                          <span className="opacity-90"> · {formatPausedReason(node.paused_reason)}</span>
                        )}
                      </div>
                    )}

                    {/* CPU & Memory */}
                    <div className="grid grid-cols-2 gap-2">
                      <div className="rounded-lg bg-slate-50 px-2.5 py-1.5 dark:bg-slate-800/60">
                        <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
                          <span className="flex items-center gap-1">
                            <Cpu className="h-3 w-3" /> CPU
                          </span>
                          <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                            {node.cpu_percent.toFixed(1)}%
                          </span>
                        </div>
                        <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
                          <div
                            className="h-full rounded-full bg-sky-500 transition-all"
                            style={{ width: `${Math.min(100, Math.max(0, node.cpu_percent))}%` }}
                          />
                        </div>
                      </div>

                      <div className="rounded-lg bg-slate-50 px-2.5 py-1.5 dark:bg-slate-800/60">
                        <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
                          <span className="flex items-center gap-1">
                            <MemoryStick className="h-3 w-3" /> 内存
                          </span>
                          <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                            {memPct.toFixed(0)}%
                          </span>
                        </div>
                        <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
                          <div
                            className="h-full rounded-full bg-violet-500 transition-all"
                            style={{ width: `${memPct}%` }}
                          />
                        </div>
                        <p className="mt-0.5 truncate text-[10px] leading-tight font-mono text-slate-500 dark:text-slate-400">
                          {formatBytes(node.mem_used_bytes)} / {formatBytes(node.mem_total_bytes)}
                        </p>
                      </div>
                    </div>

                    {/* Unified Compact Speed + Cumulative Traffic */}
                    <div className="space-y-1 rounded-lg bg-slate-50 px-2.5 py-1.5 text-[11px] dark:bg-slate-800/50">
                      <div className="flex items-center justify-between gap-2">
                        <span className="shrink-0 text-slate-500 dark:text-slate-400">实时</span>
                        <div className="flex min-w-0 items-center gap-2 font-mono">
                          <span className="inline-flex items-center gap-0.5 text-emerald-600 dark:text-emerald-400">
                            <ArrowDown className="h-3 w-3 shrink-0" />
                            {formatSpeed(node.rx_bps)}
                          </span>
                          <span className="text-slate-300 dark:text-slate-600">/</span>
                          <span className="inline-flex items-center gap-0.5 text-indigo-600 dark:text-indigo-400">
                            <ArrowUp className="h-3 w-3 shrink-0" />
                            {formatSpeed(node.tx_bps)}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center justify-between gap-2">
                        <span className="shrink-0 text-slate-500 dark:text-slate-400">累计</span>
                        {nodePctOnly ? (
                          <span className="text-slate-400">仅百分比模式</span>
                        ) : (
                          <div className="flex min-w-0 items-center gap-2 font-mono text-slate-700 dark:text-slate-200">
                            <span>↓ {formatBytes(node.total_rx_bytes)}</span>
                            <span className="text-slate-300 dark:text-slate-600">/</span>
                            <span>↑ {formatBytes(node.total_tx_bytes)}</span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Cycle Traffic */}
                    <TrafficBar node={node} globalPercentageOnly={pctOnly} compact />
                  </div>

                  {/* Core Health */}
                  <div className="mt-2.5 flex flex-wrap items-center justify-between gap-1.5 border-t border-slate-100 pt-2 dark:border-slate-800">
                    <span className="text-[11px] font-medium text-slate-400 dark:text-slate-500">
                      代理核心
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      <HealthPill label="Snell + ShadowTLS" healthy={node.core_a_healthy} />
                      <HealthPill label="sing-box" healthy={node.core_b_healthy} />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
                <thead className="bg-slate-50 text-left text-xs font-semibold text-slate-500 dark:bg-slate-800/50 dark:text-slate-400">
                  <tr>
                    <th className="px-4 py-3">节点</th>
                    <th className="px-4 py-3">状态</th>
                    <th className="px-4 py-3">CPU / 内存</th>
                    <th className="px-4 py-3">实时带宽</th>
                    <th className="px-4 py-3">周期流量</th>
                    <th className="px-4 py-3">累计已下载 / 已上传</th>
                    <th className="px-4 py-3">代理核心</th>
                    <th className="px-4 py-3">运行时长</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {nodes.map((node) => {
                    const nodePctOnly = pctOnly || node.percentage_only;
                    return (
                      <tr key={node.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                        <td className="px-4 py-3 font-medium">
                          <div className="flex items-center gap-2">
                            <span>{node.name}</span>
                            {node.region_tag && (
                              <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-semibold uppercase text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                                {node.region_tag}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <NodeStatusBadge status={node.status} />
                          {node.status === 'traffic_paused' && (
                            <div className="mt-1 text-[11px] text-amber-600 dark:text-amber-400">
                              每月 {node.billing_reset_day} 日重置
                              {node.paused_reason ? ` · ${formatPausedReason(node.paused_reason)}` : ''}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3 font-mono text-xs">
                          <div>CPU: {node.cpu_percent.toFixed(1)}%</div>
                          <div className="text-slate-500 dark:text-slate-400">
                            {formatBytes(node.mem_used_bytes)} / {formatBytes(node.mem_total_bytes)}
                          </div>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs">
                          <div className="text-emerald-600 dark:text-emerald-400">
                            ↓ {formatSpeed(node.rx_bps)}
                          </div>
                          <div className="text-indigo-600 dark:text-indigo-400">
                            ↑ {formatSpeed(node.tx_bps)}
                          </div>
                        </td>
                        <td className="min-w-[200px] px-4 py-3">
                          <TrafficBar node={node} globalPercentageOnly={pctOnly} />
                        </td>
                        <td className="px-4 py-3 font-mono text-xs">
                          {nodePctOnly ? (
                            <span className="text-slate-400">仅百分比模式</span>
                          ) : (
                            <>
                              <div className="text-emerald-600 dark:text-emerald-400">
                                ↓ {formatBytes(node.total_rx_bytes)}
                              </div>
                              <div className="text-indigo-600 dark:text-indigo-400">
                                ↑ {formatBytes(node.total_tx_bytes)}
                              </div>
                            </>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-col gap-1">
                            <HealthPill label="Snell + ShadowTLS" healthy={node.core_a_healthy} />
                            <HealthPill label="sing-box" healthy={node.core_b_healthy} />
                          </div>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-600 dark:text-slate-300">
                          {formatUptime(node.uptime_seconds)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
