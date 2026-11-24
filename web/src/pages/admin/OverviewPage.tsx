import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Bell,
  RefreshCw,
  Server,
  Users,
} from 'lucide-react';
import { api, ApiError } from '../../api/client';
import type { NodeDTO, UserDTO, WebhookChannel } from '../../types/api';
import { NodeStatusBadge, HealthPill } from '../../components/Badge';
import { formatBytes, formatSpeed } from '../../utils/format';

export function OverviewPage() {
  const [nodes, setNodes] = useState<NodeDTO[]>([]);
  const [users, setUsers] = useState<UserDTO[]>([]);
  const [webhooks, setWebhooks] = useState<WebhookChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [n, u, w] = await Promise.all([
        api.listNodes(),
        api.listUsers(),
        api.listWebhooks(),
      ]);
      setNodes(n);
      setUsers(u);
      setWebhooks(w);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '加载概览失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const onlineCount = nodes.filter((n) => n.status === 'online').length;
  const pausedCount = nodes.filter((n) => n.status === 'traffic_paused').length;
  const offlineCount = nodes.filter((n) => n.status === 'offline').length;
  const activeUsers = users.filter((u) => u.enabled).length;
  const rxTotal = nodes.reduce((s, n) => s + (n.rx_bps || 0), 0);
  const txTotal = nodes.reduce((s, n) => s + (n.tx_bps || 0), 0);
  const enabledHooks = webhooks.filter((w) => w.enabled).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white">系统概览</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            实时查看集群节点、用户流量与告警通知运行状态
          </p>
        </div>
        <button type="button" onClick={() => void load()} className="btn-secondary" disabled={loading}>
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          刷新
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/50 dark:text-rose-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <div className="card p-3.5 sm:p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-slate-400">节点在线数</span>
            <Server className="h-4 w-4 shrink-0 text-indigo-500" />
          </div>
          <p className="mt-2 text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
            {onlineCount} <span className="text-xs sm:text-sm font-normal text-slate-500">/ {nodes.length} 在线</span>
          </p>
          <p className="mt-1 text-[11px] sm:text-xs text-slate-500 dark:text-slate-400">
            {pausedCount} 暂停 · {offlineCount} 离线
          </p>
        </div>

        <div className="card p-3.5 sm:p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-slate-400">用户数</span>
            <Users className="h-4 w-4 shrink-0 text-emerald-500" />
          </div>
          <p className="mt-2 text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
            {activeUsers} <span className="text-xs sm:text-sm font-normal text-slate-500">/ {users.length} 启用</span>
          </p>
          <p className="mt-1 text-[11px] sm:text-xs text-slate-500 dark:text-slate-400">
            累计已用：{' '}
            {formatBytes(users.reduce((s, u) => s + u.used_up_bytes + u.used_down_bytes, 0))}
          </p>
        </div>

        <div className="card p-3.5 sm:p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-slate-400">实时总带宽</span>
            <Activity className="h-4 w-4 shrink-0 text-sky-500" />
          </div>
          <div className="mt-2 space-y-0.5 font-mono text-xs sm:text-sm font-semibold">
            <div className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
              <ArrowDown className="h-3.5 w-3.5 shrink-0" /> {formatSpeed(rxTotal)}
            </div>
            <div className="flex items-center gap-1.5 text-indigo-600 dark:text-indigo-400">
              <ArrowUp className="h-3.5 w-3.5 shrink-0" /> {formatSpeed(txTotal)}
            </div>
          </div>
        </div>

        <div className="card p-3.5 sm:p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500 dark:text-slate-400">告警通知通道</span>
            <Bell className="h-4 w-4 shrink-0 text-amber-500" />
          </div>
          <p className="mt-2 text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
            {enabledHooks} <span className="text-xs sm:text-sm font-normal text-slate-500">/ {webhooks.length} 启用</span>
          </p>
          <Link
            to="/admin/settings?tab=webhooks"
            className="mt-1 inline-flex items-center gap-1 text-[11px] sm:text-xs font-medium text-indigo-600 hover:underline dark:text-indigo-400"
          >
            管理告警通道 <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      </div>

      {pausedCount > 0 && (
        <div className="flex items-center gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-200">
          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
          <span>
            当前有 {pausedCount} 个节点因达到流量阈值而自动暂停，请前往{' '}
            <Link to="/admin/nodes" className="font-semibold underline">
              节点管理
            </Link>{' '}
            处理。
          </span>
        </div>
      )}

      <div className="card overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3 sm:px-5 sm:py-3.5 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">节点状态快照</h2>
          <Link to="/admin/nodes" className="text-xs font-medium text-indigo-600 hover:underline dark:text-indigo-400">
            前往节点管理 →
          </Link>
        </div>

        {/* Mobile Snapshot Cards */}
        <div className="divide-y divide-slate-100 md:hidden dark:divide-slate-800">
          {nodes.length === 0 ? (
            <div className="px-4 py-8 text-center text-xs text-slate-500">
              暂未添加任何节点。
            </div>
          ) : (
            nodes.map((n) => {
              const isSynced = n.config_revision > 0 && n.reported_config_revision === n.config_revision;
              return (
                <div key={n.id} className="space-y-2.5 p-4 text-xs">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-2 font-medium text-slate-900 dark:text-white">
                      <span className="truncate text-sm font-semibold">{n.name}</span>
                      {n.region_tag && (
                        <span className="shrink-0 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] uppercase text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                          {n.region_tag}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5">
                      <NodeStatusBadge status={n.status} />
                      {isSynced ? (
                        <span className="inline-flex whitespace-nowrap items-center rounded-full bg-emerald-100 px-2 py-0.5 text-[11px] font-medium text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300">
                          已同步
                        </span>
                      ) : (
                        <Link
                          to={`/admin/nodes?syncNodeId=${n.id}`}
                          className="inline-flex whitespace-nowrap items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-medium text-amber-800 dark:bg-amber-950/70 dark:text-amber-300"
                        >
                          去同步 →
                        </Link>
                      )}
                    </div>
                  </div>
                  <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                    <div>
                      {n.public_ip || '—'} {n.agent_arch ? `(${n.agent_arch})` : ''}
                    </div>
                    {n.public_ipv6 && <div className="mt-0.5 break-all">IPv6: {n.public_ipv6}</div>}
                  </div>
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5">
                    <div className="flex flex-wrap gap-1.5">
                      <HealthPill label="Snell + ShadowTLS" healthy={n.core_a_healthy} />
                      <HealthPill label="sing-box" healthy={n.core_b_healthy} />
                    </div>
                    <div className="font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      ↓ {formatBytes(n.cycle_rx_bytes)} / ↑ {formatBytes(n.cycle_tx_bytes)}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Desktop Snapshot Table */}
        <div className="hidden overflow-x-auto md:block">
          <table className="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
            <thead className="bg-slate-50 text-left text-xs font-semibold text-slate-500 dark:bg-slate-800/50 dark:text-slate-400">
              <tr>
                <th className="px-4 py-3">节点名称</th>
                <th className="px-4 py-3">IP / 架构</th>
                <th className="px-4 py-3">状态</th>
                <th className="px-4 py-3">代理核心</th>
                <th className="px-4 py-3">周期入站 / 出站</th>
                <th className="px-4 py-3">配置同步</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {nodes.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-xs text-slate-500">
                    暂未添加任何节点。
                  </td>
                </tr>
              ) : (
                nodes.map((n) => {
                  const isSynced = n.config_revision > 0 && n.reported_config_revision === n.config_revision;
                  return (
                    <tr key={n.id}>
                      <td className="px-4 py-3 font-medium whitespace-nowrap">
                        {n.name}
                        {n.region_tag && (
                          <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] uppercase text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                            {n.region_tag}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-500 dark:text-slate-400">
                        <div>
                          {n.public_ip || '—'} {n.agent_arch ? `(${n.agent_arch})` : ''}
                        </div>
                        {n.public_ipv6 && (
                          <div className="mt-0.5 break-all text-[11px] text-slate-400 dark:text-slate-500">
                            IPv6: {n.public_ipv6}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <NodeStatusBadge status={n.status} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1.5">
                          <HealthPill label="Snell + ShadowTLS" healthy={n.core_a_healthy} />
                          <HealthPill label="sing-box" healthy={n.core_b_healthy} />
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">
                        ↓ {formatBytes(n.cycle_rx_bytes)} / ↑ {formatBytes(n.cycle_tx_bytes)}
                      </td>
                      <td className="px-4 py-3 text-xs">
                        {isSynced ? (
                          <span className="inline-flex whitespace-nowrap items-center rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300">
                            已同步
                          </span>
                        ) : (
                          <Link
                            to={`/admin/nodes?syncNodeId=${n.id}`}
                            className="inline-flex whitespace-nowrap items-center gap-1 rounded-full bg-amber-100 px-2.5 py-0.5 text-xs font-medium text-amber-800 hover:bg-amber-200 dark:bg-amber-950/70 dark:text-amber-300 dark:hover:bg-amber-900/70"
                          >
                            待同步 · 去同步 →
                          </Link>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
