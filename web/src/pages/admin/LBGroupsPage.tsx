import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  CheckCircle2,
  Edit3,
  GitFork,
  History,
  Lock,
  LockOpen,
  Plus,
  RefreshCw,
  Settings,
  Sparkles,
  Trash2,
  Zap,
} from 'lucide-react';
import { api, ApiError } from '../../api/client';
import type {
  HuaweiCloudZone,
  LBGroupDTO,
  LBGroupUpsertRequest,
  LBStrategy,
  LBSwitchLog,
  NodeDTO,
  SnellObfs,
  SnellVersion,
  SSCipher,
} from '../../types/api';
import { useToast } from '../../contexts/ToastContext';
import { Modal } from '../../components/Modal';
import { CopyButton } from '../../components/CopyButton';
import { HealthPill, NodeStatusBadge } from '../../components/Badge';
import { ByteSizeInput } from '../../components/ByteSizeInput';
import { NumericInput } from '../../components/NumericInput';
import {
  formatBytes,
  formatDateTime,
  randomAlnum,
  randomBase64,
} from '../../utils/format';

const STRATEGY_LABELS: Record<LBStrategy, string> = {
  remaining_balance: '动态均衡（按剩余流量）',
  failover: '主备阶梯切换',
  weighted_multi: '多 IP 动态权重',
};

const LOG_EVENT_LABELS: Record<string, string> = {
  balance_switch: '均衡切换',
  failover: '故障转移',
  weight_update: '权重调整',
  manual_pin: '手动锁定',
  exhausted: '全部不可用',
  recovered: '恢复可用',
  sync_error: '同步失败',
};

const GIB = 1024 * 1024 * 1024;

function makeDefaultGroupForm(sortOrder = 0): LBGroupUpsertRequest {
  return {
    name: '',
    region_tag: '',
    enabled: true,
    sort_order: sortOrder,
    dns_zone_id: '',
    dns_zone_name: '',
    dns_domain: '',
    dns_ttl: 60,
    strategy: 'remaining_balance',
    switch_diff_bytes: 10 * GIB,
    switch_cooldown_minutes: 10,
    failover_threshold_percent: 90,
    snell_config: {
      enabled: true,
      version: 'v5',
      public_port: 18443,
      inner_port: 0,
      psk: randomAlnum(24),
      obfs: 'off',
      tfo: true,
      dns_ip_preference: '',
      stls_password: randomAlnum(20),
      stls_sni: 'gateway.icloud.com',
    },
    ss_config: {
      enabled: true,
      tcp_port: 28443,
      udp_port: 28444,
      cipher: '2022-blake3-aes-128-gcm',
      ipsk: randomBase64(16),
      stls_sni: 'swdist.apple.com',
      tfo: true,
    },
    member_node_ids: [],
  };
}

function groupToForm(g: LBGroupDTO): LBGroupUpsertRequest {
  return {
    name: g.name,
    region_tag: g.region_tag,
    enabled: g.enabled,
    sort_order: g.sort_order,
    dns_zone_id: g.dns_zone_id,
    dns_zone_name: g.dns_zone_name,
    dns_domain: g.dns_domain,
    dns_ttl: g.dns_ttl || 60,
    strategy: g.strategy,
    switch_diff_bytes: g.switch_diff_bytes,
    switch_cooldown_minutes: g.switch_cooldown_minutes,
    failover_threshold_percent: g.failover_threshold_percent || 90,
    snell_config: {
      enabled: g.snell_config.enabled,
      version: g.snell_config.version || 'v5',
      public_port: g.snell_config.public_port || 0,
      inner_port: 0,
      psk: g.snell_config.psk || '',
      obfs: g.snell_config.obfs || 'off',
      tfo: Boolean(g.snell_config.tfo),
      dns_ip_preference: '',
      stls_password: g.snell_config.stls_password || '',
      stls_sni: g.snell_config.stls_sni || '',
    },
    ss_config: {
      enabled: g.ss_config.enabled,
      tcp_port: g.ss_config.tcp_port || 0,
      udp_port: g.ss_config.udp_port || 0,
      cipher: g.ss_config.cipher || '2022-blake3-aes-128-gcm',
      ipsk: g.ss_config.ipsk || '',
      stls_sni: g.ss_config.stls_sni || '',
      tfo: Boolean(g.ss_config.tfo),
    },
    member_node_ids: [...(g.member_node_ids || [])],
  };
}

export function LBGroupsPage() {
  const toast = useToast();
  const [groups, setGroups] = useState<LBGroupDTO[]>([]);
  const [nodes, setNodes] = useState<NodeDTO[]>([]);
  const [zones, setZones] = useState<HuaweiCloudZone[]>([]);
  const [zonesError, setZonesError] = useState('');
  const [zonesLoading, setZonesLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const [syncingId, setSyncingId] = useState<number | null>(null);
  const [pinBusyKey, setPinBusyKey] = useState<string>('');

  // Create / Edit Modal
  const [editOpen, setEditOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'basic' | 'members' | 'snell' | 'ss'>('basic');
  const [form, setForm] = useState<LBGroupUpsertRequest>(() => makeDefaultGroupForm(0));
  const [subdomainPrefix, setSubdomainPrefix] = useState('');
  const [templateNodeId, setTemplateNodeId] = useState('');
  const [saving, setSaving] = useState(false);

  // Logs Modal
  const [logsGroup, setLogsGroup] = useState<LBGroupDTO | null>(null);
  const [logs, setLogs] = useState<LBSwitchLog[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);

  const loadZones = useCallback(async () => {
    setZonesLoading(true);
    setZonesError('');
    try {
      const z = await api.listHuaweiCloudZones();
      setZones(z);
    } catch (err) {
      setZones([]);
      setZonesError(err instanceof ApiError ? err.message : '无法拉取华为云 Zone 列表');
    } finally {
      setZonesLoading(false);
    }
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [gList, nList] = await Promise.all([api.listLBGroups(), api.listNodes()]);
      setGroups(gList);
      setNodes(nList);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载负载均衡分组失败');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
    void loadZones();
  }, [load, loadZones]);

  const nodeMap = useMemo(() => {
    const m = new Map<number, NodeDTO>();
    nodes.forEach((n) => m.set(n.id, n));
    return m;
  }, [nodes]);

  const openCreate = () => {
    setEditingId(null);
    setActiveTab('basic');
    const nextOrder = groups.length > 0 ? Math.max(...groups.map((g) => g.sort_order)) + 1 : 0;
    const def = makeDefaultGroupForm(nextOrder);
    if (zones.length > 0) {
      def.dns_zone_id = zones[0].id;
      def.dns_zone_name = zones[0].name;
    }
    setForm(def);
    setSubdomainPrefix('');
    setTemplateNodeId('');
    setEditOpen(true);
  };

  const openEdit = (g: LBGroupDTO) => {
    setEditingId(g.id);
    setActiveTab('basic');
    const f = groupToForm(g);
    setForm(f);
    if (f.dns_zone_name && f.dns_domain.endsWith('.' + f.dns_zone_name)) {
      setSubdomainPrefix(f.dns_domain.slice(0, f.dns_domain.length - f.dns_zone_name.length - 1));
    } else if (f.dns_zone_name && f.dns_domain === f.dns_zone_name) {
      setSubdomainPrefix('@');
    } else {
      setSubdomainPrefix('');
    }
    setTemplateNodeId('');
    setEditOpen(true);
  };

  const handleZoneChange = (zoneId: string) => {
    const z = zones.find((item) => item.id === zoneId);
    const zoneName = z ? z.name : '';
    let nextDomain = form.dns_domain;
    if (zoneName && subdomainPrefix.trim()) {
      const sub = subdomainPrefix.trim().replace(/\.+$/, '');
      nextDomain = sub === '@' ? zoneName : `${sub}.${zoneName}`;
    }
    setForm({
      ...form,
      dns_zone_id: zoneId,
      dns_zone_name: zoneName,
      dns_domain: nextDomain,
    });
  };

  const handleSubdomainChange = (rawSub: string) => {
    setSubdomainPrefix(rawSub);
    const sub = rawSub.trim().replace(/\.+$/, '').toLowerCase();
    if (form.dns_zone_name) {
      const nextDomain =
        sub === '' || sub === '@' ? form.dns_zone_name : `${sub}.${form.dns_zone_name}`;
      setForm({ ...form, dns_domain: nextDomain });
    }
  };

  const handleImportFromNode = () => {
    const id = Number(templateNodeId);
    const n = nodeMap.get(id);
    if (!n) return;
    setForm((prev) => ({
      ...prev,
      snell_config: {
        enabled: n.snell_config.enabled,
        version: n.snell_config.version || 'v5',
        public_port: n.snell_config.public_port || 18443,
        inner_port: 0,
        psk: n.snell_config.psk || '',
        obfs: n.snell_config.obfs || 'off',
        tfo: Boolean(n.snell_config.tfo),
        dns_ip_preference: '',
        stls_password: n.snell_config.stls_password || '',
        stls_sni: n.snell_config.stls_sni || '',
      },
      ss_config: {
        enabled: n.ss_config.enabled,
        tcp_port: n.ss_config.tcp_port || 28443,
        udp_port: n.ss_config.udp_port || 28444,
        cipher: n.ss_config.cipher || '2022-blake3-aes-128-gcm',
        ipsk: n.ss_config.ipsk || '',
        stls_sni: n.ss_config.stls_sni || '',
        tfo: Boolean(n.ss_config.tfo),
      },
    }));
    toast.success(`已从节点 "${n.name}" 导入协议配置`);
  };

  const toggleMember = (nodeId: number) => {
    setForm((prev) => {
      const exists = prev.member_node_ids.includes(nodeId);
      const next = exists
        ? prev.member_node_ids.filter((id) => id !== nodeId)
        : [...prev.member_node_ids, nodeId];
      return { ...prev, member_node_ids: next };
    });
  };

  const moveMember = (index: number, delta: -1 | 1) => {
    const target = index + delta;
    if (target < 0 || target >= form.member_node_ids.length) return;
    setForm((prev) => {
      const next = [...prev.member_node_ids];
      [next[index], next[target]] = [next[target], next[index]];
      return { ...prev, member_node_ids: next };
    });
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      toast.error('请填写分组名称');
      setActiveTab('basic');
      return;
    }
    if (!form.dns_domain.trim()) {
      toast.error('请填写分组绑定的完整域名');
      setActiveTab('basic');
      return;
    }
    setSaving(true);
    try {
      const payload: LBGroupUpsertRequest = {
        ...form,
        name: form.name.trim(),
        region_tag: form.region_tag.trim(),
        dns_domain: form.dns_domain.trim().toLowerCase(),
      };
      if (editingId === null) {
        await api.createLBGroup(payload);
        toast.success(`已创建负载均衡分组 "${payload.name}"`);
      } else {
        await api.updateLBGroup(editingId, payload);
        toast.success(`已更新负载均衡分组 "${payload.name}"`);
      }
      setEditOpen(false);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '保存负载均衡分组失败');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (g: LBGroupDTO) => {
    if (!window.confirm(`确定删除负载均衡分组 "${g.name}" 吗？组内节点不会被删除，将恢复为独立节点。`)) {
      return;
    }
    try {
      await api.deleteLBGroup(g.id);
      toast.success(`已删除分组 "${g.name}"`);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '删除分组失败');
    }
  };

  const handleSync = async (g: LBGroupDTO) => {
    setSyncingId(g.id);
    try {
      const updated = await api.syncLBGroup(g.id);
      setGroups((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
      toast.success(`分组 "${g.name}" DNS 已同步`);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'DNS 同步失败');
      await load();
    } finally {
      setSyncingId(null);
    }
  };

  const handlePin = async (g: LBGroupDTO, nodeId: number | null) => {
    const key = `${g.id}:${nodeId ?? 'unpin'}`;
    setPinBusyKey(key);
    try {
      const updated = await api.pinLBGroup(g.id, nodeId);
      setGroups((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
      if (updated.last_sync_error) {
        toast.error(`锁定已保存，但 DNS 同步失败：${updated.last_sync_error}`);
      } else if (nodeId === null) {
        toast.success(`分组 "${g.name}" 已恢复自动负载均衡`);
      } else {
        toast.success(`已锁定 "${g.name}" 解析到指定节点`);
      }
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '操作失败');
    } finally {
      setPinBusyKey('');
    }
  };

  const openLogs = async (g: LBGroupDTO) => {
    setLogsGroup(g);
    setLogs([]);
    setLogsLoading(true);
    try {
      const items = await api.listLBGroupLogs(g.id, 50);
      setLogs(items);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载切换日志失败');
    } finally {
      setLogsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="admin-sticky-header flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white">负载均衡分组</h1>
          <p className="hidden text-sm text-slate-500 dark:text-slate-400 sm:block">
            将多台节点合并为单一域名入口，基于华为云国际版 DNS 按剩余流量均衡与自动故障转移
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link to="/admin/settings?tab=cloud-dns" className="btn-secondary text-xs">
            <Settings className="h-3.5 w-3.5" />
            华为云 DNS 凭据
          </Link>
          <button type="button" onClick={() => void load()} className="btn-secondary" disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            刷新
          </button>
          <button type="button" onClick={openCreate} className="btn-primary">
            <Plus className="h-4 w-4" />
            新建分组
          </button>
        </div>
      </div>

      {zonesError && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-xs text-amber-950 dark:border-amber-800/70 dark:bg-amber-950/40 dark:text-amber-100">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
            <span>华为云 DNS 尚未就绪（{zonesError}），请先在系统设置中配置 AK/SK 并测试拉取域名。</span>
          </div>
          <Link to="/admin/settings?tab=cloud-dns" className="btn-secondary px-3 py-1 text-xs">
            前往配置
          </Link>
        </div>
      )}

      {groups.length === 0 && !loading ? (
        <div className="card flex flex-col items-center justify-center py-16 text-center">
          <GitFork className="h-10 w-10 text-slate-300 dark:text-slate-600" />
          <p className="mt-3 text-sm font-medium text-slate-700 dark:text-slate-300">
            暂无负载均衡分组
          </p>
          <p className="mt-1 max-w-md text-xs text-slate-500 dark:text-slate-400">
            可将两台或多台同配置节点加入同一分组，对外订阅自动合并为单一域名出口，并根据各节点剩余流量自动切换华为云 DNS 解析。
          </p>
          <button type="button" onClick={openCreate} className="btn-primary mt-4">
            <Plus className="h-4 w-4" />
            创建第一个分组
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {groups.map((g) => (
            <div key={g.id} className="card space-y-4 p-4 sm:p-5">
              {/* Header */}
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-slate-400">#{g.id}</span>
                    <h3 className="text-base font-semibold text-slate-900 dark:text-white">
                      {g.name}
                    </h3>
                    {g.region_tag && (
                      <span className="rounded bg-slate-100 px-2 py-0.5 text-[11px] font-semibold uppercase text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                        {g.region_tag}
                      </span>
                    )}
                    <span
                      className={`rounded-full px-2.5 py-0.5 text-[11px] font-medium ${
                        g.enabled
                          ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300'
                          : 'bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
                      }`}
                    >
                      {g.enabled ? '已启用' : '已禁用'}
                    </span>
                    <span className="rounded-full bg-indigo-50 px-2.5 py-0.5 text-[11px] font-medium text-indigo-700 dark:bg-indigo-950/60 dark:text-indigo-300">
                      {STRATEGY_LABELS[g.strategy]}
                    </span>
                    {g.pinned_node_id && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2.5 py-0.5 text-[11px] font-medium text-amber-800 dark:bg-amber-950/60 dark:text-amber-300">
                        <Lock className="h-3 w-3" />
                        已手动锁定
                      </span>
                    )}
                    {g.is_exhausted && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-rose-100 px-2.5 py-0.5 text-[11px] font-medium text-rose-700 dark:bg-rose-950/60 dark:text-rose-300">
                        <AlertTriangle className="h-3 w-3" />
                        全组不可用
                      </span>
                    )}
                  </div>

                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-300">
                    <span className="text-slate-500">统一出口域名:</span>
                    <code className="rounded bg-slate-100 px-2 py-0.5 font-mono font-semibold text-slate-900 dark:bg-slate-800 dark:text-slate-100">
                      {g.dns_domain}
                    </code>
                    <CopyButton text={g.dns_domain} label="复制" />
                    <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                      TTL {g.dns_ttl}s
                    </span>
                    {g.snell_config.enabled && (
                      <span className="font-mono text-[11px] text-slate-500">
                        Snell :{g.snell_config.public_port}
                      </span>
                    )}
                    {g.ss_config.enabled && (
                      <span className="font-mono text-[11px] text-slate-500">
                        SS2022 :{g.ss_config.tcp_port}
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-1.5">
                  {g.pinned_node_id && (
                    <button
                      type="button"
                      disabled={pinBusyKey === `${g.id}:unpin`}
                      onClick={() => void handlePin(g, null)}
                      className="btn-secondary px-2.5 py-1 text-xs"
                    >
                      <LockOpen className="h-3.5 w-3.5" />
                      解除锁定
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={syncingId === g.id}
                    onClick={() => void handleSync(g)}
                    className="btn-primary px-2.5 py-1 text-xs"
                  >
                    <Zap className="h-3.5 w-3.5" />
                    {syncingId === g.id ? '同步中...' : '立即同步 DNS'}
                  </button>
                  <button
                    type="button"
                    onClick={() => void openLogs(g)}
                    className="btn-secondary px-2.5 py-1 text-xs"
                  >
                    <History className="h-3.5 w-3.5" />
                    切换日志
                  </button>
                  <button
                    type="button"
                    onClick={() => openEdit(g)}
                    className="btn-secondary px-2.5 py-1 text-xs"
                  >
                    <Edit3 className="h-3.5 w-3.5" />
                    编辑
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleDelete(g)}
                    className="btn-danger px-2.5 py-1 text-xs"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    删除
                  </button>
                </div>
              </div>

              {/* Active DNS Status Banner */}
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-slate-50 px-3.5 py-2.5 text-xs dark:bg-slate-800/50">
                <div className="flex flex-wrap items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                  <span className="font-medium text-slate-700 dark:text-slate-200">当前 DNS 解析:</span>
                  {g.active_records.length === 0 ? (
                    <span className="text-slate-400">尚未同步</span>
                  ) : (
                    g.active_records.map((rec) => (
                      <span
                        key={`${rec.node_id}-${rec.ip}`}
                        className="inline-flex items-center gap-1 rounded-md bg-white px-2 py-0.5 font-mono text-[11px] text-slate-700 ring-1 ring-slate-200 dark:bg-slate-900 dark:text-slate-200 dark:ring-slate-700"
                      >
                        <span className="font-sans font-medium">{rec.node_name || `#${rec.node_id}`}</span>
                        <span>{rec.ip}</span>
                        {rec.weight ? <span className="text-indigo-600 dark:text-indigo-400">w={rec.weight}</span> : null}
                      </span>
                    ))
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
                  <span>上次切换: {g.last_switch_at ? formatDateTime(g.last_switch_at) : '—'}</span>
                  <span>上次同步: {g.last_sync_at ? formatDateTime(g.last_sync_at) : '—'}</span>
                </div>
              </div>

              {g.last_sync_error && (
                <div className="flex items-center gap-2 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/40 dark:text-rose-300">
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  <span>最近同步异常: {g.last_sync_error}</span>
                </div>
              )}

              {/* Members Table */}
              <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
                {g.members.length === 0 ? (
                  <div className="col-span-full rounded-lg border border-dashed border-slate-200 py-4 text-center text-xs text-slate-400 dark:border-slate-700">
                    尚未向该分组添加成员节点
                  </div>
                ) : (
                  g.members.map((m) => {
                    const isActive = g.active_records.some((r) => r.node_id === m.node_id);
                    const isPinned = g.pinned_node_id === m.node_id;
                    const pct =
                      m.budget_bytes > 0
                        ? Math.min(100, (m.counted_bytes / m.budget_bytes) * 100)
                        : 0;
                    return (
                      <div
                        key={m.node_id}
                        className={`rounded-xl border p-3 ${
                          isActive
                            ? 'border-indigo-300 bg-indigo-50/40 dark:border-indigo-700/70 dark:bg-indigo-950/20'
                            : 'border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900/40'
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono text-[11px] text-slate-400">#{m.priority + 1}</span>
                            <span className="font-semibold text-sm text-slate-900 dark:text-white">
                              {m.node_name}
                            </span>
                            <NodeStatusBadge status={m.status} />
                            {!m.enabled && (
                              <span className="rounded bg-slate-200 px-1.5 py-0.5 text-[10px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                                已禁用
                              </span>
                            )}
                            {isActive && (
                              <span className="rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300">
                                当前生效
                              </span>
                            )}
                            {isPinned && (
                              <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold text-amber-800 dark:bg-amber-950/60 dark:text-amber-300">
                                已锁定
                              </span>
                            )}
                          </div>
                          <button
                            type="button"
                            disabled={pinBusyKey === `${g.id}:${isPinned ? 'unpin' : m.node_id}`}
                            onClick={() => void handlePin(g, isPinned ? null : m.node_id)}
                            className="btn-secondary px-2 py-0.5 text-[11px]"
                          >
                            {isPinned ? (
                              <>
                                <LockOpen className="h-3 w-3" /> 解锁
                              </>
                            ) : (
                              <>
                                <Lock className="h-3 w-3" /> 锁定至此
                              </>
                            )}
                          </button>
                        </div>

                        <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                          <span className="font-mono">{m.public_ip || '无公网 IPv4'}</span>
                          {g.snell_config.enabled && <HealthPill label="Snell" healthy={m.core_a_healthy} />}
                          {g.ss_config.enabled && <HealthPill label="SS2022" healthy={m.core_b_healthy} />}
                        </div>

                        <div className="mt-2 space-y-1 text-[11px]">
                          <div className="flex justify-between font-mono text-slate-600 dark:text-slate-300">
                            <span>
                              已用 {formatBytes(m.counted_bytes)} /{' '}
                              {m.budget_bytes > 0 ? formatBytes(m.budget_bytes) : '不限'}
                            </span>
                            <span className="font-semibold text-indigo-600 dark:text-indigo-400">
                              剩余 {m.remaining_bytes < 0 ? '不限' : formatBytes(m.remaining_bytes)}
                            </span>
                          </div>
                          {m.budget_bytes > 0 && (
                            <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
                              <div
                                className={`h-full rounded-full ${
                                  pct >= 90 ? 'bg-rose-500' : pct >= 70 ? 'bg-amber-500' : 'bg-indigo-500'
                                }`}
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create / Edit Group Modal */}
      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title={editingId === null ? '新建负载均衡分组' : `编辑负载均衡分组 #${editingId}`}
        subtitle="保存后会自动统一覆写组内所有节点的协议参数，并同步已授权用户。"
        maxWidthClass="max-w-3xl"
        footer={
          <>
            <button type="button" onClick={() => setEditOpen(false)} className="btn-secondary">
              取消
            </button>
            <button type="submit" form="lb-group-form" disabled={saving} className="btn-primary">
              {saving ? '保存中...' : editingId === null ? '创建分组' : '保存更改'}
            </button>
          </>
        }
      >
        <div className="mb-5 flex flex-wrap gap-1 border-b border-slate-200 pb-3 dark:border-slate-800">
          {(
            [
              ['basic', '基础与域名'],
              ['members', '成员与均衡策略'],
              ['snell', 'Snell + ShadowTLS'],
              ['ss', 'sing-box (SS2022)'],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setActiveTab(key)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                activeTab === key
                  ? 'bg-indigo-600 text-white dark:bg-indigo-500'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        <form id="lb-group-form" onSubmit={handleSave} className="space-y-4">
          {activeTab === 'basic' && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium">分组名称（订阅显示名）*</label>
                <input
                  type="text"
                  className="input-field"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="例如：阿里云双线-香港"
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">地区标签</label>
                <input
                  type="text"
                  className="input-field"
                  value={form.region_tag}
                  onChange={(e) => setForm({ ...form, region_tag: e.target.value })}
                  placeholder="例如：HK"
                />
              </div>
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <label className="text-xs font-medium">华为云公网 Zone</label>
                  <button
                    type="button"
                    onClick={() => void loadZones()}
                    className="text-[11px] text-indigo-600 hover:underline dark:text-indigo-400"
                  >
                    {zonesLoading ? '拉取中...' : '刷新 Zone'}
                  </button>
                </div>
                <select
                  className="input-field"
                  value={form.dns_zone_id}
                  onChange={(e) => handleZoneChange(e.target.value)}
                >
                  <option value="">-- 请选择公网域名 Zone --</option>
                  {zones.map((z) => (
                    <option key={z.id} value={z.id}>
                      {z.name} ({z.id.slice(0, 8)}...)
                    </option>
                  ))}
                  {form.dns_zone_id && !zones.some((z) => z.id === form.dns_zone_id) && (
                    <option value={form.dns_zone_id}>
                      {form.dns_zone_name || form.dns_zone_id} (当前保存)
                    </option>
                  )}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">子域名前缀（自动拼接）</label>
                <input
                  type="text"
                  className="input-field font-mono text-xs"
                  value={subdomainPrefix}
                  onChange={(e) => handleSubdomainChange(e.target.value)}
                  placeholder="例如：ali 或 @（根域名）"
                  disabled={!form.dns_zone_name}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">绑定完整域名 (FQDN) *</label>
                <input
                  type="text"
                  className="input-field font-mono text-xs"
                  value={form.dns_domain}
                  onChange={(e) => setForm({ ...form, dns_domain: e.target.value })}
                  placeholder="ali.example.com"
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-xs font-medium">DNS TTL（秒）</label>
                  <NumericInput
                    min={1}
                    max={86400}
                    className="input-field"
                    value={form.dns_ttl}
                    onChange={(v) => setForm({ ...form, dns_ttl: v })}
                    required
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">订阅排序值</label>
                  <NumericInput
                    className="input-field"
                    value={form.sort_order}
                    onChange={(v) => setForm({ ...form, sort_order: v })}
                  />
                </div>
              </div>
              <label className="flex items-center gap-2 text-sm font-medium sm:col-span-2">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                  className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                />
                启用该负载均衡分组（启用后组内成员独立节点将从订阅中隐藏）
              </label>
            </div>
          )}

          {activeTab === 'members' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-medium">负载均衡策略</label>
                  <select
                    className="input-field"
                    value={form.strategy}
                    onChange={(e) => setForm({ ...form, strategy: e.target.value as LBStrategy })}
                  >
                    <option value="remaining_balance">动态均衡（按剩余可用流量，默认）</option>
                    <option value="failover">主备阶梯切换（按优先级顺序）</option>
                    <option value="weighted_multi">多 IP 动态权重（同时解析多 IP）</option>
                  </select>
                </div>

                {form.strategy === 'remaining_balance' && (
                  <div>
                    <label className="mb-1 block text-xs font-medium">切换冷却时间（分钟）</label>
                    <NumericInput
                      min={0}
                      className="input-field"
                      value={form.switch_cooldown_minutes}
                      onChange={(v) => setForm({ ...form, switch_cooldown_minutes: v })}
                    />
                  </div>
                )}

                {form.strategy === 'failover' && (
                  <div>
                    <label className="mb-1 block text-xs font-medium">主节点流量切换阈值（%）</label>
                    <NumericInput
                      min={1}
                      max={100}
                      className="input-field"
                      value={form.failover_threshold_percent}
                      onChange={(v) => setForm({ ...form, failover_threshold_percent: v })}
                    />
                  </div>
                )}
              </div>

              {form.strategy === 'remaining_balance' && (
                <ByteSizeInput
                  label="防抖差值（候选节点剩余流量需领先当前节点至少该值才自动切换；离线/超限立即切换）"
                  value={form.switch_diff_bytes}
                  onChange={(v) => setForm({ ...form, switch_diff_bytes: v })}
                  zeroText="0 = 只要领先即切换（受冷却时间限制）"
                />
              )}

              {form.strategy === 'weighted_multi' && (
                <div className="rounded-lg bg-indigo-50 px-3 py-2 text-xs text-indigo-800 dark:bg-indigo-950/40 dark:text-indigo-200">
                  华为云 DNS 将同时保留组内健康节点的 A 记录，并按各节点剩余可用流量比例自动计算 1–100 权重；离线或超限节点自动剔除。
                </div>
              )}

              <div className="rounded-xl border border-slate-200 p-3 dark:border-slate-800">
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-semibold">选择成员节点（已选 {form.member_node_ids.length}）</span>
                  <div className="flex items-center gap-2">
                    <select
                      className="input-field py-1 text-xs"
                      value={templateNodeId}
                      onChange={(e) => setTemplateNodeId(e.target.value)}
                    >
                      <option value="">-- 从已有节点导入协议配置 --</option>
                      {nodes.map((n) => (
                        <option key={n.id} value={String(n.id)}>
                          {n.name} (#{n.id})
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      disabled={!templateNodeId}
                      onClick={handleImportFromNode}
                      className="btn-secondary shrink-0 px-2.5 py-1 text-xs"
                    >
                      导入配置
                    </button>
                  </div>
                </div>

                <div className="grid max-h-44 grid-cols-1 gap-1.5 overflow-y-auto sm:grid-cols-2">
                  {nodes.map((n) => {
                    const checked = form.member_node_ids.includes(n.id);
                    const inOtherGroup = Boolean(n.lb_group_id && n.lb_group_id !== editingId);
                    return (
                      <label
                        key={n.id}
                        className={`flex items-center justify-between gap-2 rounded-lg border px-2.5 py-1.5 text-xs ${
                          inOtherGroup
                            ? 'cursor-not-allowed border-slate-200 opacity-50 dark:border-slate-800'
                            : 'cursor-pointer border-slate-200 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/60'
                        }`}
                      >
                        <span className="flex min-w-0 items-center gap-2">
                          <input
                            type="checkbox"
                            disabled={inOtherGroup}
                            checked={checked}
                            onChange={() => toggleMember(n.id)}
                            className="h-3.5 w-3.5 rounded border-slate-300 text-indigo-600"
                          />
                          <span className="truncate font-medium">{n.name}</span>
                        </span>
                        <span className="shrink-0 font-mono text-[10px] text-slate-400">
                          {inOtherGroup ? `已属 ${n.lb_group_name}` : n.public_ip || `#${n.id}`}
                        </span>
                      </label>
                    );
                  })}
                </div>

                {form.member_node_ids.length > 0 && (
                  <div className="mt-3 border-t border-slate-100 pt-2.5 dark:border-slate-800">
                    <div className="mb-1.5 text-[11px] font-medium text-slate-500">
                      成员优先级顺序（主备切换策略优先选择靠前节点）
                    </div>
                    <div className="space-y-1">
                      {form.member_node_ids.map((nid, idx) => {
                        const n = nodeMap.get(nid);
                        return (
                          <div
                            key={nid}
                            className="flex items-center justify-between rounded bg-slate-50 px-2.5 py-1 text-xs dark:bg-slate-800/50"
                          >
                            <span>
                              <strong className="font-mono text-slate-400 mr-2">#{idx + 1}</strong>
                              {n?.name || `节点 #${nid}`}
                            </span>
                            <div className="flex items-center gap-1">
                              <button
                                type="button"
                                disabled={idx === 0}
                                onClick={() => moveMember(idx, -1)}
                                className="rounded p-0.5 hover:bg-slate-200 disabled:opacity-30 dark:hover:bg-slate-700"
                              >
                                <ArrowUp className="h-3.5 w-3.5" />
                              </button>
                              <button
                                type="button"
                                disabled={idx === form.member_node_ids.length - 1}
                                onClick={() => moveMember(idx, 1)}
                                className="rounded p-0.5 hover:bg-slate-200 disabled:opacity-30 dark:hover:bg-slate-700"
                              >
                                <ArrowDown className="h-3.5 w-3.5" />
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'snell' && (
            <div className="space-y-4">
              <label className="flex items-center gap-2 text-sm font-medium">
                <input
                  type="checkbox"
                  checked={form.snell_config.enabled}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      snell_config: { ...form.snell_config, enabled: e.target.checked },
                    })
                  }
                  className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                />
                启用管理员 Snell + ShadowTLS v3 统一配置（自动同步至组内所有成员）
              </label>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-medium">Snell 版本</label>
                  <select
                    className="input-field"
                    value={form.snell_config.version}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        snell_config: { ...form.snell_config, version: e.target.value as SnellVersion },
                      })
                    }
                  >
                    <option value="v5">v5</option>
                    <option value="v4">v4</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">公网 ShadowTLS 监听端口</label>
                  <NumericInput
                    min={1}
                    max={65535}
                    className="input-field"
                    value={form.snell_config.public_port}
                    onChange={(v) =>
                      setForm({
                        ...form,
                        snell_config: { ...form.snell_config, public_port: v },
                      })
                    }
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">Snell PSK</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      className="input-field font-mono text-xs"
                      value={form.snell_config.psk}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          snell_config: { ...form.snell_config, psk: e.target.value },
                        })
                      }
                    />
                    <button
                      type="button"
                      onClick={() =>
                        setForm({
                          ...form,
                          snell_config: { ...form.snell_config, psk: randomAlnum(24) },
                        })
                      }
                      className="btn-secondary shrink-0 px-2.5"
                    >
                      <Sparkles className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">ShadowTLS 密码</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      className="input-field font-mono text-xs"
                      value={form.snell_config.stls_password}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          snell_config: { ...form.snell_config, stls_password: e.target.value },
                        })
                      }
                    />
                    <button
                      type="button"
                      onClick={() =>
                        setForm({
                          ...form,
                          snell_config: { ...form.snell_config, stls_password: randomAlnum(20) },
                        })
                      }
                      className="btn-secondary shrink-0 px-2.5"
                    >
                      <Sparkles className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">ShadowTLS 伪装 SNI</label>
                  <input
                    type="text"
                    className="input-field font-mono text-xs"
                    value={form.snell_config.stls_sni}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        snell_config: { ...form.snell_config, stls_sni: e.target.value },
                      })
                    }
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">Snell Obfs</label>
                  <select
                    className="input-field"
                    value={form.snell_config.obfs}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        snell_config: { ...form.snell_config, obfs: e.target.value as SnellObfs },
                      })
                    }
                  >
                    <option value="off">off</option>
                    <option value="http">http</option>
                    <option value="tls">tls</option>
                  </select>
                </div>
              </div>

              <label className="flex items-center gap-2 text-xs font-medium">
                <input
                  type="checkbox"
                  checked={form.snell_config.tfo}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      snell_config: { ...form.snell_config, tfo: e.target.checked },
                    })
                  }
                  className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                />
                开启 TCP Fast Open (TFO)
              </label>
            </div>
          )}

          {activeTab === 'ss' && (
            <div className="space-y-4">
              <label className="flex items-center gap-2 text-sm font-medium">
                <input
                  type="checkbox"
                  checked={form.ss_config.enabled}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      ss_config: { ...form.ss_config, enabled: e.target.checked },
                    })
                  }
                  className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                />
                启用多用户 SS2022 + ShadowTLS v3 统一配置（自动同步至组内所有成员）
              </label>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-medium">TCP 公网端口 (ShadowTLS)</label>
                  <NumericInput
                    min={1}
                    max={65535}
                    className="input-field"
                    value={form.ss_config.tcp_port}
                    onChange={(v) =>
                      setForm({
                        ...form,
                        ss_config: { ...form.ss_config, tcp_port: v },
                      })
                    }
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">UDP 端口（0 则复用 TCP 端口）</label>
                  <NumericInput
                    min={0}
                    max={65535}
                    className="input-field"
                    value={form.ss_config.udp_port}
                    onChange={(v) =>
                      setForm({
                        ...form,
                        ss_config: { ...form.ss_config, udp_port: v },
                      })
                    }
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">SS2022 加密套件</label>
                  <select
                    className="input-field"
                    value={form.ss_config.cipher}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        ss_config: { ...form.ss_config, cipher: e.target.value as SSCipher },
                      })
                    }
                  >
                    <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm (16B)</option>
                    <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm (32B)</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">ShadowTLS 伪装 SNI</label>
                  <input
                    type="text"
                    className="input-field font-mono text-xs"
                    value={form.ss_config.stls_sni}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        ss_config: { ...form.ss_config, stls_sni: e.target.value },
                      })
                    }
                  />
                </div>
                <div className="sm:col-span-2">
                  <label className="mb-1 block text-xs font-medium">Server iPSK (Base64)</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      className="input-field font-mono text-xs"
                      value={form.ss_config.ipsk}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          ss_config: { ...form.ss_config, ipsk: e.target.value },
                        })
                      }
                    />
                    <button
                      type="button"
                      onClick={() =>
                        setForm({
                          ...form,
                          ss_config: {
                            ...form.ss_config,
                            ipsk: randomBase64(
                              form.ss_config.cipher === '2022-blake3-aes-256-gcm' ? 32 : 16
                            ),
                          },
                        })
                      }
                      className="btn-secondary shrink-0 px-3 text-xs"
                    >
                      <Sparkles className="h-3.5 w-3.5" />
                      随机生成
                    </button>
                  </div>
                </div>
              </div>

              <label className="flex items-center gap-2 text-xs font-medium">
                <input
                  type="checkbox"
                  checked={form.ss_config.tfo}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      ss_config: { ...form.ss_config, tfo: e.target.checked },
                    })
                  }
                  className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                />
                开启 sing-box TCP Fast Open (TFO)
              </label>
            </div>
          )}
        </form>
      </Modal>

      {/* Switch Logs Modal */}
      <Modal
        open={Boolean(logsGroup)}
        onClose={() => setLogsGroup(null)}
        title={`DNS 切换日志 — ${logsGroup?.name ?? ''}`}
        subtitle={logsGroup?.dns_domain}
        maxWidthClass="max-w-3xl"
        footer={
          <button type="button" onClick={() => setLogsGroup(null)} className="btn-primary">
            关闭
          </button>
        }
      >
        {logsLoading ? (
          <p className="py-8 text-center text-sm text-slate-500">加载切换日志中...</p>
        ) : logs.length === 0 ? (
          <p className="py-8 text-center text-sm text-slate-400">暂无 DNS 切换记录</p>
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <table className="min-w-full divide-y divide-slate-200 text-left text-xs dark:divide-slate-800">
              <thead className="sticky top-0 bg-white text-slate-500 dark:bg-slate-900">
                <tr>
                  <th className="py-2 pr-3 font-medium">时间</th>
                  <th className="py-2 pr-3 font-medium">事件</th>
                  <th className="py-2 pr-3 font-medium">解析变更</th>
                  <th className="py-2 font-medium">原因</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70">
                {logs.map((item) => (
                  <tr key={item.id}>
                    <td className="whitespace-nowrap py-2 pr-3 font-mono text-[11px] text-slate-500">
                      {formatDateTime(item.created_at)}
                    </td>
                    <td className="whitespace-nowrap py-2 pr-3">
                      <span className="rounded bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                        {LOG_EVENT_LABELS[item.event_type] || item.event_type}
                      </span>
                    </td>
                    <td className="py-2 pr-3 font-mono text-[11px]">
                      {item.from_ips || '—'} → {item.to_ips || '—'}
                    </td>
                    <td className="py-2 text-slate-600 dark:text-slate-300">{item.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Modal>
    </div>
  );
}
