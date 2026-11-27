import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  ArrowDown,
  ArrowUp,
  Cpu,
  Edit3,
  Plus,
  RefreshCw,
  RotateCcw,
  Scale,
  Server,
  SlidersHorizontal,
  Sparkles,
  Terminal,
  Trash2,
  Zap,
} from 'lucide-react';
import { api, ApiError } from '../../api/client';
import type {
  DNSIPPreference,
  DNSRuleGroup,
  InstallCmdResponse,
  NodeDTO,
  NodeUpsertRequest,
  ServiceCtlAction,
  SnellObfs,
  SnellVersion,
  SSCipher,
  ThresholdAction,
  TrafficCountMode,
} from '../../types/api';
import { useToast } from '../../contexts/ToastContext';
import { Modal } from '../../components/Modal';
import { HealthPill, NodeStatusBadge } from '../../components/Badge';
import { CopyButton } from '../../components/CopyButton';
import { ByteSizeInput } from '../../components/ByteSizeInput';
import { NumericInput } from '../../components/NumericInput';
import {
  formatBytes,
  formatDateTime,
  formatKernelVersion,
  formatSpeed,
  formatUptime,
  randomAlnum,
  randomBase64,
} from '../../utils/format';

function makeDefaultForm(sortOrder = 0): NodeUpsertRequest {
  return {
    name: '',
    region_tag: '',
    public_ip: '',
    public_ipv6: '',
    custom_entry_host: '',
    custom_entry_port: 0,
    sort_order: sortOrder,
    enabled: true,
    snell_config: {
      enabled: true,
      version: 'v5',
      public_port: 18443,
      inner_port: 18444,
      psk: randomAlnum(24),
      obfs: 'off',
      tfo: true,
      dns_ip_preference: 'prefer-ipv4',
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
    dns_unlock_enabled: false,
    dns_unlock_server: '',
    dns_rule_group_id: null,
    dns_extra_rules: [],
    traffic_limit_bytes: 0,
    traffic_threshold_bytes: 0,
    traffic_count_mode: 'both',
    threshold_action: 'stop_all',
    billing_reset_day: 1,
  };
}

function nodeToForm(n: NodeDTO): NodeUpsertRequest {
  return {
    name: n.name,
    region_tag: n.region_tag,
    public_ip: n.public_ip,
    public_ipv6: n.public_ipv6,
    custom_entry_host: n.custom_entry_host,
    custom_entry_port: n.custom_entry_port,
    sort_order: n.sort_order,
    enabled: n.enabled,
    snell_config: {
      enabled: n.snell_config.enabled,
      version: n.snell_config.version || 'v5',
      public_port: n.snell_config.public_port || 0,
      inner_port: n.snell_config.inner_port || 0,
      psk: n.snell_config.psk || '',
      obfs: n.snell_config.obfs || 'off',
      tfo: Boolean(n.snell_config.tfo),
      dns_ip_preference: n.snell_config.dns_ip_preference || 'prefer-ipv4',
      stls_password: n.snell_config.stls_password || '',
      stls_sni: n.snell_config.stls_sni || '',
    },
    ss_config: {
      enabled: n.ss_config.enabled,
      tcp_port: n.ss_config.tcp_port || 0,
      udp_port: n.ss_config.udp_port || 0,
      cipher: n.ss_config.cipher || '2022-blake3-aes-128-gcm',
      ipsk: n.ss_config.ipsk || '',
      stls_sni: n.ss_config.stls_sni || '',
      tfo: Boolean(n.ss_config.tfo),
    },
    dns_unlock_enabled: n.dns_unlock_enabled,
    dns_unlock_server: n.dns_unlock_server,
    dns_rule_group_id: n.dns_rule_group_id,
    dns_extra_rules: n.dns_extra_rules || [],
    traffic_limit_bytes: n.traffic_limit_bytes,
    traffic_threshold_bytes: n.traffic_threshold_bytes,
    traffic_count_mode: n.traffic_count_mode || 'both',
    threshold_action: n.threshold_action || 'stop_all',
    billing_reset_day: n.billing_reset_day >= 1 && n.billing_reset_day <= 31 ? n.billing_reset_day : 1,
  };
}

export function NodesPage() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const syncNodeIdParam = Number(searchParams.get('syncNodeId') || 0);

  const [nodes, setNodes] = useState<NodeDTO[]>([]);
  const [dnsGroups, setDnsGroups] = useState<DNSRuleGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [regionFilter, setRegionFilter] = useState<string>('__ALL__');

  // Create/Edit Modal
  const [editOpen, setEditOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'basic' | 'snell' | 'ss' | 'dns' | 'traffic'>('basic');
  const [form, setForm] = useState<NodeUpsertRequest>(() => makeDefaultForm());
  const [extraRulesText, setExtraRulesText] = useState('');
  const [saving, setSaving] = useState(false);

  // Install Command Modal
  const [installOpen, setInstallOpen] = useState(false);
  const [installData, setInstallData] = useState<InstallCmdResponse | null>(null);
  const [installLoading, setInstallLoading] = useState(false);

  // Calibrate Traffic Modal
  const [calNode, setCalNode] = useState<NodeDTO | null>(null);
  const [calRx, setCalRx] = useState('0');
  const [calTx, setCalTx] = useState('0');
  const [calSaving, setCalSaving] = useState(false);

  // Service Ctl Modal
  const [ctlNode, setCtlNode] = useState<NodeDTO | null>(null);
  const [ctlBusy, setCtlBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [nList, gList] = await Promise.all([api.listNodes(), api.listDnsRules()]);
      setNodes(nList);
      setDnsGroups(gList);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载节点列表失败');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const { regionTags, hasUntagged, filteredNodes } = useMemo(() => {
    const tagSet = new Set<string>();
    let untagged = false;
    for (const n of nodes) {
      const tag = (n.region_tag || '').trim();
      if (tag) {
        tagSet.add(tag);
      } else {
        untagged = true;
      }
    }
    const sortedTags = Array.from(tagSet).sort((a, b) => a.localeCompare(b));
    const filtered =
      regionFilter === '__ALL__'
        ? nodes
        : regionFilter === '__UNTAGGED__'
          ? nodes.filter((n) => !(n.region_tag || '').trim())
          : nodes.filter((n) => (n.region_tag || '').trim() === regionFilter);
    return { regionTags: sortedTags, hasUntagged: untagged, filteredNodes: filtered };
  }, [nodes, regionFilter]);

  useEffect(() => {
    if (
      regionFilter !== '__ALL__' &&
      regionFilter !== '__UNTAGGED__' &&
      !regionTags.includes(regionFilter)
    ) {
      setRegionFilter('__ALL__');
    }
  }, [regionFilter, regionTags]);

  const targetSyncNode = useMemo(
    () => (syncNodeIdParam > 0 ? nodes.find((n) => n.id === syncNodeIdParam) ?? null : null),
    [nodes, syncNodeIdParam]
  );

  const openCreate = () => {
    const nextSort = nodes.length > 0 ? Math.max(...nodes.map((n) => n.sort_order)) + 1 : 0;
    setEditingId(null);
    setForm(makeDefaultForm(nextSort));
    setExtraRulesText('');
    setActiveTab('basic');
    setEditOpen(true);
  };

  const openEdit = (n: NodeDTO) => {
    setEditingId(n.id);
    setForm(nodeToForm(n));
    setExtraRulesText((n.dns_extra_rules || []).join('\n'));
    setActiveTab('basic');
    setEditOpen(true);
  };

  const openInstallCmd = async (nodeId: number) => {
    setInstallOpen(true);
    setInstallLoading(true);
    setInstallData(null);
    try {
      const cmd = await api.getNodeInstallCmd(nodeId);
      setInstallData(cmd);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '获取安装命令失败');
      setInstallOpen(false);
    } finally {
      setInstallLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      toast.error('请填写节点名称');
      setActiveTab('basic');
      return;
    }
    const customEntryPort = Number.isNaN(form.custom_entry_port) ? 0 : form.custom_entry_port;
    if (!Number.isInteger(customEntryPort) || customEntryPort < 0 || customEntryPort > 65535) {
      toast.error('自定义入口端口必须为 0 到 65535 之间的整数');
      setActiveTab('basic');
      return;
    }
    const sortOrder = Number.isNaN(form.sort_order) ? 0 : form.sort_order;
    if (!Number.isInteger(sortOrder)) {
      toast.error('排序值必须为整数');
      setActiveTab('basic');
      return;
    }
    const snellPubPort = Number.isNaN(form.snell_config.public_port)
      ? 0
      : form.snell_config.public_port;
    const snellInnerPort = Number.isNaN(form.snell_config.inner_port)
      ? 0
      : form.snell_config.inner_port;
    if (
      !Number.isInteger(snellPubPort) ||
      snellPubPort < 0 ||
      snellPubPort > 65535 ||
      !Number.isInteger(snellInnerPort) ||
      snellInnerPort < 0 ||
      snellInnerPort > 65535
    ) {
      toast.error('Snell 端口必须为 0 到 65535 之间的整数');
      setActiveTab('snell');
      return;
    }
    const ssTcpPort = Number.isNaN(form.ss_config.tcp_port) ? 0 : form.ss_config.tcp_port;
    const ssUdpPort = Number.isNaN(form.ss_config.udp_port) ? 0 : form.ss_config.udp_port;
    if (
      !Number.isInteger(ssTcpPort) ||
      ssTcpPort < 0 ||
      ssTcpPort > 65535 ||
      !Number.isInteger(ssUdpPort) ||
      ssUdpPort < 0 ||
      ssUdpPort > 65535
    ) {
      toast.error('SS2022 端口必须为 0 到 65535 之间的整数');
      setActiveTab('ss');
      return;
    }
    if (
      !Number.isInteger(form.billing_reset_day) ||
      form.billing_reset_day < 1 ||
      form.billing_reset_day > 31
    ) {
      toast.error('月度流量重置日必须为 1 到 31 之间的整数');
      setActiveTab('traffic');
      return;
    }
    const payload: NodeUpsertRequest = {
      ...form,
      name: form.name.trim(),
      region_tag: form.region_tag.trim(),
      public_ip: (form.public_ip ?? '').trim(),
      public_ipv6: (form.public_ipv6 ?? '').trim(),
      custom_entry_host: form.custom_entry_host.trim(),
      custom_entry_port: customEntryPort,
      sort_order: sortOrder,
      snell_config: {
        ...form.snell_config,
        public_port: snellPubPort,
        inner_port: snellInnerPort,
      },
      ss_config: {
        ...form.ss_config,
        tcp_port: ssTcpPort,
        udp_port: ssUdpPort,
      },
      dns_unlock_server: form.dns_unlock_server.trim(),
      dns_rule_group_id: form.dns_rule_group_id ?? null,
      dns_extra_rules: extraRulesText
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean),
    };

    setSaving(true);
    try {
      if (editingId === null) {
        const created = await api.createNode(payload);
        toast.success(`已创建节点 "${created.name}"`);
        setEditOpen(false);
        await load();
        void openInstallCmd(created.id);
      } else {
        const updated = await api.updateNode(editingId, payload);
        toast.success(`已更新节点 "${updated.name}"`);
        setEditOpen(false);
        await load();
      }
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '保存节点失败');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (n: NodeDTO) => {
    if (!window.confirm(`确定删除节点 "${n.name}" 吗？该节点的历史每日流量日志也会一并移除。`)) {
      return;
    }
    try {
      await api.deleteNode(n.id);
      toast.success(`已删除节点 "${n.name}"`);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '删除节点失败');
    }
  };

  const handleMove = async (index: number, delta: -1 | 1) => {
    if (regionFilter !== '__ALL__') return;
    const targetIdx = index + delta;
    if (targetIdx < 0 || targetIdx >= nodes.length) return;
    const reordered = [...nodes];
    const [moved] = reordered.splice(index, 1);
    reordered.splice(targetIdx, 0, moved);
    const ids = reordered.map((n) => n.id);
    setNodes(reordered);
    try {
      await api.reorderNodes(ids);
      toast.success('节点排序已更新');
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '更新节点排序失败');
      await load();
    }
  };

  const handleSync = async (n: NodeDTO) => {
    try {
      const res = await api.syncNode(n.id);
      toast.info(
        res.synced
          ? `已向 "${n.name}" 下发最新配置同步`
          : `节点 "${n.name}" 当前离线，已记录待同步配置`
      );
      if (syncNodeIdParam === n.id) {
        setSearchParams({});
      }
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '同步节点配置失败');
    }
  };

  const handleResetTraffic = async (n: NodeDTO) => {
    if (!window.confirm(`确定将 "${n.name}" 的本周期流量计数器清零吗？（累计总流量将保留）`)) return;
    try {
      await api.resetNodeTraffic(n.id);
      toast.success(`已清零 "${n.name}" 的本周期流量`);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '清零周期流量失败');
    }
  };

  const handleCalibrateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!calNode) return;
    const rx = Number(calRx);
    const tx = Number(calTx);
    if (!Number.isInteger(rx) || rx < 0 || !Number.isInteger(tx) || tx < 0) {
      toast.error('周期下载和上传字节数必须为非负整数');
      return;
    }
    setCalSaving(true);
    try {
      await api.calibrateNodeTraffic(calNode.id, { cycle_rx_bytes: rx, cycle_tx_bytes: tx });
      toast.success(`已校准 "${calNode.name}" 的周期流量`);
      setCalNode(null);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '流量校准失败');
    } finally {
      setCalSaving(false);
    }
  };

  const handleServiceCtl = async (action: ServiceCtlAction) => {
    if (!ctlNode) return;
    setCtlBusy(true);
    try {
      const res = await api.serviceCtlNode(ctlNode.id, action);
      toast.success(`已向 "${ctlNode.name}" 发送控制指令 (${res.action})`);
      setCtlNode(null);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '发送服务控制指令失败');
    } finally {
      setCtlBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="admin-sticky-header space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white">节点管理</h1>
            <p className="hidden text-sm text-slate-500 dark:text-slate-400 sm:block">
              管理 Snell + ShadowTLS v3、sing-box SS2022 EIH、DNS 解锁、流量上限及节点部署命令
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button type="button" onClick={() => void load()} className="btn-secondary" disabled={loading}>
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              刷新
            </button>
            <button type="button" onClick={openCreate} className="btn-primary">
              <Plus className="h-4 w-4" />
              添加节点
            </button>
          </div>
        </div>

        {/* Region Tag Filter Bar */}
        {nodes.length > 0 && (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-slate-500 dark:text-slate-400">地区筛选：</span>
            <button
              type="button"
              onClick={() => setRegionFilter('__ALL__')}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium ${
                regionFilter === '__ALL__'
                  ? 'bg-indigo-600 text-white dark:bg-indigo-500'
                  : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-800'
              }`}
            >
              全部地区 ({nodes.length})
            </button>
            {regionTags.map((tag) => {
              const count = nodes.filter((n) => (n.region_tag || '').trim() === tag).length;
              return (
                <button
                  key={tag}
                  type="button"
                  onClick={() => setRegionFilter(tag)}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium ${
                    regionFilter === tag
                      ? 'bg-indigo-600 text-white dark:bg-indigo-500'
                      : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-800'
                  }`}
                >
                  {tag} ({count})
                </button>
              );
            })}
            {hasUntagged && (
              <button
                type="button"
                onClick={() => setRegionFilter('__UNTAGGED__')}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium ${
                  regionFilter === '__UNTAGGED__'
                    ? 'bg-indigo-600 text-white dark:bg-indigo-500'
                    : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-800'
                }`}
              >
                未分组 ({nodes.filter((n) => !(n.region_tag || '').trim()).length})
              </button>
            )}
          </div>
        )}
      </div>

      {/* Sync Prompt Banner when navigated from Overview */}
      {targetSyncNode && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-950 dark:border-amber-800/70 dark:bg-amber-950/40 dark:text-amber-100">
          <div>
            <strong>{targetSyncNode.name}</strong> 配置尚未同步到最新版本，可点击右侧按钮手动触发配置同步。
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void handleSync(targetSyncNode)}
              className="btn-primary px-3 py-1.5 text-xs"
            >
              <Zap className="h-3.5 w-3.5" />
              立即同步配置
            </button>
            <button
              type="button"
              onClick={() => setSearchParams({})}
              className="btn-secondary px-3 py-1.5 text-xs"
            >
              忽略
            </button>
          </div>
        </div>
      )}

      {nodes.length === 0 && !loading ? (
        <div className="card flex flex-col items-center justify-center py-16 text-center">
          <Server className="h-10 w-10 text-slate-300 dark:text-slate-600" />
          <p className="mt-3 text-sm font-medium text-slate-700 dark:text-slate-300">暂无节点</p>
          <button type="button" onClick={openCreate} className="btn-primary mt-4">
            <Plus className="h-4 w-4" /> 添加第一个节点
          </button>
        </div>
      ) : filteredNodes.length === 0 ? (
        <div className="card flex flex-col items-center justify-center py-12 text-center">
          <p className="text-sm font-medium text-slate-600 dark:text-slate-300">
            当前地区筛选条件下没有匹配的节点
          </p>
          <button
            type="button"
            onClick={() => setRegionFilter('__ALL__')}
            className="btn-secondary mt-3 text-xs"
          >
            查看全部节点
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredNodes.map((node, idx) => {
            const isSyncHighlighted = syncNodeIdParam > 0 && node.id === syncNodeIdParam;
            const isSynced =
              node.config_revision > 0 && node.reported_config_revision === node.config_revision;
            return (
              <div
                key={node.id}
                className={`card p-4 sm:p-5 ${
                  isSyncHighlighted
                    ? 'ring-2 ring-amber-400 dark:ring-amber-500'
                    : ''
                }`}
              >
                <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
                  {/* Left Info */}
                  <div className="min-w-0 flex-1 space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-slate-400">#{node.id}</span>
                      <h3 className="text-base font-semibold text-slate-900 dark:text-white">{node.name}</h3>
                      {node.region_tag && (
                        <span className="shrink-0 whitespace-nowrap rounded bg-slate-100 px-2 py-0.5 text-[11px] font-semibold uppercase text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                          {node.region_tag}
                        </span>
                      )}
                      <NodeStatusBadge status={node.status} />
                      <span
                        className={`shrink-0 whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium ${
                          isSynced
                            ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300'
                            : 'bg-amber-100 text-amber-800 dark:bg-amber-950/70 dark:text-amber-300'
                        }`}
                      >
                        {isSynced ? '配置已同步' : '配置待同步'}
                      </span>
                      {!node.enabled && (
                        <span className="shrink-0 whitespace-nowrap rounded bg-slate-200 px-2 py-0.5 text-[11px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                          已禁用
                        </span>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
                      <span className="font-mono">
                        入口：{node.custom_entry_host || node.public_ip || '等待节点上报'}
                        {node.custom_entry_port > 0 ? `:${node.custom_entry_port}` : ''}
                      </span>
                      {node.public_ip && (
                        <span className="font-mono">IPv4：{node.public_ip}</span>
                      )}
                      {node.public_ipv6 && (
                        <span className="font-mono break-all">IPv6：{node.public_ipv6}</span>
                      )}
                      <span>
                        系统架构：<strong className="font-mono">{node.agent_os || '—'}/{node.agent_arch || '—'}</strong>
                      </span>
                      <span>最后在线：{formatDateTime(node.last_seen_at)}</span>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 pt-0.5">
                      <HealthPill label="Snell + ShadowTLS" healthy={node.core_a_healthy} />
                      <HealthPill label="sing-box" healthy={node.core_b_healthy} />
                      <span className="inline-flex max-w-full flex-wrap items-center gap-1 rounded-md bg-slate-100 px-2 py-0.5 font-mono text-[11px] break-words text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                        <Cpu className="h-3 w-3 shrink-0" />
                        <span>
                          Snell: {formatKernelVersion(node.reported_versions?.snell_server)} · ShadowTLS:{' '}
                          {formatKernelVersion(node.reported_versions?.shadow_tls)} · sing-box:{' '}
                          {formatKernelVersion(node.reported_versions?.sing_box)}
                        </span>
                      </span>
                    </div>
                  </div>

                  {/* Telemetry */}
                  <div className="grid grid-cols-2 gap-3 rounded-xl bg-slate-50 p-3 text-xs dark:bg-slate-800/60 sm:grid-cols-3 xl:w-[580px] xl:shrink-0 xl:grid-cols-6">
                    <div>
                      <div className="text-slate-400">CPU / 磁盘</div>
                      <div className="mt-0.5 font-mono font-semibold text-slate-800 dark:text-slate-200">
                        {node.cpu_percent.toFixed(1)}% / {node.disk_used_percent.toFixed(0)}%
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-400">内存</div>
                      <div className="mt-0.5 font-mono font-semibold text-slate-800 dark:text-slate-200">
                        {formatBytes(node.mem_used_bytes)}
                      </div>
                      {node.mem_total_bytes > 0 && (
                        <div className="text-[10px] font-mono text-slate-400">
                          / {formatBytes(node.mem_total_bytes)}
                        </div>
                      )}
                    </div>
                    <div>
                      <div className="text-slate-400">运行时长</div>
                      <div className="mt-0.5 font-mono font-semibold text-slate-800 dark:text-slate-200">
                        {formatUptime(node.uptime_seconds)}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-400">实时速率</div>
                      <div className="mt-0.5 font-mono text-[11px]">
                        <span className="text-emerald-600 dark:text-emerald-400">↓{formatSpeed(node.rx_bps)}</span>
                        <br />
                        <span className="text-indigo-600 dark:text-indigo-400">↑{formatSpeed(node.tx_bps)}</span>
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-400">周期流量</div>
                      <div className="mt-0.5 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                        ↓{formatBytes(node.cycle_rx_bytes)}
                        <br />↑{formatBytes(node.cycle_tx_bytes)}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-400">累计流量</div>
                      <div className="mt-0.5 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                        ↓{formatBytes(node.total_rx_bytes)}
                        <br />↑{formatBytes(node.total_tx_bytes)}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Actions Bar */}
                <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-slate-100 pt-3 dark:border-slate-800">
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      disabled={regionFilter !== '__ALL__' || idx === 0}
                      onClick={() => void handleMove(idx, -1)}
                      className="btn-secondary px-2 py-1 text-xs"
                      title={regionFilter === '__ALL__' ? '上移' : '请先切换到“全部地区”再调整排序'}
                    >
                      <ArrowUp className="h-3.5 w-3.5" />
                    </button>
                    <button
                      type="button"
                      disabled={regionFilter !== '__ALL__' || idx === filteredNodes.length - 1}
                      onClick={() => void handleMove(idx, 1)}
                      className="btn-secondary px-2 py-1 text-xs"
                      title={regionFilter === '__ALL__' ? '下移' : '请先切换到“全部地区”再调整排序'}
                    >
                      <ArrowDown className="h-3.5 w-3.5" />
                    </button>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => void openInstallCmd(node.id)}
                      className="btn-secondary px-2.5 py-1 text-xs"
                    >
                      <Terminal className="h-3.5 w-3.5" />
                      安装命令
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleSync(node)}
                      className={`px-2.5 py-1 text-xs ${isSynced ? 'btn-secondary' : 'btn-primary'}`}
                    >
                      <Zap className="h-3.5 w-3.5" />
                      同步配置
                    </button>
                    <button
                      type="button"
                      onClick={() => setCtlNode(node)}
                      className="btn-secondary px-2.5 py-1 text-xs"
                    >
                      <SlidersHorizontal className="h-3.5 w-3.5" />
                      服务控制
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setCalNode(node);
                        setCalRx(String(node.cycle_rx_bytes));
                        setCalTx(String(node.cycle_tx_bytes));
                      }}
                      className="btn-secondary px-2.5 py-1 text-xs"
                    >
                      <Scale className="h-3.5 w-3.5" />
                      流量校准
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleResetTraffic(node)}
                      className="btn-secondary px-2.5 py-1 text-xs"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      重置周期流量
                    </button>
                    <button
                      type="button"
                      onClick={() => openEdit(node)}
                      className="btn-secondary px-2.5 py-1 text-xs"
                    >
                      <Edit3 className="h-3.5 w-3.5" />
                      编辑
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleDelete(node)}
                      className="btn-danger px-2.5 py-1 text-xs"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      删除
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Create / Edit Modal */}
      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title={editingId === null ? '添加节点' : `编辑节点 #${editingId}`}
        subtitle="保存后将递增配置版本号，并自动向在线节点下发同步。"
        maxWidthClass="max-w-3xl"
        footer={
          <>
            <button type="button" onClick={() => setEditOpen(false)} className="btn-secondary">
              取消
            </button>
            <button type="submit" form="node-upsert-form" disabled={saving} className="btn-primary">
              {saving ? '保存中...' : editingId === null ? '创建节点' : '保存更改'}
            </button>
          </>
        }
      >
        <div className="mb-5 flex flex-wrap gap-1 border-b border-slate-200 pb-3 dark:border-slate-800">
          {(
            [
              ['basic', '基础与入口'],
              ['snell', 'Snell + ShadowTLS'],
              ['ss', 'sing-box (SS2022)'],
              ['dns', 'DNS 解锁'],
              ['traffic', '流量与计费'],
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

        <form id="node-upsert-form" onSubmit={handleSave} className="space-y-4">
          {activeTab === 'basic' && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium">节点名称 *</label>
                <input
                  type="text"
                  className="input-field"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="例如：HK-Edge-01"
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">地区标签 (Region Tag)</label>
                <input
                  type="text"
                  className="input-field"
                  value={form.region_tag}
                  onChange={(e) => setForm({ ...form, region_tag: e.target.value })}
                  placeholder="例如：HK, JP, SG, US"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">自定义入口域名/IP（CDN / 中转）</label>
                <input
                  type="text"
                  className="input-field"
                  value={form.custom_entry_host}
                  onChange={(e) => setForm({ ...form, custom_entry_host: e.target.value })}
                  placeholder="可选：中转域名或入口 IP"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">自定义入口端口（0 = 使用内核端口）</label>
                <NumericInput
                  min={0}
                  max={65535}
                  className="input-field"
                  value={form.custom_entry_port}
                  onChange={(v) => setForm({ ...form, custom_entry_port: v })}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">公网 IPv4 覆盖</label>
                <input
                  type="text"
                  className="input-field font-mono text-xs"
                  value={form.public_ip || ''}
                  onChange={(e) => setForm({ ...form, public_ip: e.target.value })}
                  placeholder="留空由节点端自动探测上报"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">公网 IPv6 覆盖</label>
                <input
                  type="text"
                  className="input-field font-mono text-xs"
                  value={form.public_ipv6 || ''}
                  onChange={(e) => setForm({ ...form, public_ipv6: e.target.value })}
                  placeholder="留空由节点端自动探测上报"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">排序权重</label>
                <NumericInput
                  className="input-field"
                  value={form.sort_order}
                  onChange={(v) => setForm({ ...form, sort_order: v })}
                />
              </div>
              <div className="flex items-end pb-1">
                <label className="flex items-center gap-2 text-sm font-medium">
                  <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                    className="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  启用节点（展示在公开状态页并下发订阅）
                </label>
              </div>
            </div>
          )}

          {activeTab === 'snell' && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="sm:col-span-2">
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
                  启用 Snell + ShadowTLS v3 管理员通道
                </label>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Snell 协议版本</label>
                <select
                  className="input-field"
                  value={form.snell_config.version || 'v5'}
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
                <label className="mb-1 block text-xs font-medium">混淆模式 (Obfs)</label>
                <select
                  className="input-field"
                  value={form.snell_config.obfs || 'off'}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      snell_config: { ...form.snell_config, obfs: e.target.value as SnellObfs },
                    })
                  }
                >
                  <option value="off">off（关闭）</option>
                  <option value="http">http</option>
                  <option value="tls">tls</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">公网监听端口（ShadowTLS 入口）</label>
                <NumericInput
                  min={0}
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
                <label className="mb-1 block text-xs font-medium">内部监听端口（Snell 回环端口）</label>
                <NumericInput
                  min={0}
                  max={65535}
                  className="input-field"
                  value={form.snell_config.inner_port}
                  onChange={(v) =>
                    setForm({
                      ...form,
                      snell_config: { ...form.snell_config, inner_port: v },
                    })
                  }
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Snell PSK 密钥</label>
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
                    title="随机生成 PSK"
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
                    title="随机生成密码"
                  >
                    <Sparkles className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">ShadowTLS 伪装域名 (SNI)</label>
                <input
                  type="text"
                  className="input-field"
                  value={form.snell_config.stls_sni}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      snell_config: { ...form.snell_config, stls_sni: e.target.value },
                    })
                  }
                  placeholder="gateway.icloud.com"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">DNS IP 优先级</label>
                <select
                  className="input-field"
                  value={form.snell_config.dns_ip_preference || 'prefer-ipv4'}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      snell_config: {
                        ...form.snell_config,
                        dns_ip_preference: e.target.value as DNSIPPreference,
                      },
                    })
                  }
                >
                  <option value="prefer-ipv4">prefer-ipv4（优先 IPv4）</option>
                  <option value="prefer-ipv6">prefer-ipv6（优先 IPv6）</option>
                  <option value="ipv4-only">ipv4-only（仅 IPv4）</option>
                  <option value="auto">auto（自动）</option>
                </select>
              </div>
              <div className="sm:col-span-2">
                <label className="flex items-center gap-2 text-sm">
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
                  启用 TCP Fast Open (TFO)
                </label>
              </div>
            </div>
          )}

          {activeTab === 'ss' && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="sm:col-span-2">
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
                  启用 sing-box SS2022 EIH + ShadowTLS v3 用户通道
                </label>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">TCP 端口（ShadowTLS v3 监听）</label>
                <NumericInput
                  min={0}
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
                <label className="mb-1 block text-xs font-medium">UDP 端口（原生 SS2022 UDP）</label>
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
                <label className="mb-1 block text-xs font-medium">加密方式</label>
                <select
                  className="input-field"
                  value={form.ss_config.cipher || '2022-blake3-aes-128-gcm'}
                  onChange={(e) => {
                    const cipher = e.target.value as SSCipher;
                    const byteLen = cipher === '2022-blake3-aes-256-gcm' ? 32 : 16;
                    setForm({
                      ...form,
                      ss_config: {
                        ...form.ss_config,
                        cipher,
                        ipsk: randomBase64(byteLen),
                      },
                    });
                  }}
                >
                  <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm (16B iPSK)</option>
                  <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm (32B iPSK)</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">ShadowTLS 伪装域名 (SNI)</label>
                <input
                  type="text"
                  className="input-field"
                  value={form.ss_config.stls_sni}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      ss_config: { ...form.ss_config, stls_sni: e.target.value },
                    })
                  }
                  placeholder="swdist.apple.com"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="mb-1 block text-xs font-medium">服务端 iPSK (Base64)</label>
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
                    onClick={() => {
                      const byteLen =
                        form.ss_config.cipher === '2022-blake3-aes-256-gcm' ? 32 : 16;
                      setForm({
                        ...form,
                        ss_config: { ...form.ss_config, ipsk: randomBase64(byteLen) },
                      });
                    }}
                    className="btn-secondary shrink-0 px-3"
                  >
                    <Sparkles className="h-3.5 w-3.5" />
                    重新生成
                  </button>
                </div>
              </div>
              <div className="sm:col-span-2">
                <label className="flex items-center gap-2 text-sm font-medium">
                  <input
                    type="checkbox"
                    checked={Boolean(form.ss_config.tfo)}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        ss_config: { ...form.ss_config, tfo: e.target.checked },
                      })
                    }
                    className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                  />
                  启用 TCP Fast Open (TFO)
                </label>
              </div>
            </div>
          )}

          {activeTab === 'dns' && (
            <div className="space-y-4">
              <label className="flex items-center gap-2 text-sm font-medium">
                <input
                  type="checkbox"
                  checked={form.dns_unlock_enabled}
                  onChange={(e) => setForm({ ...form, dns_unlock_enabled: e.target.checked })}
                  className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                />
                启用内置本地回环 DNS 流媒体解锁分流器
              </label>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-medium">解锁上游 DNS 服务器</label>
                  <input
                    type="text"
                    className="input-field font-mono text-xs"
                    value={form.dns_unlock_server}
                    onChange={(e) => setForm({ ...form, dns_unlock_server: e.target.value })}
                    placeholder="例如：1.2.3.4:53 或 1.2.3.4:5353"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">绑定 DNS 规则组</label>
                  <select
                    className="input-field"
                    value={form.dns_rule_group_id === null ? '' : String(form.dns_rule_group_id)}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        dns_rule_group_id: e.target.value === '' ? null : Number(e.target.value),
                      })
                    }
                  >
                    <option value="">（不绑定规则组）</option>
                    {dnsGroups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}（{g.rules.length} 条规则）
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="mb-1 block text-xs font-medium">节点专属额外解锁规则（每行一条）</label>
                <textarea
                  rows={5}
                  className="input-field font-mono text-xs"
                  value={extraRulesText}
                  onChange={(e) => setExtraRulesText(e.target.value)}
                  placeholder={'netflix.com\n^nflxvideo.net\n*.disneyplus.com'}
                />
                <p className="mt-1 text-[11px] text-slate-500">
                  支持 <code>abc.com</code>（含主域与子域）、<code>^abc.com</code>（仅精确主域）、{' '}
                  <code>*.abc.com</code>（仅子域）。
                </p>
              </div>
            </div>
          )}

          {activeTab === 'traffic' && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <ByteSizeInput
                label="月度展示流量上限"
                value={form.traffic_limit_bytes}
                onChange={(v) => setForm({ ...form, traffic_limit_bytes: v })}
              />
              <ByteSizeInput
                label="自动熔断暂停阈值"
                value={form.traffic_threshold_bytes}
                onChange={(v) => setForm({ ...form, traffic_threshold_bytes: v })}
                zeroText="0 = 关闭自动暂停"
              />
              <div>
                <label className="mb-1 block text-xs font-medium">流量统计方式</label>
                <select
                  className="input-field"
                  value={form.traffic_count_mode}
                  onChange={(e) =>
                    setForm({ ...form, traffic_count_mode: e.target.value as TrafficCountMode })
                  }
                >
                  <option value="both">双向累加 (RX + TX)</option>
                  <option value="tx_only">仅统计上传 (TX)</option>
                  <option value="rx_only">仅统计下载 (RX)</option>
                  <option value="max_dir">取较大单向 max(RX, TX)</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">达到阈值触发动作</label>
                <select
                  className="input-field"
                  value={form.threshold_action}
                  onChange={(e) =>
                    setForm({ ...form, threshold_action: e.target.value as ThresholdAction })
                  }
                >
                  <option value="stop_all">全部停止 (暂停 Snell 与 SS2022)</option>
                  <option value="stop_ss_only">仅停止 SS2022 (保留管理员 Snell)</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">每月流量重置日（1–31）</label>
                <NumericInput
                  min={1}
                  max={31}
                  className="input-field"
                  value={form.billing_reset_day}
                  onChange={(v) => setForm({ ...form, billing_reset_day: v })}
                  required
                />
              </div>
            </div>
          )}
        </form>
      </Modal>

      {/* Install Command Modal */}
      <Modal
        open={installOpen}
        onClose={() => setInstallOpen(false)}
        title="节点端 (node-agent) 安装命令"
        subtitle={installData ? `面板地址：${installData.panel_url}` : '正在生成安装脚本...'}
        maxWidthClass="max-w-3xl"
        footer={
          <button type="button" onClick={() => setInstallOpen(false)} className="btn-primary">
            完成
          </button>
        }
      >
        {installLoading ? (
          <p className="py-8 text-center text-sm text-slate-500">正在获取安装命令...</p>
        ) : installData ? (
          <div className="space-y-4">
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-800/60">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-600 dark:text-slate-300">NODE_TOKEN</span>
                <CopyButton text={installData.node_token} label="复制 Token" />
              </div>
              <code className="mt-1.5 block break-all font-mono text-xs text-indigo-600 dark:text-indigo-400">
                {installData.node_token}
              </code>
            </div>

            <div>
              <div className="mb-1.5 flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  Docker Compose（推荐）
                </span>
                <CopyButton text={installData.docker_compose} label="复制 Compose" />
              </div>
              <pre className="overflow-x-auto rounded-lg bg-slate-900 p-3.5 font-mono text-xs text-slate-100">
                {installData.docker_compose}
              </pre>
            </div>

            <div>
              <div className="mb-1.5 flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  Docker Run
                </span>
                <CopyButton text={installData.docker_run} label="复制命令" />
              </div>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-slate-900 p-3.5 font-mono text-xs text-slate-100">
                {installData.docker_run}
              </pre>
            </div>
          </div>
        ) : null}
      </Modal>

      {/* Calibrate Traffic Modal */}
      <Modal
        open={Boolean(calNode)}
        onClose={() => setCalNode(null)}
        title={`校准周期流量 — ${calNode?.name ?? ''}`}
        subtitle="手动设置当前计费周期的入站 (RX) 与出站 (TX) 字节计数器。"
        maxWidthClass="max-w-md"
        footer={
          <>
            <button type="button" onClick={() => setCalNode(null)} className="btn-secondary">
              取消
            </button>
            <button type="submit" form="calibrate-form" disabled={calSaving} className="btn-primary">
              {calSaving ? '应用中...' : '确认校准'}
            </button>
          </>
        }
      >
        <form id="calibrate-form" onSubmit={handleCalibrateSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-xs font-medium">周期下载 / 入站字节数 (RX)</label>
            <input
              type="number"
              min={0}
              step={1}
              className="input-field font-mono"
              value={calRx}
              onChange={(e) => setCalRx(e.target.value)}
              required
            />
            <p className="mt-1 text-[11px] text-slate-500">{formatBytes(Number(calRx) || 0)}</p>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">周期上传 / 出站字节数 (TX)</label>
            <input
              type="number"
              min={0}
              step={1}
              className="input-field font-mono"
              value={calTx}
              onChange={(e) => setCalTx(e.target.value)}
              required
            />
            <p className="mt-1 text-[11px] text-slate-500">{formatBytes(Number(calTx) || 0)}</p>
          </div>
        </form>
      </Modal>

      {/* Service Control Modal */}
      <Modal
        open={Boolean(ctlNode)}
        onClose={() => setCtlNode(null)}
        title={`服务控制 — ${ctlNode?.name ?? ''}`}
        subtitle="向在线的节点端远程下发核心进程重启指令。"
        maxWidthClass="max-w-md"
      >
        {ctlNode && (
          <div className="space-y-3">
            {ctlNode.status === 'offline' && (
              <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-200">
                节点当前离线，远程服务控制需要节点保持在线连接。
              </div>
            )}
            <button
              type="button"
              disabled={ctlBusy || ctlNode.status === 'offline'}
              onClick={() => void handleServiceCtl('restart_snell')}
              className="btn-secondary w-full justify-between"
            >
              <span>重启 Snell + ShadowTLS</span>
              <span className="font-mono text-xs text-slate-400">restart_snell</span>
            </button>
            <button
              type="button"
              disabled={ctlBusy || ctlNode.status === 'offline'}
              onClick={() => void handleServiceCtl('restart_singbox')}
              className="btn-secondary w-full justify-between"
            >
              <span>仅重启 sing-box</span>
              <span className="font-mono text-xs text-slate-400">restart_singbox</span>
            </button>
            <button
              type="button"
              disabled={ctlBusy || ctlNode.status === 'offline'}
              onClick={() => void handleServiceCtl('restart_all')}
              className="btn-primary w-full justify-between"
            >
              <span>重启全部代理服务</span>
              <span className="font-mono text-xs opacity-80">restart_all</span>
            </button>
          </div>
        )}
      </Modal>
    </div>
  );
}
