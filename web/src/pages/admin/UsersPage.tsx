import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  BarChart3,
  CheckSquare,
  Edit3,
  KeyRound,
  Link2,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Shield,
  Sparkles,
  Trash2,
} from 'lucide-react';
import { api, ApiError, buildAdminSubUrl, buildUserSubUrl } from '../../api/client';
import type {
  AdminTrafficResponse,
  NodeDTO,
  SubMode,
  SubTarget,
  SubTemplate,
  UserDTO,
  UserTrafficBreakdownResponse,
} from '../../types/api';
import { useToast } from '../../contexts/ToastContext';
import { Modal } from '../../components/Modal';
import { CopyButton } from '../../components/CopyButton';
import { ByteSizeInput } from '../../components/ByteSizeInput';
import { NumericInput } from '../../components/NumericInput';
import {
  formatBytes,
  formatDateTime,
  localDateTimeToRFC3339,
  randomHex,
  toLocalDateTimeInput,
} from '../../utils/format';

export function UsersPage() {
  const toast = useToast();
  const [users, setUsers] = useState<UserDTO[]>([]);
  const [nodes, setNodes] = useState<NodeDTO[]>([]);
  const ssEnabledNodes = useMemo(
    () => nodes.filter((n) => Boolean(n.ss_config?.enabled)),
    [nodes]
  );
  const ssEnabledNodeIdSet = useMemo(
    () => new Set(ssEnabledNodes.map((n) => n.id)),
    [ssEnabledNodes]
  );
  const [templates, setTemplates] = useState<SubTemplate[]>([]);
  const [adminTraffic, setAdminTraffic] = useState<AdminTrafficResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // Admin Surge subscription modal & settings
  const [adminSubModalOpen, setAdminSubModalOpen] = useState(false);
  const [adminBreakdownOpen, setAdminBreakdownOpen] = useState(false);
  const [adminSubToken, setAdminSubToken] = useState('');
  const [adminSubTokenSaving, setAdminSubTokenSaving] = useState(false);
  const [adminMode, setAdminMode] = useState<SubMode>('full');
  const [adminTplId, setAdminTplId] = useState<string>('');
  const [adminPreview, setAdminPreview] = useState<string | null>(null);
  const [adminPreviewLoading, setAdminPreviewLoading] = useState(false);

  // Create/Edit Modal
  const [editOpen, setEditOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<UserDTO | null>(null);
  const [username, setUsername] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [quotaBytes, setQuotaBytes] = useState(0);
  const [resetDay, setResetDay] = useState(1);
  const [expireInput, setExpireInput] = useState('');
  const [selectedNodeIds, setSelectedNodeIds] = useState<number[]>([]);
  const [saving, setSaving] = useState(false);

  // Node Access Matrix Modal
  const [matrixUser, setMatrixUser] = useState<UserDTO | null>(null);
  const [matrixNodeIds, setMatrixNodeIds] = useState<number[]>([]);
  const [matrixSaving, setMatrixSaving] = useState(false);

  // Reset Keys Modal
  const [keysUser, setKeysUser] = useState<UserDTO | null>(null);
  const [resetSubToken, setResetSubToken] = useState(false);
  const [keysBusy, setKeysBusy] = useState(false);

  // Subscription Copy & Preview Modal
  const [subUser, setSubUser] = useState<UserDTO | null>(null);
  const [subTarget, setSubTarget] = useState<SubTarget>('mihomo');
  const [subMode, setSubMode] = useState<SubMode>('full');
  const [subTplId, setSubTplId] = useState<string>('');
  const [subPreview, setSubPreview] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  // User Traffic Breakdown Modal
  const [breakdownUser, setBreakdownUser] = useState<UserDTO | null>(null);
  const [breakdownData, setBreakdownData] = useState<UserTrafficBreakdownResponse | null>(null);
  const [breakdownLoading, setBreakdownLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [uList, nList, tList, settings, adminTraf] = await Promise.all([
        api.listUsers(),
        api.listNodes(),
        api.listTemplates(),
        api.getSettings(),
        api.getAdminTraffic(),
      ]);
      setUsers(uList);
      setNodes(nList);
      setTemplates(tList);
      setAdminSubToken(settings.admin_sub_token);
      setAdminTraffic(adminTraf);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载用户数据失败');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleSaveAdminToken = async (nextToken?: string) => {
    const token = (nextToken ?? adminSubToken).trim();
    if (!token || /\s/.test(token)) {
      toast.error('管理员订阅 Token 不能为空且不能包含空格');
      return;
    }
    setAdminSubTokenSaving(true);
    try {
      const updated = await api.updateSettings({ admin_sub_token: token });
      setAdminSubToken(updated.admin_sub_token);
      setAdminPreview(null);
      toast.success('管理员订阅 Token 已更新');
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '保存管理员订阅 Token 失败');
    } finally {
      setAdminSubTokenSaving(false);
    }
  };

  const handlePreviewAdminSub = async () => {
    if (adminPreview !== null) {
      setAdminPreview(null);
      return;
    }
    if (!adminSubUrl) return;
    setAdminPreviewLoading(true);
    try {
      const res = await fetch(adminSubUrl);
      const txt = await res.text();
      setAdminPreview(`HTTP ${res.status}\n${txt}`);
    } catch (err) {
      setAdminPreview(err instanceof Error ? err.message : '预览请求失败');
    } finally {
      setAdminPreviewLoading(false);
    }
  };

  const handleResetAdminTraffic = async () => {
    if (!window.confirm('确定将管理员 (Snell) 在各节点的已用流量记录清零吗？')) return;
    try {
      await api.resetAdminTraffic();
      toast.success('已清零管理员流量统计');
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '清零管理员流量失败');
    }
  };

  const openTrafficBreakdown = async (u: UserDTO) => {
    setBreakdownUser(u);
    setBreakdownData(null);
    setBreakdownLoading(true);
    try {
      const data = await api.getUserTrafficBreakdown(u.id);
      setBreakdownData(data);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载节点流量明细失败');
      setBreakdownUser(null);
    } finally {
      setBreakdownLoading(false);
    }
  };

  const openCreate = () => {
    setEditingUser(null);
    setUsername('');
    setEnabled(true);
    setQuotaBytes(0);
    setResetDay(1);
    setExpireInput('');
    setSelectedNodeIds(ssEnabledNodes.map((n) => n.id));
    setEditOpen(true);
  };

  const openEdit = (u: UserDTO) => {
    setEditingUser(u);
    setUsername(u.username);
    setEnabled(u.enabled);
    setQuotaBytes(u.traffic_quota_bytes);
    setResetDay(u.billing_reset_day);
    setExpireInput(toLocalDateTimeInput(u.expire_at));
    setSelectedNodeIds((u.node_ids || []).filter((id) => ssEnabledNodeIdSet.has(id)));
    setEditOpen(true);
  };

  const handleSaveUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim()) {
      toast.error('请填写用户名');
      return;
    }
    if (!Number.isInteger(resetDay) || resetDay < 0 || resetDay > 31) {
      toast.error('账单重置日必须为 0 到 31 之间的整数');
      return;
    }
    const expireAt = expireInput.trim() ? localDateTimeToRFC3339(expireInput) : null;
    if (expireInput.trim() && expireAt === null) {
      toast.error('过期时间格式无效');
      return;
    }

    const filteredNodeIds = selectedNodeIds.filter((id) => ssEnabledNodeIdSet.has(id));
    setSaving(true);
    try {
      if (editingUser === null) {
        await api.createUser({
          username: username.trim(),
          enabled,
          traffic_quota_bytes: quotaBytes,
          billing_reset_day: resetDay,
          expire_at: expireAt,
          node_ids: filteredNodeIds,
        });
        toast.success(`已创建用户 "${username.trim()}"`);
      } else {
        const hiddenDisabledIds = (editingUser.node_ids || []).filter(
          (id) => !ssEnabledNodeIdSet.has(id)
        );
        const mergedNodeIds = Array.from(new Set([...filteredNodeIds, ...hiddenDisabledIds]));
        await api.updateUser(editingUser.id, {
          username: username.trim(),
          enabled,
          traffic_quota_bytes: quotaBytes,
          billing_reset_day: resetDay,
          expire_at: expireAt,
          node_ids: mergedNodeIds,
        });
        toast.success(`已更新用户 "${username.trim()}"`);
      }
      setEditOpen(false);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '保存用户失败');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (u: UserDTO) => {
    if (!window.confirm(`确定删除用户 "${u.username}" 吗？`)) return;
    try {
      await api.deleteUser(u.id);
      toast.success(`已删除用户 "${u.username}"`);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '删除用户失败');
    }
  };

  const handleResetTraffic = async (u: UserDTO) => {
    if (!window.confirm(`确定将 "${u.username}" 的已用流量和节点明细清零吗？`)) return;
    try {
      await api.resetUserTraffic(u.id);
      toast.success(`已重置 "${u.username}" 的已用流量`);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '重置用户流量失败');
    }
  };

  const handleSaveMatrix = async () => {
    if (!matrixUser) return;
    setMatrixSaving(true);
    try {
      const filteredNodeIds = matrixNodeIds.filter((id) => ssEnabledNodeIdSet.has(id));
      const hiddenDisabledIds = (matrixUser.node_ids || []).filter(
        (id) => !ssEnabledNodeIdSet.has(id)
      );
      const mergedNodeIds = Array.from(new Set([...filteredNodeIds, ...hiddenDisabledIds]));
      await api.setUserNodes(matrixUser.id, mergedNodeIds);
      toast.success(`已更新 "${matrixUser.username}" 的可用节点权限`);
      setMatrixUser(null);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '更新节点权限失败');
    } finally {
      setMatrixSaving(false);
    }
  };

  const handleResetKeys = async () => {
    if (!keysUser) return;
    setKeysBusy(true);
    try {
      await api.resetUserKeys(keysUser.id, {
        reset_sub_token: resetSubToken,
        reset_upsk: true,
        reset_stls_password: true,
      });
      toast.success(`已重置 "${keysUser.username}" 的密钥凭证`);
      setKeysUser(null);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '重置密钥失败');
    } finally {
      setKeysBusy(false);
    }
  };

  const toggleInArray = (arr: number[], id: number): number[] => {
    const clicked = nodes.find((n) => n.id === id);
    if (clicked?.lb_group_id) {
      const groupSSIds = ssEnabledNodes
        .filter((n) => n.lb_group_id === clicked.lb_group_id)
        .map((n) => n.id);
      if (groupSSIds.length > 0) {
        const removing = arr.includes(id);
        if (removing) {
          const groupSet = new Set(groupSSIds);
          return arr.filter((x) => !groupSet.has(x));
        }
        return Array.from(new Set([...arr, ...groupSSIds]));
      }
    }
    return arr.includes(id) ? arr.filter((x) => x !== id) : [...arr, id];
  };

  const adminSurgeTemplates = templates.filter((t) => t.client_type === 'surge_admin');
  const adminSubUrl = adminSubToken
    ? buildAdminSubUrl(adminSubToken, adminMode, adminTplId ? Number(adminTplId) : null)
    : '';
  const snellNodesCount = nodes.filter((n) => n.enabled && n.snell_config?.enabled).length;
  const adminUsedBytes = adminTraffic?.total_bytes ?? 0;

  const matchingTemplates = templates.filter((t) =>
    subTarget === 'mihomo'
      ? t.client_type === 'mihomo_user'
      : subTarget === 'surge'
        ? t.client_type === 'surge_user'
        : false
  );

  const subUrl = subUser
    ? buildUserSubUrl(
        subUser.sub_token,
        subTarget,
        subMode,
        subTarget !== 'shadowrocket' && subTplId ? Number(subTplId) : null
      )
    : '';

  const handlePreviewSub = async () => {
    if (subPreview !== null) {
      setSubPreview(null);
      return;
    }
    if (!subUrl) return;
    setPreviewLoading(true);
    try {
      const res = await fetch(subUrl);
      const txt = await res.text();
      setSubPreview(`HTTP ${res.status}\n${txt}`);
    } catch (err) {
      setSubPreview(err instanceof Error ? err.message : '预览请求失败');
    } finally {
      setPreviewLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="admin-sticky-header flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white">用户与订阅管理</h1>
          <p className="hidden text-sm text-slate-500 dark:text-slate-400 sm:block">
            统一管理管理员专属 Snell 通道与 SS2022 用户的配额、节点授权及订阅配置
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={() => void load()} className="btn-secondary" disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            刷新
          </button>
          <button type="button" onClick={openCreate} className="btn-primary">
            <Plus className="h-4 w-4" />
            添加用户
          </button>
        </div>
      </div>

      {/* Mobile Cards (Admin + Regular Users) */}
      <div className="space-y-3 md:hidden">
        {/* Pinned Admin Mobile Card */}
        <div className="card space-y-3 border-indigo-200/80 bg-indigo-50/30 p-4 dark:border-indigo-900/60 dark:bg-indigo-950/20">
          <div className="flex items-start justify-between gap-2">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center gap-1 rounded-md bg-indigo-100 px-2 py-0.5 text-[11px] font-semibold text-indigo-700 dark:bg-indigo-950/80 dark:text-indigo-300">
                  <Shield className="h-3 w-3" />
                  管理员
                </span>
              </div>
              <div className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                Snell + ShadowTLS v3 专属通道
              </div>
            </div>
            <span className="inline-flex whitespace-nowrap rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300">
              正常
            </span>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-white/80 px-3 py-2 text-xs dark:bg-slate-900/70">
            <button
              type="button"
              onClick={() => setAdminBreakdownOpen(true)}
              className="inline-flex items-center gap-1.5 font-mono text-indigo-600 underline decoration-dotted underline-offset-4 dark:text-indigo-400"
            >
              <BarChart3 className="h-3.5 w-3.5" />
              <span>{formatBytes(adminUsedBytes)} / 不限</span>
            </button>
            <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
              Snell 节点 {snellNodesCount} / {nodes.length}
            </span>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200/70 pt-2.5 text-xs dark:border-slate-800">
            <span className="text-[11px] text-slate-500 dark:text-slate-400">永不过期 · 不自动重置</span>
            <div className="flex flex-wrap gap-1.5">
              <button
                type="button"
                onClick={() => {
                  setAdminPreview(null);
                  setAdminSubModalOpen(true);
                }}
                className="btn-secondary px-2.5 py-1 text-xs"
              >
                <Link2 className="h-3.5 w-3.5" />
                订阅
              </button>
              <button
                type="button"
                onClick={() => void handleResetAdminTraffic()}
                className="btn-secondary px-2.5 py-1 text-xs"
                title="清零管理员流量统计"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                清零
              </button>
            </div>
          </div>
        </div>

        {users.length === 0 && !loading ? (
          <div className="card flex flex-col items-center justify-center py-10 text-center">
            <p className="text-sm font-medium text-slate-700 dark:text-slate-300">暂无普通用户</p>
            <button type="button" onClick={openCreate} className="btn-primary mt-3 text-xs">
              <Plus className="h-4 w-4" /> 添加第一个用户
            </button>
          </div>
        ) : (
          users.map((u) => {
            const used = u.used_up_bytes + u.used_down_bytes;
            const pct =
              u.traffic_quota_bytes > 0
                ? Math.min(100, (used / u.traffic_quota_bytes) * 100)
                : 0;
            const expired = u.expire_at ? new Date(u.expire_at).getTime() <= Date.now() : false;
            const authorizedSSNodeIds = (u.node_ids || []).filter((id) => ssEnabledNodeIdSet.has(id));
            return (
              <div key={u.id} className="card space-y-3 p-4">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">{u.username}</span>
                      <span className="font-mono text-[11px] text-slate-400">#{u.id}</span>
                    </div>
                    <div className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                      {u.billing_reset_day === 0 ? '不自动重置' : `每月 ${u.billing_reset_day} 日重置`} ·{' '}
                      {u.expire_at ? `到期 ${formatDateTime(u.expire_at)}` : '永不过期'}
                    </div>
                  </div>
                  {!u.enabled ? (
                    <span className="inline-flex whitespace-nowrap rounded-full bg-slate-200 px-2.5 py-0.5 text-xs font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-400">
                      已禁用
                    </span>
                  ) : expired ? (
                    <span className="inline-flex whitespace-nowrap rounded-full bg-rose-100 px-2.5 py-0.5 text-xs font-medium text-rose-700 dark:bg-rose-950/70 dark:text-rose-300">
                      已过期
                    </span>
                  ) : (
                    <span className="inline-flex whitespace-nowrap rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300">
                      正常
                    </span>
                  )}
                </div>

                <div className="space-y-1.5 rounded-lg bg-slate-50 p-3 text-xs dark:bg-slate-800/60">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={() => void openTrafficBreakdown(u)}
                      className="inline-flex items-center gap-1.5 font-mono text-indigo-600 underline decoration-dotted underline-offset-4 dark:text-indigo-400"
                    >
                      <BarChart3 className="h-3.5 w-3.5" />
                      <span>
                        {formatBytes(used)} /{' '}
                        {u.traffic_quota_bytes === 0 ? '不限' : formatBytes(u.traffic_quota_bytes)}
                      </span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setMatrixUser(u);
                        setMatrixNodeIds(authorizedSSNodeIds);
                      }}
                      className="inline-flex items-center gap-1 rounded border border-slate-200 bg-white px-2 py-0.5 text-[11px] font-medium dark:border-slate-700 dark:bg-slate-900"
                    >
                      <CheckSquare className="h-3 w-3 text-indigo-500" />
                      {authorizedSSNodeIds.length} / {ssEnabledNodes.length}
                    </button>
                  </div>
                  {u.traffic_quota_bytes > 0 && (
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
                      <div
                        className={`h-full rounded-full ${pct >= 95 ? 'bg-rose-500' : 'bg-indigo-500'}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  )}
                </div>

                <div className="flex flex-wrap justify-end gap-1.5 border-t border-slate-100 pt-2.5 dark:border-slate-800">
                  <button
                    type="button"
                    onClick={() => {
                      setSubUser(u);
                      setSubTarget('mihomo');
                      setSubMode('full');
                      setSubTplId('');
                      setSubPreview(null);
                    }}
                    className="btn-secondary px-2.5 py-1 text-xs"
                  >
                    <Link2 className="h-3.5 w-3.5" />
                    订阅
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setKeysUser(u);
                      setResetSubToken(false);
                    }}
                    className="btn-secondary px-2.5 py-1 text-xs"
                  >
                    <KeyRound className="h-3.5 w-3.5" />
                    密钥
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleResetTraffic(u)}
                    className="btn-secondary px-2 py-1 text-xs"
                    title="清零已用流量"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => openEdit(u)}
                    className="btn-secondary px-2 py-1 text-xs"
                    title="编辑用户"
                  >
                    <Edit3 className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleDelete(u)}
                    className="btn-danger px-2 py-1 text-xs"
                    title="删除用户"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Desktop Table (Pinned Admin Row + Regular Users) */}
      <div className="card hidden overflow-hidden md:block">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
            <thead className="bg-slate-50 text-left text-xs font-semibold text-slate-500 dark:bg-slate-800/50 dark:text-slate-400">
              <tr>
                <th className="px-4 py-3">用户</th>
                <th className="px-4 py-3">状态</th>
                <th className="px-4 py-3">已用流量 / 配额（点击查明细）</th>
                <th className="px-4 py-3">重置日</th>
                <th className="px-4 py-3">到期时间</th>
                <th className="px-4 py-3">可用节点</th>
                <th className="px-4 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {/* Pinned Admin Row */}
              <tr className="bg-indigo-50/40 hover:bg-indigo-50/70 dark:bg-indigo-950/20 dark:hover:bg-indigo-950/35">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <span className="inline-flex items-center gap-1 rounded-md bg-indigo-100 px-1.5 py-0.5 text-[11px] font-semibold text-indigo-700 dark:bg-indigo-950/80 dark:text-indigo-300">
                      <Shield className="h-3 w-3" />
                      管理员
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">Snell + ShadowTLS v3</div>
                </td>
                <td className="px-4 py-3">
                  <span className="inline-flex whitespace-nowrap rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300">
                    正常
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-xs">
                  <button
                    type="button"
                    onClick={() => setAdminBreakdownOpen(true)}
                    className="group text-left hover:text-indigo-600 dark:hover:text-indigo-400"
                    title="点击查看管理员各节点 Snell 流量使用分布"
                  >
                    <div className="inline-flex items-center gap-1.5 underline decoration-dotted underline-offset-4">
                      <BarChart3 className="h-3.5 w-3.5 text-indigo-500 opacity-75 group-hover:opacity-100" />
                      <span>{formatBytes(adminUsedBytes)} / 不限</span>
                    </div>
                  </button>
                </td>
                <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">不自动重置</td>
                <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">永不过期</td>
                <td className="px-4 py-3">
                  <span className="inline-flex whitespace-nowrap items-center gap-1 rounded-lg border border-indigo-200 bg-white/80 px-2 py-1 text-xs font-medium text-indigo-700 dark:border-indigo-900 dark:bg-slate-900/70 dark:text-indigo-300">
                    <Shield className="h-3.5 w-3.5" />
                    {snellNodesCount} / {nodes.length} (Snell)
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap justify-end gap-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        setAdminPreview(null);
                        setAdminSubModalOpen(true);
                      }}
                      className="btn-secondary px-2 py-1 text-xs"
                    >
                      <Link2 className="h-3.5 w-3.5" />
                      订阅
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleResetAdminTraffic()}
                      className="btn-secondary px-2 py-1 text-xs"
                      title="清零管理员流量统计"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </td>
              </tr>

              {users.length === 0 && !loading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-xs text-slate-500">
                    暂无普通用户，点击右上角“添加用户”创建多用户 SS2022 订阅账号。
                  </td>
                </tr>
              ) : (
                users.map((u) => {
                  const used = u.used_up_bytes + u.used_down_bytes;
                  const pct =
                    u.traffic_quota_bytes > 0
                      ? Math.min(100, (used / u.traffic_quota_bytes) * 100)
                      : 0;
                  const expired = u.expire_at ? new Date(u.expire_at).getTime() <= Date.now() : false;
                  return (
                    <tr key={u.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                      <td className="px-4 py-3">
                        <div className="font-semibold text-slate-900 dark:text-white">{u.username}</div>
                        <div className="font-mono text-[11px] text-slate-400">#{u.id}</div>
                      </td>
                      <td className="px-4 py-3">
                        {!u.enabled ? (
                          <span className="inline-flex whitespace-nowrap rounded-full bg-slate-200 px-2.5 py-0.5 text-xs font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-400">
                            已禁用
                          </span>
                        ) : expired ? (
                          <span className="inline-flex whitespace-nowrap rounded-full bg-rose-100 px-2.5 py-0.5 text-xs font-medium text-rose-700 dark:bg-rose-950/70 dark:text-rose-300">
                            已过期
                          </span>
                        ) : (
                          <span className="inline-flex whitespace-nowrap rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300">
                            正常
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">
                        <button
                          type="button"
                          onClick={() => void openTrafficBreakdown(u)}
                          className="group text-left hover:text-indigo-600 dark:hover:text-indigo-400"
                          title="点击查看各节点流量使用分布"
                        >
                          <div className="inline-flex items-center gap-1.5 underline decoration-dotted underline-offset-4">
                            <BarChart3 className="h-3.5 w-3.5 text-indigo-500 opacity-75 group-hover:opacity-100" />
                            <span>
                              {formatBytes(used)} /{' '}
                              {u.traffic_quota_bytes === 0 ? '不限' : formatBytes(u.traffic_quota_bytes)}
                            </span>
                          </div>
                          {u.traffic_quota_bytes > 0 && (
                            <div className="mt-1 h-1.5 w-32 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
                              <div
                                className={`h-full rounded-full ${pct >= 95 ? 'bg-rose-500' : 'bg-indigo-500'}`}
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          )}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-xs">
                        {u.billing_reset_day === 0 ? '不自动重置' : `每月 ${u.billing_reset_day} 日`}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">
                        {u.expire_at ? formatDateTime(u.expire_at) : '永不过期'}
                      </td>
                      <td className="px-4 py-3">
                        {(() => {
                          const tableAuthorizedSSIds = (u.node_ids || []).filter((id) =>
                            ssEnabledNodeIdSet.has(id)
                          );
                          return (
                            <button
                              type="button"
                              onClick={() => {
                                setMatrixUser(u);
                                setMatrixNodeIds(tableAuthorizedSSIds);
                              }}
                              className="inline-flex whitespace-nowrap items-center gap-1 rounded-lg border border-slate-200 px-2 py-1 text-xs font-medium hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
                            >
                              <CheckSquare className="h-3.5 w-3.5 text-indigo-500" />
                              {tableAuthorizedSSIds.length} / {ssEnabledNodes.length}
                            </button>
                          );
                        })()}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => {
                              setSubUser(u);
                              setSubTarget('mihomo');
                              setSubMode('full');
                              setSubTplId('');
                              setSubPreview(null);
                            }}
                            className="btn-secondary px-2 py-1 text-xs"
                          >
                            <Link2 className="h-3.5 w-3.5" />
                            订阅
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setKeysUser(u);
                              setResetSubToken(false);
                            }}
                            className="btn-secondary px-2 py-1 text-xs"
                          >
                            <KeyRound className="h-3.5 w-3.5" />
                            密钥
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleResetTraffic(u)}
                            className="btn-secondary px-2 py-1 text-xs"
                            title="清零已用流量"
                          >
                            <RotateCcw className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => openEdit(u)}
                            className="btn-secondary px-2 py-1 text-xs"
                            title="编辑用户"
                          >
                            <Edit3 className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleDelete(u)}
                            className="btn-danger px-2 py-1 text-xs"
                            title="删除用户"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Admin Surge Subscription Config Modal */}
      <Modal
        open={adminSubModalOpen}
        onClose={() => setAdminSubModalOpen(false)}
        title="管理员专属 Surge 订阅设置"
        subtitle="仅包含已启用 Snell + ShadowTLS v3 协议节点，不会下发给普通用户。"
        maxWidthClass="max-w-2xl"
        footer={
          <button type="button" onClick={() => setAdminSubModalOpen(false)} className="btn-primary">
            关闭
          </button>
        }
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium">输出模式</label>
              <select
                className="input-field"
                value={adminMode}
                onChange={(e) => {
                  setAdminMode(e.target.value as SubMode);
                  setAdminPreview(null);
                }}
              >
                <option value="full">full（完整托管配置 #!MANAGED-CONFIG）</option>
                <option value="proxy">proxy（仅 Snell 节点列表）</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">Admin Surge 模板</label>
              <select
                className="input-field"
                value={adminTplId}
                onChange={(e) => {
                  setAdminTplId(e.target.value);
                  setAdminPreview(null);
                }}
              >
                <option value="">默认 surge_admin 模板</option>
                {adminSurgeTemplates.map((t) => (
                  <option key={t.id} value={String(t.id)}>
                    {t.name} {t.is_default ? '(默认)' : ''}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium">管理员订阅 Token</label>
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                type="text"
                className="input-field font-mono text-xs"
                value={adminSubToken}
                onChange={(e) => {
                  setAdminSubToken(e.target.value);
                  setAdminPreview(null);
                }}
              />
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={adminSubTokenSaving}
                  onClick={() => {
                    const next = `adm_${randomHex(16)}`;
                    setAdminSubToken(next);
                    void handleSaveAdminToken(next);
                  }}
                  className="btn-secondary flex-1 sm:flex-none px-2.5 text-xs"
                  title="随机生成并保存新 Token"
                >
                  <Sparkles className="h-3.5 w-3.5" />
                  重置
                </button>
                <button
                  type="button"
                  disabled={adminSubTokenSaving}
                  onClick={() => void handleSaveAdminToken()}
                  className="btn-primary flex-1 sm:flex-none px-2.5 text-xs"
                  title="保存手动修改的 Token"
                >
                  <Save className="h-3.5 w-3.5" />
                  保存
                </button>
              </div>
            </div>
          </div>

          {adminSubUrl && (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-800/60">
              <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-600 dark:text-slate-300">
                  Admin Surge 订阅地址
                </span>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => void handlePreviewAdminSub()}
                    disabled={adminPreviewLoading}
                    className="btn-secondary px-2.5 py-1 text-xs"
                  >
                    {adminPreviewLoading ? '加载中...' : adminPreview !== null ? '收起预览' : '预览输出'}
                  </button>
                  <CopyButton text={adminSubUrl} label="复制链接" />
                </div>
              </div>
              <code className="block break-all font-mono text-xs text-indigo-600 dark:text-indigo-400">
                {adminSubUrl}
              </code>
            </div>
          )}

          {adminPreview !== null && (
            <pre className="max-h-64 overflow-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-100">
              {adminPreview}
            </pre>
          )}
        </div>
      </Modal>

      {/* Admin Traffic Breakdown Modal */}
      <Modal
        open={adminBreakdownOpen}
        onClose={() => setAdminBreakdownOpen(false)}
        title="管理员节点流量明细"
        subtitle="基于各节点 snell-server 进程实际转发统计（按累计消耗由高到低排序）。"
        maxWidthClass="max-w-2xl"
        footer={
          <button type="button" onClick={() => setAdminBreakdownOpen(false)} className="btn-primary">
            关闭
          </button>
        }
      >
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 rounded-xl bg-slate-50 p-3.5 text-xs dark:bg-slate-800/60">
            <div>
              <span className="text-slate-400">管理员 Snell 累计流量</span>
              <p className="mt-0.5 font-mono text-sm font-bold text-slate-900 dark:text-white">
                {formatBytes(adminUsedBytes)}
              </p>
            </div>
            <div>
              <span className="text-slate-400">记录节点数</span>
              <p className="mt-0.5 font-mono text-sm font-bold text-indigo-600 dark:text-indigo-400">
                {adminTraffic?.items.length ?? 0} 个节点
              </p>
            </div>
          </div>

          {!adminTraffic || adminTraffic.items.length === 0 ? (
            <div className="rounded-xl border border-slate-200 px-4 py-8 text-center text-xs text-slate-500 dark:border-slate-800">
              暂无管理员 Snell 节点使用记录（清零后或尚未使用 Snell 节点时为空）。
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
              <table className="min-w-full divide-y divide-slate-200 text-xs dark:divide-slate-800">
                <thead className="bg-slate-50 text-left font-semibold text-slate-500 dark:bg-slate-800/60 dark:text-slate-400">
                  <tr>
                    <th className="px-3.5 py-2.5">节点</th>
                    <th className="px-3.5 py-2.5">已用流量</th>
                    <th className="px-3.5 py-2.5">占比</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {adminTraffic.items.map((item) => {
                    const denom = adminUsedBytes > 0 ? adminUsedBytes : item.total_bytes;
                    const sharePct = denom > 0 ? Math.min(100, (item.total_bytes / denom) * 100) : 0;
                    return (
                      <tr key={item.node_id}>
                        <td className="px-3.5 py-2.5 font-medium text-slate-900 dark:text-white">
                          {item.node_name}
                          {item.region_tag && (
                            <span className="ml-1.5 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] uppercase text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                              {item.region_tag}
                            </span>
                          )}
                        </td>
                        <td className="px-3.5 py-2.5 font-mono font-semibold text-slate-800 dark:text-slate-200">
                          {formatBytes(item.total_bytes)}
                        </td>
                        <td className="w-40 px-3.5 py-2.5">
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                              <div
                                className="h-full rounded-full bg-indigo-500"
                                style={{ width: `${Math.max(3, sharePct)}%` }}
                              />
                            </div>
                            <span className="w-11 text-right font-mono text-[11px] text-slate-500">
                              {sharePct.toFixed(1)}%
                            </span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Modal>

      {/* User Traffic Breakdown Modal */}
      <Modal
        open={Boolean(breakdownUser)}
        onClose={() => setBreakdownUser(null)}
        title={`节点流量使用明细 — ${breakdownUser?.username ?? ''}`}
        subtitle="按当前统计周期内各节点累计消耗流量由高到低排序。"
        maxWidthClass="max-w-2xl"
        footer={
          <button type="button" onClick={() => setBreakdownUser(null)} className="btn-primary">
            关闭
          </button>
        }
      >
        {breakdownLoading ? (
          <p className="py-8 text-center text-sm text-slate-500">正在加载流量明细...</p>
        ) : breakdownData ? (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-2 sm:gap-3 rounded-xl bg-slate-50 p-3 sm:p-3.5 text-xs dark:bg-slate-800/60">
              <div>
                <span className="text-slate-400">总下载</span>
                <p className="mt-0.5 font-mono text-sm font-bold text-emerald-600 dark:text-emerald-400">
                  {formatBytes(breakdownData.total_down_bytes)}
                </p>
              </div>
              <div>
                <span className="text-slate-400">总上传</span>
                <p className="mt-0.5 font-mono text-sm font-bold text-indigo-600 dark:text-indigo-400">
                  {formatBytes(breakdownData.total_up_bytes)}
                </p>
              </div>
              <div>
                <span className="text-slate-400">用户已用合计</span>
                <p className="mt-0.5 font-mono text-sm font-bold text-slate-900 dark:text-white">
                  {formatBytes(breakdownData.total_bytes)}
                </p>
              </div>
            </div>

            {breakdownData.items.length === 0 ? (
              <div className="rounded-xl border border-slate-200 px-4 py-8 text-center text-xs text-slate-500 dark:border-slate-800">
                暂无按节点区分的使用记录（清零流量后或尚未产生代理流量时为空）。
              </div>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
                <table className="min-w-full divide-y divide-slate-200 text-xs dark:divide-slate-800">
                  <thead className="bg-slate-50 text-left font-semibold text-slate-500 dark:bg-slate-800/60 dark:text-slate-400">
                    <tr>
                      <th className="px-3.5 py-2.5">节点</th>
                      <th className="px-3.5 py-2.5">下载</th>
                      <th className="px-3.5 py-2.5">上传</th>
                      <th className="px-3.5 py-2.5">总计</th>
                      <th className="px-3.5 py-2.5">占比</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {breakdownData.items.map((item) => {
                      const denom = breakdownData.total_bytes > 0 ? breakdownData.total_bytes : item.total_bytes;
                      const sharePct = denom > 0 ? Math.min(100, (item.total_bytes / denom) * 100) : 0;
                      return (
                        <tr key={item.node_id}>
                          <td className="px-3.5 py-2.5 font-medium text-slate-900 dark:text-white">
                            {item.node_name}
                            {item.region_tag && (
                              <span className="ml-1.5 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] uppercase text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                                {item.region_tag}
                              </span>
                            )}
                          </td>
                          <td className="px-3.5 py-2.5 font-mono text-emerald-600 dark:text-emerald-400">
                            {formatBytes(item.down_bytes)}
                          </td>
                          <td className="px-3.5 py-2.5 font-mono text-indigo-600 dark:text-indigo-400">
                            {formatBytes(item.up_bytes)}
                          </td>
                          <td className="px-3.5 py-2.5 font-mono font-semibold text-slate-800 dark:text-slate-200">
                            {formatBytes(item.total_bytes)}
                          </td>
                          <td className="w-36 px-3.5 py-2.5">
                            <div className="flex items-center gap-2">
                              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                                <div
                                  className="h-full rounded-full bg-indigo-500"
                                  style={{ width: `${Math.max(3, sharePct)}%` }}
                                />
                              </div>
                              <span className="w-11 text-right font-mono text-[11px] text-slate-500">
                                {sharePct.toFixed(1)}%
                              </span>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ) : null}
      </Modal>

      {/* Create/Edit User Modal */}
      <Modal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title={editingUser === null ? '添加用户' : `编辑用户 — ${editingUser.username}`}
        footer={
          <>
            <button type="button" onClick={() => setEditOpen(false)} className="btn-secondary">
              取消
            </button>
            <button type="submit" form="user-form" disabled={saving} className="btn-primary">
              {saving ? '保存中...' : '保存用户'}
            </button>
          </>
        }
      >
        <form id="user-form" onSubmit={handleSaveUser} className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium">用户名 *</label>
              <input
                type="text"
                className="input-field"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">月度流量重置日（0 = 关闭，1–31）</label>
              <NumericInput
                min={0}
                max={31}
                className="input-field"
                value={resetDay}
                onChange={setResetDay}
                required
              />
            </div>
          </div>

          <ByteSizeInput
            label="流量配额"
            value={quotaBytes}
            onChange={setQuotaBytes}
            zeroText="0 = 无限流量配额"
          />

          <div>
            <div className="mb-1 flex items-center justify-between">
              <label className="text-xs font-medium">过期时间（可选）</label>
              {expireInput && (
                <button
                  type="button"
                  onClick={() => setExpireInput('')}
                  className="text-xs text-indigo-600 hover:underline dark:text-indigo-400"
                >
                  清除（设为永不过期）
                </button>
              )}
            </div>
            <input
              type="datetime-local"
              className="input-field"
              value={expireInput}
              onChange={(e) => setExpireInput(e.target.value)}
            />
          </div>

          <label className="flex items-center gap-2 text-sm font-medium">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-slate-300 text-indigo-600"
            />
            启用该用户
          </label>

          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <label className="text-xs font-medium">已授权节点（{selectedNodeIds.length}）</label>
              <div className="flex gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => setSelectedNodeIds(ssEnabledNodes.map((n) => n.id))}
                  className="text-indigo-600 hover:underline dark:text-indigo-400"
                >
                  全选
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedNodeIds([])}
                  className="text-slate-500 hover:underline"
                >
                  清空
                </button>
              </div>
            </div>
            <div className="grid max-h-40 grid-cols-1 gap-1.5 overflow-y-auto rounded-lg border border-slate-200 p-2.5 dark:border-slate-800 sm:grid-cols-2">
              {ssEnabledNodes.length === 0 ? (
                <div className="col-span-full py-2 text-center text-xs text-slate-400">
                  暂无已启用 sing-box 用户通道的可用节点
                </div>
              ) : (
                ssEnabledNodes.map((n) => (
                  <label key={n.id} className="flex items-center justify-between gap-2 rounded px-1.5 py-1 text-xs hover:bg-slate-50 dark:hover:bg-slate-800">
                    <span className="flex min-w-0 items-center gap-2">
                      <input
                        type="checkbox"
                        checked={selectedNodeIds.includes(n.id)}
                        onChange={() => setSelectedNodeIds((prev) => toggleInArray(prev, n.id))}
                        className="h-3.5 w-3.5 rounded border-slate-300 text-indigo-600"
                      />
                      <span className="truncate">{n.name}</span>
                    </span>
                    {n.lb_group_name && (
                      <span className="shrink-0 rounded bg-indigo-50 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 dark:bg-indigo-950/70 dark:text-indigo-300">
                        {n.lb_group_name}
                      </span>
                    )}
                  </label>
                ))
              )}
            </div>
          </div>
        </form>
      </Modal>

      {/* Node Access Matrix Modal */}
      <Modal
        open={Boolean(matrixUser)}
        onClose={() => setMatrixUser(null)}
        title={`节点访问权限 — ${matrixUser?.username ?? ''}`}
        subtitle="保存后将立即向授权节点的 sing-box 同步最新用户列表。"
        footer={
          <>
            <button type="button" onClick={() => setMatrixUser(null)} className="btn-secondary">
              取消
            </button>
            <button type="button" onClick={() => void handleSaveMatrix()} disabled={matrixSaving} className="btn-primary">
              {matrixSaving ? '保存中...' : '保存权限'}
            </button>
          </>
        }
      >
        <div className="space-y-3">
          <div className="flex justify-between text-xs">
            <span className="text-slate-500">已选择 {matrixNodeIds.length} / {ssEnabledNodes.length} 个可用节点</span>
            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => setMatrixNodeIds(ssEnabledNodes.map((n) => n.id))}
                className="text-indigo-600 hover:underline dark:text-indigo-400"
              >
                全选
              </button>
              <button
                type="button"
                onClick={() => setMatrixNodeIds([])}
                className="text-slate-500 hover:underline"
              >
                全部取消
              </button>
            </div>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {ssEnabledNodes.length === 0 ? (
              <div className="col-span-full rounded-lg border border-dashed border-slate-200 py-4 text-center text-xs text-slate-400 dark:border-slate-700">
                暂无已启用 sing-box 用户通道的可用节点
              </div>
            ) : (
              ssEnabledNodes.map((n) => (
                <label
                  key={n.id}
                  className="flex cursor-pointer items-center justify-between rounded-lg border border-slate-200 px-3 py-2 text-sm hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/60"
                >
                  <span className="flex min-w-0 items-center gap-2">
                    <input
                      type="checkbox"
                      checked={matrixNodeIds.includes(n.id)}
                      onChange={() => setMatrixNodeIds((prev) => toggleInArray(prev, n.id))}
                      className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                    />
                    <span className="truncate">{n.name}</span>
                  </span>
                  <span className="flex shrink-0 items-center gap-1.5">
                    {n.lb_group_name && (
                      <span className="rounded bg-indigo-50 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 dark:bg-indigo-950/70 dark:text-indigo-300">
                        {n.lb_group_name}
                      </span>
                    )}
                    {n.region_tag && (
                      <span className="text-[11px] font-mono uppercase text-slate-400">{n.region_tag}</span>
                    )}
                  </span>
                </label>
              ))
            )}
          </div>
        </div>
      </Modal>

      {/* Reset Keys Modal */}
      <Modal
        open={Boolean(keysUser)}
        onClose={() => setKeysUser(null)}
        title={`密钥凭证与重置 — ${keysUser?.username ?? ''}`}
        maxWidthClass="max-w-lg"
        footer={
          <>
            <button type="button" onClick={() => setKeysUser(null)} className="btn-secondary">
              关闭
            </button>
            <button type="button" onClick={() => void handleResetKeys()} disabled={keysBusy} className="btn-danger">
              {keysBusy ? '重置中...' : '确认重置密钥'}
            </button>
          </>
        }
      >
        {keysUser && (
          <div className="space-y-4">
            <div className="space-y-2 rounded-lg bg-slate-50 p-3 font-mono text-xs dark:bg-slate-800/70">
              <div>
                <span className="text-slate-400">16B uPSK：</span>
                <span className="break-all">{keysUser.ss_upsk_16}</span>
              </div>
              <div>
                <span className="text-slate-400">32B uPSK：</span>
                <span className="break-all">{keysUser.ss_upsk_32}</span>
              </div>
              <div>
                <span className="text-slate-400">ShadowTLS 密码：</span>
                <span className="break-all">{keysUser.stls_password}</span>
              </div>
              <div>
                <span className="text-slate-400">订阅 Token：</span>
                <span className="break-all">{keysUser.sub_token}</span>
              </div>
            </div>

            <p className="text-xs text-slate-500 dark:text-slate-400">
              重置密钥将重新生成 16B / 32B SS2022 用户密钥与 ShadowTLS 密码，并热更新至所有已授权节点。
            </p>

            <label className="flex items-center gap-2 text-sm font-medium">
              <input
                type="checkbox"
                checked={resetSubToken}
                onChange={(e) => setResetSubToken(e.target.checked)}
                className="h-4 w-4 rounded border-slate-300 text-rose-600"
              />
              同时重置订阅链接 Token（<code>reset_sub_token</code>）
            </label>
          </div>
        )}
      </Modal>

      {/* Subscription URL & Preview Modal */}
      <Modal
        open={Boolean(subUser)}
        onClose={() => setSubUser(null)}
        title={`用户订阅链接 — ${subUser?.username ?? ''}`}
        subtitle="用户订阅仅包含 SS2022 + ShadowTLS v3 节点，不会包含 Snell 管理员通道。"
        maxWidthClass="max-w-2xl"
        footer={
          <button type="button" onClick={() => setSubUser(null)} className="btn-primary">
            关闭
          </button>
        }
      >
        {subUser && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div>
                <label className="mb-1 block text-xs font-medium">客户端类型</label>
                <select
                  className="input-field"
                  value={subTarget}
                  onChange={(e) => {
                    const next = e.target.value as SubTarget;
                    setSubTarget(next);
                    setSubTplId('');
                    setSubPreview(null);
                  }}
                >
                  <option value="mihomo">Clash Meta / Mihomo</option>
                  <option value="surge">Surge</option>
                  <option value="shadowrocket">Shadowrocket</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">输出模式</label>
                <select
                  className="input-field"
                  value={subMode}
                  disabled={subTarget === 'shadowrocket'}
                  onChange={(e) => {
                    setSubMode(e.target.value as SubMode);
                    setSubPreview(null);
                  }}
                >
                  <option value="full">full（完整托管配置）</option>
                  <option value="proxy">proxy（仅节点列表）</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">规则模板</label>
                <select
                  className="input-field"
                  value={subTplId}
                  disabled={subTarget === 'shadowrocket'}
                  onChange={(e) => {
                    setSubTplId(e.target.value);
                    setSubPreview(null);
                  }}
                >
                  <option value="">默认模板</option>
                  {matchingTemplates.map((t) => (
                    <option key={t.id} value={String(t.id)}>
                      {t.name} {t.is_default ? '(默认)' : ''}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-800/60">
              <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-600 dark:text-slate-300">
                  订阅链接
                </span>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => void handlePreviewSub()}
                    disabled={previewLoading}
                    className="btn-secondary px-2.5 py-1 text-xs"
                  >
                    {previewLoading ? '加载中...' : subPreview !== null ? '收起预览' : '预览输出'}
                  </button>
                  <CopyButton text={subUrl} label="复制链接" />
                </div>
              </div>
              <code className="block break-all font-mono text-xs text-indigo-600 dark:text-indigo-400">
                {subUrl}
              </code>
            </div>

            {subPreview !== null && (
              <pre className="max-h-64 overflow-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-100">
                {subPreview}
              </pre>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
