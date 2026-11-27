import React, { useCallback, useEffect, useState } from 'react';
import { CloudDownload, Cpu, Plus, RefreshCw, Rocket, Trash2 } from 'lucide-react';
import { api, ApiError } from '../../api/client';
import type {
  KernelCatalog,
  KernelName,
  KernelUpdateBatchResult,
  NodeDTO,
} from '../../types/api';
import { useToast } from '../../contexts/ToastContext';
import { Modal } from '../../components/Modal';
import { NodeStatusBadge } from '../../components/Badge';
import { formatBytes, formatDateTime, formatKernelVersion } from '../../utils/format';

export function KernelsPage() {
  const toast = useToast();
  const [catalog, setCatalog] = useState<KernelCatalog | null>(null);
  const [nodes, setNodes] = useState<NodeDTO[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);

  // Batch update form
  const [selectedNodeIds, setSelectedNodeIds] = useState<number[]>([]);
  const [kernel, setKernel] = useState<KernelName>('sing-box');
  const [version, setVersion] = useState('');
  const [downloadUrl, setDownloadUrl] = useState('');
  const [sha256, setSha256] = useState('');
  const [updating, setUpdating] = useState(false);
  const [batchResult, setBatchResult] = useState<KernelUpdateBatchResult | null>(null);

  // Add custom snell version modal
  const [snellModalOpen, setSnellModalOpen] = useState(false);
  const [snellVer, setSnellVer] = useState('');
  const [snellAmd64, setSnellAmd64] = useState('');
  const [snellArm64, setSnellArm64] = useState('');
  const [snellSaving, setSnellSaving] = useState(false);

  const openSnellModal = () => {
    setSnellVer('');
    setSnellAmd64('');
    setSnellArm64('');
    setSnellModalOpen(true);
  };

  const closeSnellModal = () => {
    setSnellModalOpen(false);
    setSnellVer('');
    setSnellAmd64('');
    setSnellArm64('');
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [cat, nList] = await Promise.all([api.getKernels(), api.listNodes()]);
      setCatalog(cat);
      setNodes(nList);
      setVersion((prev) => {
        if (prev) return prev;
        const first = cat['sing-box']?.[0]?.version || '';
        return first;
      });
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载内核版本目录失败');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleKernelChange = (nextKernel: KernelName) => {
    setKernel(nextKernel);
    setDownloadUrl('');
    setSha256('');
    if (!catalog) {
      setVersion('');
      return;
    }
    if (nextKernel === 'sing-box') {
      setVersion(catalog['sing-box']?.[0]?.version || '');
    } else if (nextKernel === 'shadow-tls') {
      setVersion(catalog['shadow-tls']?.[0]?.version || '');
    } else {
      setVersion(catalog['snell-server']?.[0]?.version || '');
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      const cat = await api.syncKernels();
      setCatalog(cat);
      toast.success('已从 GitHub 同步最新版本信息');
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'GitHub 版本同步失败');
    } finally {
      setSyncing(false);
    }
  };

  const handleAddSnell = async (e: React.FormEvent) => {
    e.preventDefault();
    const urls: Record<string, string> = {};
    if (snellAmd64.trim()) urls.amd64 = snellAmd64.trim();
    if (snellArm64.trim()) urls.arm64 = snellArm64.trim();
    if (!snellVer.trim() || Object.keys(urls).length === 0) {
      toast.error('请填写版本号并至少提供一个架构的下载地址');
      return;
    }
    setSnellSaving(true);
    try {
      await api.addSnellVersion({ version: snellVer.trim(), urls });
      toast.success(`已添加 snell-server ${snellVer.trim()}`);
      setSnellModalOpen(false);
      setSnellVer('');
      setSnellAmd64('');
      setSnellArm64('');
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '添加 snell 版本失败');
    } finally {
      setSnellSaving(false);
    }
  };

  const handleDeleteSnell = async (ver: string) => {
    if (!window.confirm(`确定删除自定义 snell-server 版本 "${ver}" 吗？`)) return;
    try {
      await api.deleteSnellVersion(ver);
      toast.success(`已删除 snell-server ${ver}`);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '删除 snell 版本失败');
    }
  };

  const handleBatchUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedNodeIds.length === 0) {
      toast.error('请至少选择一个节点');
      return;
    }
    if (!version.trim()) {
      toast.error('请填写目标版本号');
      return;
    }
    setUpdating(true);
    setBatchResult(null);
    try {
      const res = await api.updateKernels({
        node_ids: selectedNodeIds,
        kernel,
        version: version.trim(),
        download_url: downloadUrl.trim() || undefined,
        sha256: sha256.trim() || undefined,
      });
      setBatchResult(res);
      if (res.dispatched.length > 0 && res.failed.length === 0) {
        toast.success(`已向 ${res.dispatched.length} 个节点下发 ${kernel} ${version.trim()} 更新任务`);
      } else if (res.dispatched.length > 0) {
        toast.info(
          `已向 ${res.dispatched.length} 个节点下发任务，${res.failed.length} 个节点失败或离线`
        );
      } else {
        toast.error('未成功下发到任何节点，请查看下方逐节点结果');
      }
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '内核更新请求失败');
    } finally {
      setUpdating(false);
    }
  };

  const toggleNode = (id: number) => {
    setSelectedNodeIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const availableVersions =
    !catalog
      ? []
      : kernel === 'sing-box'
        ? catalog['sing-box'].map((r) => r.version)
        : kernel === 'shadow-tls'
          ? catalog['shadow-tls'].map((r) => r.version)
          : catalog['snell-server'].map((s) => s.version);

  const nodeNameById = (id: number) => nodes.find((n) => n.id === id)?.name || `节点 #${id}`;

  return (
    <div className="space-y-6">
      <div className="admin-sticky-header flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white">内核版本管理</h1>
          <p className="hidden text-sm text-slate-500 dark:text-slate-400 sm:block">
            同步 GitHub 发布版本（sing-box / shadow-tls）、维护 snell-server 下载源并向节点批量推送升级
            {catalog?.synced_at ? ` · 上次同步：${formatDateTime(catalog.synced_at)}` : ''}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={() => void load()} className="btn-secondary" disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            刷新
          </button>
          <button type="button" onClick={() => void handleSync()} className="btn-primary" disabled={syncing}>
            <CloudDownload className={`h-4 w-4 ${syncing ? 'animate-bounce' : ''}`} />
            {syncing ? '正在同步 GitHub...' : '同步 GitHub 版本'}
          </button>
        </div>
      </div>

      {/* OTA Upgrade Dispatcher */}
      <form onSubmit={handleBatchUpdate} className="card space-y-4 p-5">
        <div className="flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
            <Rocket className="h-4 w-4 text-indigo-500" />
            批量下发内核升级（已选 {selectedNodeIds.length} 个节点）
          </h2>
          <div className="flex gap-2 text-xs">
            <button
              type="button"
              onClick={() => setSelectedNodeIds(nodes.map((n) => n.id))}
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

        <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
          <div>
            <label className="mb-1 block text-xs font-medium">目标内核</label>
            <select
              className="input-field"
              value={kernel}
              onChange={(e) => handleKernelChange(e.target.value as KernelName)}
            >
              <option value="sing-box">sing-box</option>
              <option value="shadow-tls">shadow-tls</option>
              <option value="snell-server">snell-server</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">目标版本 *</label>
            <input
              type="text"
              list="kernel-version-suggestions"
              className="input-field font-mono text-xs"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder="选择或输入版本号"
              required
            />
            <datalist id="kernel-version-suggestions">
              {availableVersions.map((v) => (
                <option key={v} value={v} />
              ))}
            </datalist>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">下载地址（可选覆盖）</label>
            <input
              type="url"
              className="input-field font-mono text-xs"
              value={downloadUrl}
              onChange={(e) => setDownloadUrl(e.target.value)}
              placeholder="留空则按版本目录自动匹配"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">SHA-256（可选 64 位十六进制）</label>
            <input
              type="text"
              className="input-field font-mono text-xs"
              value={sha256}
              onChange={(e) => setSha256(e.target.value)}
              placeholder="留空则自动从目录获取"
            />
          </div>
        </div>

        {/* Mobile Node Selection List */}
        <div className="space-y-2 md:hidden">
          {nodes.length === 0 ? (
            <div className="rounded-lg border border-slate-200 px-3 py-6 text-center text-xs text-slate-500 dark:border-slate-800">
              暂无可用节点。
            </div>
          ) : (
            nodes.map((n) => (
              <div
                key={n.id}
                onClick={() => toggleNode(n.id)}
                className="cursor-pointer space-y-2 rounded-lg border border-slate-200 p-3 text-xs hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/40"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2">
                    <input
                      type="checkbox"
                      checked={selectedNodeIds.includes(n.id)}
                      onChange={() => toggleNode(n.id)}
                      onClick={(e) => e.stopPropagation()}
                      className="h-4 w-4 shrink-0 rounded border-slate-300 text-indigo-600"
                    />
                    <span className="truncate font-semibold text-slate-900 dark:text-white">{n.name}</span>
                    {n.agent_arch && (
                      <span className="shrink-0 font-mono text-[11px] text-slate-400">{n.agent_arch}</span>
                    )}
                  </div>
                  <NodeStatusBadge status={n.status} />
                </div>
                <div className="grid grid-cols-3 gap-2 rounded bg-slate-50 p-2 font-mono text-[11px] dark:bg-slate-800/60">
                  <div>
                    <div className="text-[10px] text-slate-400">sing-box</div>
                    <div className="truncate">{formatKernelVersion(n.reported_versions?.sing_box)}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-400">shadow-tls</div>
                    <div className="truncate">{formatKernelVersion(n.reported_versions?.shadow_tls)}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-400">snell</div>
                    <div className="truncate">{formatKernelVersion(n.reported_versions?.snell_server)}</div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Desktop Node Selection Table */}
        <div className="hidden overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800 md:block">
          <table className="min-w-full divide-y divide-slate-200 text-xs dark:divide-slate-800">
            <thead className="bg-slate-50 text-left font-semibold text-slate-500 dark:bg-slate-800/60 dark:text-slate-400">
              <tr>
                <th className="w-10 px-3 py-2.5">选择</th>
                <th className="px-3 py-2.5">节点</th>
                <th className="px-3 py-2.5">状态</th>
                <th className="px-3 py-2.5">架构</th>
                <th className="px-3 py-2.5">sing-box</th>
                <th className="px-3 py-2.5">shadow-tls</th>
                <th className="px-3 py-2.5">snell-server</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {nodes.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-3 py-6 text-center text-slate-500">
                    暂无可用节点。
                  </td>
                </tr>
              ) : (
                nodes.map((n) => (
                  <tr
                    key={n.id}
                    className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/40"
                    onClick={() => toggleNode(n.id)}
                  >
                    <td className="px-3 py-2.5" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selectedNodeIds.includes(n.id)}
                        onChange={() => toggleNode(n.id)}
                        className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                      />
                    </td>
                    <td className="px-3 py-2.5 font-medium text-slate-900 dark:text-white">{n.name}</td>
                    <td className="px-3 py-2.5">
                      <NodeStatusBadge status={n.status} />
                    </td>
                    <td className="px-3 py-2.5 font-mono">{n.agent_arch || '—'}</td>
                    <td className="px-3 py-2.5 font-mono">{formatKernelVersion(n.reported_versions?.sing_box)}</td>
                    <td className="px-3 py-2.5 font-mono">{formatKernelVersion(n.reported_versions?.shadow_tls)}</td>
                    <td className="px-3 py-2.5 font-mono">{formatKernelVersion(n.reported_versions?.snell_server)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="flex justify-end">
          <button type="submit" disabled={updating || selectedNodeIds.length === 0} className="btn-primary">
            <Rocket className="h-4 w-4" />
            {updating ? '正在下发...' : `升级选中节点 (${selectedNodeIds.length})`}
          </button>
        </div>

        {batchResult && (
          <div className="space-y-2 rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-800/50">
            <div className="text-xs font-semibold text-slate-700 dark:text-slate-200">
              批量下发结果（成功下发 {batchResult.dispatched.length}，失败/离线 {batchResult.failed.length}）
            </div>
            <div className="space-y-1">
              {batchResult.results.map((r) => (
                <div
                  key={r.node_id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded bg-white px-2.5 py-1.5 text-xs dark:bg-slate-900"
                >
                  <span className="font-medium">{nodeNameById(r.node_id)}</span>
                  <div className="flex flex-wrap items-center gap-2">
                    {r.error && <span className="text-rose-600 dark:text-rose-400">{r.error}</span>}
                    <span
                      className={`rounded px-2 py-0.5 font-mono text-[11px] font-semibold ${
                        r.status === 'dispatched'
                          ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300'
                          : r.status === 'offline'
                            ? 'bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300'
                            : 'bg-rose-100 text-rose-700 dark:bg-rose-950 dark:text-rose-300'
                      }`}
                    >
                      {r.status === 'dispatched' ? '已下发' : r.status === 'offline' ? '节点离线' : '下发失败'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </form>

      {/* Catalog Grid */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* snell-server */}
        <div className="card p-5">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <Cpu className="h-4 w-4 text-indigo-500" /> snell-server
            </h3>
            <button type="button" onClick={openSnellModal} className="btn-secondary px-2.5 py-1 text-xs">
              <Plus className="h-3.5 w-3.5" /> 添加源地址
            </button>
          </div>
          <div className="space-y-2.5">
            {(catalog?.['snell-server'] ?? []).map((entry) => (
              <div
                key={entry.version}
                className="rounded-lg border border-slate-200 p-3 text-xs dark:border-slate-800"
              >
                <div className="flex items-center justify-between">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono font-bold text-slate-900 dark:text-white">{entry.version}</span>
                    <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] uppercase dark:bg-slate-800">
                      {entry.major}
                    </span>
                    {entry.built_in && (
                      <span className="rounded bg-indigo-50 px-1.5 py-0.5 text-[10px] text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
                        内置
                      </span>
                    )}
                  </div>
                  {!entry.built_in && (
                    <button
                      type="button"
                      onClick={() => void handleDeleteSnell(entry.version)}
                      className="text-rose-600 hover:text-rose-700 dark:text-rose-400"
                      title="删除自定义版本"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
                <div className="mt-1.5 space-y-0.5 font-mono text-[10px] text-slate-500 dark:text-slate-400">
                  {Object.entries(entry.urls).map(([arch, u]) => (
                    <div key={arch} className="truncate" title={u}>
                      {arch}: {u}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* sing-box */}
        <div className="card p-5">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold">
            <Cpu className="h-4 w-4 text-emerald-500" /> sing-box 发行版
          </h3>
          {(catalog?.['sing-box'] ?? []).length === 0 ? (
            <p className="text-xs text-slate-500">请点击上方“同步 GitHub 版本”获取 sing-box 发行列表。</p>
          ) : (
            <div className="max-h-96 space-y-2 overflow-y-auto pr-1">
              {(catalog?.['sing-box'] ?? []).map((rel) => (
                <div key={rel.version} className="rounded-lg border border-slate-200 p-3 text-xs dark:border-slate-800">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold">{rel.version}</span>
                    <span className="text-[11px] text-slate-400">{rel.tag_name}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1.5 text-[10px] font-mono text-slate-500">
                    {Object.entries(rel.assets || {}).map(([arch, asset]) => (
                      <span key={arch} className="rounded bg-slate-100 px-1.5 py-0.5 dark:bg-slate-800">
                        {arch} ({formatBytes(asset.size)})
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* shadow-tls */}
        <div className="card p-5">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold">
            <Cpu className="h-4 w-4 text-amber-500" /> shadow-tls 发行版
          </h3>
          {(catalog?.['shadow-tls'] ?? []).length === 0 ? (
            <p className="text-xs text-slate-500">请点击上方“同步 GitHub 版本”获取 shadow-tls 发行列表。</p>
          ) : (
            <div className="max-h-96 space-y-2 overflow-y-auto pr-1">
              {(catalog?.['shadow-tls'] ?? []).map((rel) => (
                <div key={rel.version} className="rounded-lg border border-slate-200 p-3 text-xs dark:border-slate-800">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold">{rel.version}</span>
                    <span className="text-[11px] text-slate-400">{rel.tag_name}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1.5 text-[10px] font-mono text-slate-500">
                    {Object.entries(rel.assets || {}).map(([arch, asset]) => (
                      <span key={arch} className="rounded bg-slate-100 px-1.5 py-0.5 dark:bg-slate-800">
                        {arch} ({formatBytes(asset.size)})
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Add Custom Snell Version Modal */}
      <Modal
        open={snellModalOpen}
        onClose={closeSnellModal}
        title="添加自定义 snell-server 版本"
        subtitle="请填写 amd64 与/或 arm64 架构的 HTTP/HTTPS zip 下载地址（留空的架构将被忽略）。"
        maxWidthClass="max-w-lg"
        footer={
          <>
            <button type="button" onClick={closeSnellModal} className="btn-secondary">
              取消
            </button>
            <button type="submit" form="snell-ver-form" disabled={snellSaving} className="btn-primary">
              {snellSaving ? '保存中...' : '添加版本'}
            </button>
          </>
        }
      >
        <form id="snell-ver-form" onSubmit={handleAddSnell} className="space-y-4">
          <div>
            <label className="mb-1 block text-xs font-medium">版本号 *</label>
            <input
              type="text"
              className="input-field font-mono"
              value={snellVer}
              onChange={(e) => setSnellVer(e.target.value)}
              placeholder="例如：v5.0.2 或 v4.1.2"
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">amd64 下载地址</label>
            <input
              type="url"
              className="input-field font-mono text-xs"
              value={snellAmd64}
              onChange={(e) => setSnellAmd64(e.target.value)}
              placeholder="https://dl.nssurge.com/snell/snell-server-v5.0.2-linux-amd64.zip"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">arm64 下载地址</label>
            <input
              type="url"
              className="input-field font-mono text-xs"
              value={snellArm64}
              onChange={(e) => setSnellArm64(e.target.value)}
              placeholder="https://dl.nssurge.com/snell/snell-server-v5.0.2-linux-aarch64.zip"
            />
          </div>
        </form>
      </Modal>
    </div>
  );
}
