import React, { useCallback, useEffect, useState } from 'react';
import { Edit3, Globe2, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { api, ApiError } from '../../api/client';
import type { DNSRuleGroup } from '../../types/api';
import { useToast } from '../../contexts/ToastContext';
import { Modal } from '../../components/Modal';
import { formatDateTime } from '../../utils/format';

export function DnsRulesSection({ embedded = false }: { embedded?: boolean }) {
  const toast = useToast();
  const [groups, setGroups] = useState<DNSRuleGroup[]>([]);
  const [loading, setLoading] = useState(true);

  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [rulesText, setRulesText] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.listDnsRules();
      setGroups(list);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载 DNS 规则组失败');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const openCreate = () => {
    setEditingId(null);
    setName('');
    setDescription('');
    setRulesText('');
    setModalOpen(true);
  };

  const openEdit = (g: DNSRuleGroup) => {
    setEditingId(g.id);
    setName(g.name);
    setDescription(g.description);
    setRulesText((g.rules || []).join('\n'));
    setModalOpen(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      toast.error('请填写规则组名称');
      return;
    }
    const rules = rulesText
      .split('\n')
      .map((r) => r.trim())
      .filter(Boolean);

    setSaving(true);
    try {
      if (editingId === null) {
        await api.createDnsRule({ name: name.trim(), description: description.trim(), rules });
        toast.success('已创建 DNS 规则组');
      } else {
        await api.updateDnsRule(editingId, {
          name: name.trim(),
          description: description.trim(),
          rules,
        });
        toast.success('已更新 DNS 规则组并同步关联节点');
      }
      setModalOpen(false);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '保存 DNS 规则组失败');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (g: DNSRuleGroup) => {
    if (!window.confirm(`确定删除 DNS 规则组 "${g.name}" 吗？关联节点将取消绑定并触发配置同步。`)) {
      return;
    }
    try {
      await api.deleteDnsRule(g.id);
      toast.success('已删除 DNS 规则组');
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '删除 DNS 规则组失败');
    }
  };

  const Heading = embedded ? 'h2' : 'h1';

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Heading className={`${embedded ? 'text-lg' : 'text-xl'} font-bold text-slate-900 dark:text-white`}>
            DNS 解锁规则组
          </Heading>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            管理可复用的流媒体与 AI 解锁域名规则组，下发至各节点的本地 DNS 分流器
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={() => void load()} className="btn-secondary" disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            刷新
          </button>
          <button type="button" onClick={openCreate} className="btn-primary">
            <Plus className="h-4 w-4" />
            新建规则组
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-indigo-200 bg-indigo-50/70 px-4 py-3 text-xs text-indigo-950 dark:border-indigo-900/60 dark:bg-indigo-950/40 dark:text-indigo-200">
        <strong className="font-semibold">域名匹配语法说明：</strong>{' '}
        <code className="rounded bg-white/80 px-1.5 py-0.5 font-mono dark:bg-slate-900">abc.com</code> 匹配主域名及全部子域名 ·{' '}
        <code className="rounded bg-white/80 px-1.5 py-0.5 font-mono dark:bg-slate-900">^abc.com</code> 仅精确匹配主域名 ·{' '}
        <code className="rounded bg-white/80 px-1.5 py-0.5 font-mono dark:bg-slate-900">*.abc.com</code> 仅匹配子域名（不含根域名）。
      </div>

      {groups.length === 0 && !loading ? (
        <div className="card flex flex-col items-center justify-center py-16 text-center">
          <Globe2 className="h-10 w-10 text-slate-300 dark:text-slate-600" />
          <p className="mt-3 text-sm font-medium text-slate-700 dark:text-slate-300">暂无 DNS 规则组</p>
          <button type="button" onClick={openCreate} className="btn-primary mt-4">
            <Plus className="h-4 w-4" /> 新建规则组
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {groups.map((g) => (
            <div key={g.id} className="card flex flex-col justify-between p-5">
              <div>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-base font-semibold text-slate-900 dark:text-white">{g.name}</h3>
                    {g.description && (
                      <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{g.description}</p>
                    )}
                  </div>
                  <span className="shrink-0 rounded-full bg-indigo-50 px-2.5 py-0.5 text-xs font-semibold text-indigo-700 dark:bg-indigo-950/70 dark:text-indigo-300">
                    {g.rules.length} 条规则
                  </span>
                </div>
                <pre className="mt-3 max-h-36 overflow-y-auto rounded-lg bg-slate-50 p-3 font-mono text-xs text-slate-700 dark:bg-slate-800/70 dark:text-slate-300">
                  {g.rules.length > 0 ? g.rules.join('\n') : '（空）'}
                </pre>
              </div>
              <div className="mt-4 flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-800">
                <span className="text-[11px] text-slate-400">更新于 {formatDateTime(g.updated_at)}</span>
                <div className="flex gap-2">
                  <button type="button" onClick={() => openEdit(g)} className="btn-secondary px-2.5 py-1 text-xs">
                    <Edit3 className="h-3.5 w-3.5" /> 编辑
                  </button>
                  <button type="button" onClick={() => void handleDelete(g)} className="btn-danger px-2.5 py-1 text-xs">
                    <Trash2 className="h-3.5 w-3.5" /> 删除
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editingId === null ? '新建 DNS 规则组' : '编辑 DNS 规则组'}
        footer={
          <>
            <button type="button" onClick={() => setModalOpen(false)} className="btn-secondary">
              取消
            </button>
            <button type="submit" form="dns-group-form" disabled={saving} className="btn-primary">
              {saving ? '保存中...' : '保存规则组'}
            </button>
          </>
        }
      >
        <form id="dns-group-form" onSubmit={handleSave} className="space-y-4">
          <div>
            <label className="mb-1 block text-xs font-medium">规则组名称 *</label>
            <input
              type="text"
              className="input-field"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="例如：流媒体与 AI 解锁"
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">描述说明</label>
            <input
              type="text"
              className="input-field"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="可选备注说明"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">域名规则列表（每行一条）</label>
            <textarea
              rows={8}
              className="input-field font-mono text-xs"
              value={rulesText}
              onChange={(e) => setRulesText(e.target.value)}
              placeholder={'netflix.com\n^nflxvideo.net\n*.disneyplus.com\nopenai.com'}
            />
            <p className="mt-1 text-[11px] text-slate-500">
              <code>abc.com</code>（含主域及子域）· <code>^abc.com</code>（仅主域）· <code>*.abc.com</code>（仅子域）
            </p>
          </div>
        </form>
      </Modal>
    </div>
  );
}

export function DnsRulesPage() {
  return <DnsRulesSection />;
}
