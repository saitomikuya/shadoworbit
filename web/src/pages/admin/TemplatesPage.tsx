import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Edit3, FileCode2, Plus, RefreshCw, Star, Trash2 } from 'lucide-react';
import { api, ApiError } from '../../api/client';
import type { SubTemplate, TemplateClientType } from '../../types/api';
import { useToast } from '../../contexts/ToastContext';
import { Modal } from '../../components/Modal';
import { formatDateTime } from '../../utils/format';

const PLACEHOLDERS_BY_TYPE: Record<TemplateClientType, string[]> = {
  surge_admin: ['{{MANAGED_CONFIG_HEADER}}', '{{PROXIES}}', '{{PROXY_NAMES}}'],
  surge_user: ['{{MANAGED_CONFIG_HEADER}}', '{{PROXIES}}', '{{PROXY_NAMES}}'],
  mihomo_user: ['{{PROXIES}}', '{{PROXY_NAMES_YAML}}', '{{PROXY_NAMES}}'],
};

const TYPE_LABELS: Record<TemplateClientType, string> = {
  surge_admin: '管理员 Surge (Snell)',
  mihomo_user: '用户 Clash / Mihomo',
  surge_user: '用户 Surge (SS2022)',
};

export function TemplatesPage() {
  const toast = useToast();
  const [templates, setTemplates] = useState<SubTemplate[]>([]);
  const [filterType, setFilterType] = useState<TemplateClientType | ''>('');
  const [loading, setLoading] = useState(true);

  // Create/Edit modal
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [name, setName] = useState('');
  const [clientType, setClientType] = useState<TemplateClientType>('mihomo_user');
  const [content, setContent] = useState('');
  const [isDefault, setIsDefault] = useState(false);
  const [saving, setSaving] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const tList = await api.listTemplates();
      setTemplates(tList);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载订阅模板失败');
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
    setClientType('mihomo_user');
    setContent('proxies:\n{{PROXIES}}\n');
    setIsDefault(false);
    setModalOpen(true);
  };

  const openEdit = (t: SubTemplate) => {
    setEditingId(t.id);
    setName(t.name);
    setClientType(t.client_type);
    setContent(t.content);
    setIsDefault(t.is_default);
    setModalOpen(true);
  };

  const insertPlaceholder = (token: string) => {
    const el = textareaRef.current;
    if (!el) {
      setContent((prev) => prev + token);
      return;
    }
    const start = el.selectionStart ?? content.length;
    const end = el.selectionEnd ?? content.length;
    const next = content.slice(0, start) + token + content.slice(end);
    setContent(next);
    window.requestAnimationFrame(() => {
      el.focus();
      el.setSelectionRange(start + token.length, start + token.length);
    });
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      toast.error('请填写模板名称');
      return;
    }
    setSaving(true);
    try {
      if (editingId === null) {
        await api.createTemplate({
          name: name.trim(),
          client_type: clientType,
          content,
          is_default: isDefault,
        });
        toast.success('已创建订阅模板');
      } else {
        await api.updateTemplate(editingId, {
          name: name.trim(),
          client_type: clientType,
          content,
          is_default: isDefault,
        });
        toast.success('已更新订阅模板');
      }
      setModalOpen(false);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '保存订阅模板失败');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (t: SubTemplate) => {
    if (!window.confirm(`确定删除模板 "${t.name}" 吗？`)) return;
    try {
      await api.deleteTemplate(t.id);
      toast.success('已删除订阅模板');
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '删除订阅模板失败');
    }
  };

  const filteredTemplates = filterType
    ? templates.filter((t) => t.client_type === filterType)
    : templates;

  return (
    <div className="space-y-6">
      <div className="admin-sticky-header space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white">
              订阅规则模板
            </h1>
            <p className="hidden text-sm text-slate-500 dark:text-slate-400 sm:block">
              管理 Surge 与 Clash / Mihomo 分流规则模板；管理员与用户订阅生成入口位于“用户管理”页
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button type="button" onClick={() => void load()} className="btn-secondary" disabled={loading}>
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              刷新
            </button>
            <button type="button" onClick={openCreate} className="btn-primary">
              <Plus className="h-4 w-4" />
              新建模板
            </button>
          </div>
        </div>

        {/* Filter */}
        <div className="flex flex-wrap items-center gap-2">
          {(
            [
              ['', '全部类型'],
              ['surge_admin', '管理员 Surge'],
              ['mihomo_user', '用户 Clash / Mihomo'],
              ['surge_user', '用户 Surge'],
            ] as const
          ).map(([val, label]) => (
            <button
              key={label}
              type="button"
              onClick={() => setFilterType(val)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium ${
                filterType === val
                  ? 'bg-indigo-600 text-white dark:bg-indigo-500'
                  : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-800'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {filteredTemplates.length === 0 && !loading ? (
        <div className="card flex flex-col items-center justify-center py-14 text-center">
          <FileCode2 className="h-10 w-10 text-slate-300 dark:text-slate-600" />
          <p className="mt-3 text-sm font-medium text-slate-600 dark:text-slate-300">暂无符合条件的模板</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {filteredTemplates.map((t) => (
            <div key={t.id} className="card flex flex-col justify-between p-5">
              <div>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-base font-semibold text-slate-900 dark:text-white">{t.name}</h3>
                      {t.is_default && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-semibold text-amber-800 dark:bg-amber-950/70 dark:text-amber-300">
                          <Star className="h-3 w-3" /> 默认模板
                        </span>
                      )}
                    </div>
                    <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                      {TYPE_LABELS[t.client_type]} · <code>{t.client_type}</code> · ID #{t.id}
                    </p>
                  </div>
                </div>
                <pre className="mt-3 max-h-40 overflow-auto rounded-lg bg-slate-50 p-3 font-mono text-xs text-slate-700 dark:bg-slate-800/70 dark:text-slate-300">
                  {t.content}
                </pre>
              </div>
              <div className="mt-4 flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-800">
                <span className="text-[11px] text-slate-400">更新于 {formatDateTime(t.updated_at)}</span>
                <div className="flex gap-2">
                  <button type="button" onClick={() => openEdit(t)} className="btn-secondary px-2.5 py-1 text-xs">
                    <Edit3 className="h-3.5 w-3.5" /> 编辑
                  </button>
                  <button type="button" onClick={() => void handleDelete(t)} className="btn-danger px-2.5 py-1 text-xs">
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
        title={editingId === null ? '新建订阅模板' : '编辑订阅模板'}
        maxWidthClass="max-w-3xl"
        footer={
          <>
            <button type="button" onClick={() => setModalOpen(false)} className="btn-secondary">
              取消
            </button>
            <button type="submit" form="template-form" disabled={saving} className="btn-primary">
              {saving ? '保存中...' : '保存模板'}
            </button>
          </>
        }
      >
        <form id="template-form" onSubmit={handleSave} className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium">模板名称 *</label>
              <input
                type="text"
                className="input-field"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">客户端类型 *</label>
              <select
                className="input-field"
                value={clientType}
                onChange={(e) => setClientType(e.target.value as TemplateClientType)}
              >
                <option value="surge_admin">surge_admin（管理员 Surge）</option>
                <option value="mihomo_user">mihomo_user（用户 Clash / Mihomo）</option>
                <option value="surge_user">surge_user（用户 Surge）</option>
              </select>
            </div>
          </div>

          <label className="flex items-center gap-2 text-sm font-medium">
            <input
              type="checkbox"
              checked={isDefault}
              onChange={(e) => setIsDefault(e.target.checked)}
              className="h-4 w-4 rounded border-slate-300 text-indigo-600"
            />
            设为 <code>{clientType}</code> 类型的默认模板
          </label>

          <div>
            <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
              <label className="text-xs font-medium">模板正文</label>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] text-slate-400">快捷插入变量：</span>
                {PLACEHOLDERS_BY_TYPE[clientType].map((ph) => (
                  <button
                    key={ph}
                    type="button"
                    onClick={() => insertPlaceholder(ph)}
                    className="rounded-md bg-indigo-50 px-2 py-0.5 font-mono text-[11px] font-medium text-indigo-700 hover:bg-indigo-100 dark:bg-indigo-950/70 dark:text-indigo-300 dark:hover:bg-indigo-900"
                  >
                    {ph}
                  </button>
                ))}
              </div>
            </div>
            <textarea
              ref={textareaRef}
              rows={14}
              className="input-field font-mono text-xs"
              value={content}
              onChange={(e) => setContent(e.target.value)}
            />
          </div>
        </form>
      </Modal>
    </div>
  );
}
