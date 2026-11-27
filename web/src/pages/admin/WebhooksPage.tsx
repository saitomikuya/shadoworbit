import React, { useCallback, useEffect, useState } from 'react';
import { Bell, Edit3, Plus, RefreshCw, Send, Trash2 } from 'lucide-react';
import { api, ApiError } from '../../api/client';
import {
  CANONICAL_WEBHOOK_EVENTS,
  type WebhookChannel,
  type WebhookProvider,
} from '../../types/api';
import { useToast } from '../../contexts/ToastContext';
import { Modal } from '../../components/Modal';

interface HeaderRow {
  key: string;
  value: string;
}

function parseCustomSecret(secret: string): { headers: HeaderRow[]; template: string } {
  if (!secret.trim()) return { headers: [], template: '' };
  try {
    const parsed = JSON.parse(secret) as Record<string, unknown>;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const keys = Object.keys(parsed);
      const isStructured =
        keys.length > 0 &&
        keys.every((k) => k === 'headers' || k === 'template') &&
        ((parsed.headers && typeof parsed.headers === 'object' && !Array.isArray(parsed.headers)) ||
          typeof parsed.template === 'string');

      if (isStructured) {
        const headers =
          parsed.headers && typeof parsed.headers === 'object' && !Array.isArray(parsed.headers)
            ? Object.entries(parsed.headers as Record<string, unknown>)
                .filter(([, v]) => typeof v === 'string')
                .map(([key, value]) => ({ key, value: String(value) }))
            : [];
        const template = typeof parsed.template === 'string' ? parsed.template : '';
        return { headers, template };
      }

      const headers = Object.entries(parsed)
        .filter(([, v]) => typeof v === 'string')
        .map(([key, value]) => ({ key, value: String(value) }));
      return { headers, template: '' };
    }
  } catch {
    // ignore
  }
  return { headers: [], template: '' };
}

const PROVIDER_LABELS: Record<WebhookProvider, string> = {
  feishu: '飞书 (Feishu)',
  dingtalk: '钉钉 (DingTalk)',
  wecom: '企业微信 (WeCom)',
  serverchan: 'Server酱',
  custom: '自定义 (JSON 模板)',
};

const EVENT_LABELS: Record<string, string> = {
  node_offline: '节点离线（超过 10 分钟）',
  node_online: '节点上线恢复',
  process_crashed: '内核进程异常退出',
  kernel_update: '内核更新结果',
  config_error: '配置下发/应用失败',
  traffic_warning: '节点流量预警',
  traffic_paused: '节点流量超限暂停',
  traffic_recovered: '节点计费周期重置恢复',
  user_quota_exhausted: '用户流量配额耗尽',
  user_expired: '用户账号过期',
  high_resource_usage: '高负载资源告警',
};

export function WebhooksSection({ embedded = false }: { embedded?: boolean }) {
  const toast = useToast();
  const [channels, setChannels] = useState<WebhookChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [testingId, setTestingId] = useState<number | null>(null);

  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [name, setName] = useState('');
  const [provider, setProvider] = useState<WebhookProvider>('feishu');
  const [url, setUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [customHeaders, setCustomHeaders] = useState<HeaderRow[]>([]);
  const [customTemplate, setCustomTemplate] = useState('');
  const [events, setEvents] = useState<string[]>(['*']);
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.listWebhooks();
      setChannels(list);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载通知通道失败');
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
    setProvider('feishu');
    setUrl('');
    setSecret('');
    setCustomHeaders([]);
    setCustomTemplate('');
    setEvents(['*']);
    setEnabled(true);
    setModalOpen(true);
  };

  const openEdit = (w: WebhookChannel) => {
    const parsedCustom =
      w.provider === 'custom'
        ? parseCustomSecret(w.secret || '')
        : { headers: [], template: '' };
    setEditingId(w.id);
    setName(w.name);
    setProvider(w.provider);
    setUrl(w.url);
    setSecret(w.provider === 'custom' ? '' : w.secret || '');
    setCustomHeaders(parsedCustom.headers);
    setCustomTemplate(w.custom_template || parsedCustom.template || '');
    setEvents(w.subscribed_events || ['*']);
    setEnabled(w.enabled);
    setModalOpen(true);
  };

  const toggleEvent = (ev: string) => {
    if (ev === '*') {
      setEvents((prev) => (prev.includes('*') ? [] : ['*']));
      return;
    }
    setEvents((prev) => {
      const withoutWild = prev.filter((x) => x !== '*' && x !== 'all');
      return withoutWild.includes(ev) ? withoutWild.filter((x) => x !== ev) : [...withoutWild, ev];
    });
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !url.trim()) {
      toast.error('请填写通道名称和 Webhook URL');
      return;
    }
    if (events.length === 0) {
      toast.error('请至少选择一个订阅事件，或开启全部事件 "*"');
      return;
    }

    let finalSecret = '';
    if (provider === 'feishu' || provider === 'dingtalk' || provider === 'serverchan') {
      finalSecret = secret.trim();
    } else if (provider === 'custom') {
      const headerMap: Record<string, string> = {};
      for (const row of customHeaders) {
        const k = row.key.trim();
        if (!k) continue;
        const lower = k.toLowerCase();
        if (lower === 'host' || lower === 'content-length') {
          toast.error(`后端禁止自定义 "${k}" 请求头`);
          return;
        }
        headerMap[k] = row.value;
      }
      finalSecret = Object.keys(headerMap).length > 0 ? JSON.stringify(headerMap) : '';
    }

    setSaving(true);
    try {
      const payload = {
        name: name.trim(),
        provider,
        url: url.trim(),
        secret: finalSecret,
        subscribed_events: events,
        enabled,
        custom_template: provider === 'custom' ? customTemplate : '',
      };
      if (editingId === null) {
        await api.createWebhook(payload);
        toast.success('已创建告警通知通道');
      } else {
        await api.updateWebhook(editingId, payload);
        toast.success('已更新告警通知通道');
      }
      setModalOpen(false);
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '保存告警通知通道失败');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (w: WebhookChannel) => {
    if (!window.confirm(`确定删除通知通道 "${w.name}" 吗？`)) return;
    try {
      await api.deleteWebhook(w.id);
      toast.success('已删除通知通道');
      await load();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '删除通知通道失败');
    }
  };

  const handleTest = async (w: WebhookChannel) => {
    setTestingId(w.id);
    try {
      await api.testWebhook(w.id);
      toast.success(`已向 "${w.name}" 发送测试消息`);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '发送测试消息失败');
    } finally {
      setTestingId(null);
    }
  };

  const Heading = embedded ? 'h2' : 'h1';

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Heading className={`${embedded ? 'text-lg' : 'text-xl'} font-bold text-slate-900 dark:text-white`}>
            告警通知中心
          </Heading>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            配置飞书、钉钉、企业微信、Server酱及自定义 JSON Webhook 告警通知与事件订阅
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={() => void load()} className="btn-secondary" disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            刷新
          </button>
          <button type="button" onClick={openCreate} className="btn-primary">
            <Plus className="h-4 w-4" />
            新增通道
          </button>
        </div>
      </div>

      {channels.length === 0 && !loading ? (
        <div className="card flex flex-col items-center justify-center py-16 text-center">
          <Bell className="h-10 w-10 text-slate-300 dark:text-slate-600" />
          <p className="mt-3 text-sm font-medium text-slate-700 dark:text-slate-300">
            暂未配置任何通知通道
          </p>
          <button type="button" onClick={openCreate} className="btn-primary mt-4">
            <Plus className="h-4 w-4" /> 新增通知通道
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {channels.map((w) => (
            <div key={w.id} className="card flex flex-col justify-between p-5">
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-base font-semibold text-slate-900 dark:text-white">{w.name}</h3>
                      <span className="rounded bg-indigo-50 px-2 py-0.5 text-[11px] font-semibold text-indigo-700 dark:bg-indigo-950/70 dark:text-indigo-300">
                        {PROVIDER_LABELS[w.provider] || w.provider}
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                          w.enabled
                            ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300'
                            : 'bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
                        }`}
                      >
                        {w.enabled ? '已启用' : '已停用'}
                      </span>
                    </div>
                    <p className="mt-1 break-all font-mono text-xs text-slate-500 dark:text-slate-400">
                      {w.url}
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap gap-1.5">
                  {(w.subscribed_events || []).map((ev) => (
                    <span
                      key={ev}
                      className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-700 dark:bg-slate-800 dark:text-slate-300"
                    >
                      {ev === '*' ? '全部事件 (*)' : EVENT_LABELS[ev] || ev}
                    </span>
                  ))}
                </div>
              </div>

              <div className="mt-4 flex flex-wrap items-center justify-end gap-2 border-t border-slate-100 pt-3 dark:border-slate-800">
                <button
                  type="button"
                  disabled={testingId === w.id}
                  onClick={() => void handleTest(w)}
                  className="btn-secondary px-2.5 py-1 text-xs"
                >
                  <Send className="h-3.5 w-3.5" />
                  {testingId === w.id ? '发送中...' : '发送测试'}
                </button>
                <button
                  type="button"
                  onClick={() => openEdit(w)}
                  className="btn-secondary px-2.5 py-1 text-xs"
                >
                  <Edit3 className="h-3.5 w-3.5" />
                  编辑
                </button>
                <button
                  type="button"
                  onClick={() => void handleDelete(w)}
                  className="btn-danger px-2.5 py-1 text-xs"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  删除
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editingId === null ? '新增通知通道' : '编辑通知通道'}
        maxWidthClass="max-w-2xl"
        footer={
          <>
            <button type="button" onClick={() => setModalOpen(false)} className="btn-secondary">
              取消
            </button>
            <button type="submit" form="webhook-form" disabled={saving} className="btn-primary">
              {saving ? '保存中...' : '保存配置'}
            </button>
          </>
        }
      >
        <form id="webhook-form" onSubmit={handleSave} className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium">通道名称 *</label>
              <input
                type="text"
                className="input-field"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="例如：运维告警群 / 我的微信推送"
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">推送平台 (Provider) *</label>
              <select
                className="input-field"
                value={provider}
                onChange={(e) => setProvider(e.target.value as WebhookProvider)}
              >
                <option value="feishu">飞书 (Feishu)</option>
                <option value="dingtalk">钉钉 (DingTalk)</option>
                <option value="wecom">企业微信 (WeCom)</option>
                <option value="serverchan">Server酱</option>
                <option value="custom">自定义 (JSON 模板)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium">Webhook 地址 *</label>
            <input
              type="url"
              className="input-field font-mono text-xs"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={
                provider === 'serverchan'
                  ? 'https://sctapi.ftqq.com/<SendKey>.send'
                  : 'https://...'
              }
              required
            />
            {provider === 'serverchan' && (
              <p className="mt-1 text-[11px] text-slate-500">
                支持 Server酱 Turbo (<code>https://sctapi.ftqq.com/&lt;SendKey&gt;.send</code>) 与 Server酱³ 推送地址。
              </p>
            )}
          </div>

          {(provider === 'feishu' || provider === 'dingtalk') && (
            <div>
              <label className="mb-1 block text-xs font-medium">签名密钥（可选）</label>
              <input
                type="text"
                className="input-field font-mono text-xs"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder="可选 HMAC-SHA256 签名密钥"
              />
            </div>
          )}

          {provider === 'serverchan' && (
            <div>
              <label className="mb-1 block text-xs font-medium">附加参数 / 标签（可选）</label>
              <input
                type="text"
                className="input-field font-mono text-xs"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder='可选标签文本（如 ShadowOrbit）或 JSON（如 {"channel":"9","tags":"告警"}）'
              />
            </div>
          )}

          {provider === 'custom' && (
            <div className="space-y-4 rounded-xl border border-slate-200 p-4 dark:border-slate-800">
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <label className="text-xs font-medium">
                    自定义 HTTP 请求头（禁止 Host / Content-Length）
                  </label>
                  <button
                    type="button"
                    onClick={() => setCustomHeaders((prev) => [...prev, { key: '', value: '' }])}
                    className="btn-secondary px-2 py-1 text-xs"
                  >
                    + 添加请求头
                  </button>
                </div>
                {customHeaders.length === 0 ? (
                  <p className="text-xs text-slate-400">未配置自定义请求头。</p>
                ) : (
                  <div className="space-y-2">
                    {customHeaders.map((row, i) => (
                      <div key={i} className="flex gap-2">
                        <input
                          type="text"
                          className="input-field font-mono text-xs"
                          placeholder="Header 名称（如 Authorization）"
                          value={row.key}
                          onChange={(e) =>
                            setCustomHeaders((prev) =>
                              prev.map((r, idx) => (idx === i ? { ...r, key: e.target.value } : r))
                            )
                          }
                        />
                        <input
                          type="text"
                          className="input-field font-mono text-xs"
                          placeholder="值"
                          value={row.value}
                          onChange={(e) =>
                            setCustomHeaders((prev) =>
                              prev.map((r, idx) => (idx === i ? { ...r, value: e.target.value } : r))
                            )
                          }
                        />
                        <button
                          type="button"
                          onClick={() =>
                            setCustomHeaders((prev) => prev.filter((_, idx) => idx !== i))
                          }
                          className="btn-danger px-2.5 py-1 text-xs"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <label className="mb-1 block text-xs font-medium">
                  自定义 JSON 请求体模板（Go <code>text/template</code> 语法，输出须为合法 JSON）
                </label>
                <textarea
                  rows={4}
                  className="input-field font-mono text-xs"
                  value={customTemplate}
                  onChange={(e) => setCustomTemplate(e.target.value)}
                  placeholder='{"event":"{{jsonEscape .Type}}","title":"{{jsonEscape .Title}}","message":"{{jsonEscape .Message}}"}'
                />
              </div>
            </div>
          )}

          <div>
            <div className="mb-2 flex items-center justify-between">
              <label className="text-xs font-medium">订阅事件类型</label>
              <button
                type="button"
                onClick={() => toggleEvent('*')}
                className={`rounded-md px-2.5 py-1 text-xs font-medium ${
                  events.includes('*')
                    ? 'bg-indigo-600 text-white'
                    : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'
                }`}
              >
                *（全部事件）
              </button>
            </div>
            <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
              {CANONICAL_WEBHOOK_EVENTS.map((ev) => (
                <label
                  key={ev}
                  className="flex items-center gap-2 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs dark:border-slate-800"
                >
                  <input
                    type="checkbox"
                    checked={events.includes('*') || events.includes(ev)}
                    onChange={() => toggleEvent(ev)}
                    className="h-3.5 w-3.5 rounded border-slate-300 text-indigo-600"
                  />
                  <span>{EVENT_LABELS[ev] || ev}</span>
                  <span className="ml-auto font-mono text-[10px] text-slate-400">{ev}</span>
                </label>
              ))}
            </div>
          </div>

          <label className="flex items-center gap-2 text-sm font-medium">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-slate-300 text-indigo-600"
            />
            启用该通道
          </label>
        </form>
      </Modal>
    </div>
  );
}

export function WebhooksPage() {
  return <WebhooksSection />;
}
