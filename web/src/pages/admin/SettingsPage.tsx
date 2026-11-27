import React, { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Bell, Globe2, RefreshCw, Save, Sliders, Sparkles } from 'lucide-react';
import { api, ApiError } from '../../api/client';
import type { SystemSettings } from '../../types/api';
import { useToast } from '../../contexts/ToastContext';
import { NumericInput } from '../../components/NumericInput';
import { randomHex } from '../../utils/format';
import { DnsRulesSection } from './DnsRulesPage';
import { WebhooksSection } from './WebhooksPage';

type SettingsTab = 'general' | 'dns-rules' | 'webhooks';

export function SettingsPage() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = searchParams.get('tab');
  const activeTab: SettingsTab =
    rawTab === 'dns-rules' ? 'dns-rules' : rawTab === 'webhooks' ? 'webhooks' : 'general';

  const switchTab = (next: SettingsTab) => {
    if (next === 'general') {
      setSearchParams({});
    } else {
      setSearchParams({ tab: next });
    }
  };

  const [form, setForm] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getSettings();
      setForm(data);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '加载系统设置失败');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form) return;
    if (!Number.isInteger(form.alert_cooldown_minutes) || form.alert_cooldown_minutes < 0) {
      toast.error('告警冷却时间必须为大于等于 0 的整数');
      return;
    }
    if (
      !Number.isInteger(form.warning_threshold_percent) ||
      form.warning_threshold_percent < 0 ||
      form.warning_threshold_percent > 100
    ) {
      toast.error('流量告警阈值必须在 0 到 100 之间');
      return;
    }
    if (!Number.isInteger(form.offline_timeout_seconds) || form.offline_timeout_seconds < 1) {
      toast.error('离线超时秒数必须为大于等于 1 的整数');
      return;
    }
    if (
      !Number.isInteger(form.default_local_dns_port) ||
      form.default_local_dns_port < 1 ||
      form.default_local_dns_port > 65535
    ) {
      toast.error('默认本地 DNS 监听端口必须在 1 到 65535 之间');
      return;
    }
    const dockerImage = form.agent_docker_image.trim();
    if (!dockerImage || /[\s'"`;|&$<>\\]/.test(dockerImage)) {
      toast.error('节点端 Docker 镜像不能为空且不能包含空格或特殊字符');
      return;
    }
    if (
      !Number.isInteger(form.traffic_log_max_entries) ||
      form.traffic_log_max_entries < 100 ||
      form.traffic_log_max_entries > 1000000
    ) {
      toast.error('流量日志保存上限必须在 100 到 1,000,000 条之间');
      return;
    }
    setSaving(true);
    try {
      const updated = await api.updateSettings({
        ...form,
        agent_docker_image: dockerImage,
      });
      setForm(updated);
      toast.success('系统设置已保存');
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '保存系统设置失败');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="admin-sticky-header space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white">系统设置</h1>
            <p className="hidden text-sm text-slate-500 dark:text-slate-400 sm:block">
              统一管理面板基础信息、监控告警阈值、DNS 解锁规则组与告警推送通道
            </p>
          </div>
          {activeTab === 'general' && (
            <button type="button" onClick={() => void load()} className="btn-secondary" disabled={loading}>
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              重新加载
            </button>
          )}
        </div>

        {/* Integrated Settings Tabs */}
        <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => switchTab('general')}
          className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors ${
            activeTab === 'general'
              ? 'bg-indigo-600 text-white dark:bg-indigo-500'
              : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-800 dark:hover:bg-slate-800'
          }`}
        >
          <Sliders className="h-4 w-4" />
          基础与告警设置
        </button>
        <button
          type="button"
          onClick={() => switchTab('dns-rules')}
          className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors ${
            activeTab === 'dns-rules'
              ? 'bg-indigo-600 text-white dark:bg-indigo-500'
              : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-800 dark:hover:bg-slate-800'
          }`}
        >
          <Globe2 className="h-4 w-4" />
          DNS 解锁规则
        </button>
        <button
          type="button"
          onClick={() => switchTab('webhooks')}
          className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors ${
            activeTab === 'webhooks'
              ? 'bg-indigo-600 text-white dark:bg-indigo-500'
              : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-800 dark:hover:bg-slate-800'
          }`}
        >
          <Bell className="h-4 w-4" />
          告警通知
        </button>
        </div>
      </div>

      {activeTab === 'dns-rules' ? (
        <DnsRulesSection embedded />
      ) : activeTab === 'webhooks' ? (
        <WebhooksSection embedded />
      ) : loading && !form ? (
        <p className="py-10 text-center text-sm text-slate-500">正在加载系统设置...</p>
      ) : !form ? (
        <div className="card p-6 text-center text-sm text-rose-600">
          无法加载系统设置。{' '}
          <button type="button" onClick={() => void load()} className="underline">
            重试
          </button>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Public Dashboard & Branding */}
          <div className="card space-y-4 p-4 sm:p-5">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-white">
              公开状态页配置
            </h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium">站点标题</label>
                <input
                  type="text"
                  className="input-field"
                  value={form.site_title}
                  onChange={(e) => setForm({ ...form, site_title: e.target.value })}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">管理员订阅 Token</label>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <input
                    type="text"
                    className="input-field font-mono text-xs"
                    value={form.admin_sub_token}
                    onChange={(e) => setForm({ ...form, admin_sub_token: e.target.value })}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setForm({ ...form, admin_sub_token: `adm_${randomHex(16)}` })}
                    className="btn-secondary shrink-0 px-3"
                    title="生成随机 Token"
                  >
                    <Sparkles className="h-3.5 w-3.5" />
                    <span className="sm:hidden">随机生成</span>
                  </button>
                </div>
              </div>
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium">公开公告栏</label>
              <textarea
                rows={3}
                className="input-field"
                value={form.announcement}
                onChange={(e) => setForm({ ...form, announcement: e.target.value })}
                placeholder="可选：显示在公开状态页顶部的公告内容"
              />
            </div>

            <label className="flex items-center gap-2 text-sm font-medium">
              <input
                type="checkbox"
                checked={form.percentage_only}
                onChange={(e) => setForm({ ...form, percentage_only: e.target.checked })}
                className="h-4 w-4 rounded border-slate-300 text-indigo-600"
              />
              仅百分比隐私模式（在公开状态页隐藏具体 GB/TB 流量数值）
            </label>
          </div>

          {/* Alerts & Monitoring */}
          <div className="card space-y-4 p-5">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-white">
              监控与告警阈值
            </h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div>
                <label className="mb-1 block text-xs font-medium">告警冷却间隔（分钟，≥ 0）</label>
                <NumericInput
                  min={0}
                  className="input-field"
                  value={form.alert_cooldown_minutes}
                  onChange={(v) => setForm({ ...form, alert_cooldown_minutes: v })}
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">
                  流量预警阈值（%，0–100）
                </label>
                <NumericInput
                  min={0}
                  max={100}
                  className="input-field"
                  value={form.warning_threshold_percent}
                  onChange={(v) => setForm({ ...form, warning_threshold_percent: v })}
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">
                  节点离线判定超时（秒，≥ 1）
                </label>
                <NumericInput
                  min={1}
                  className="input-field"
                  value={form.offline_timeout_seconds}
                  onChange={(v) => setForm({ ...form, offline_timeout_seconds: v })}
                  required
                />
                <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                  心跳超时后标记离线；持续离线超过 10 分钟后推送告警
                </p>
              </div>
            </div>

            <div className="flex flex-col gap-2.5 pt-1">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.alert_user_expired}
                  onChange={(e) => setForm({ ...form, alert_user_expired: e.target.checked })}
                  className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                />
                用户账号到期时发送通知（<code>alert_user_expired</code>）
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.alert_user_quota_exhausted}
                  onChange={(e) =>
                    setForm({ ...form, alert_user_quota_exhausted: e.target.checked })
                  }
                  className="h-4 w-4 rounded border-slate-300 text-indigo-600"
                />
                用户流量配额耗尽时发送通知（<code>alert_user_quota_exhausted</code>）
              </label>
            </div>
          </div>

          {/* Default DNS Settings */}
          <div className="card space-y-4 p-4 sm:p-5">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-white">
              默认节点 DNS 分流器配置
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              修改以下默认值后，将自动触发所有在线节点同步最新配置。
            </p>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium">默认上游 DNS</label>
                <input
                  type="text"
                  className="input-field font-mono text-xs"
                  value={form.default_upstream_dns}
                  onChange={(e) => setForm({ ...form, default_upstream_dns: e.target.value })}
                  placeholder="1.1.1.1:53"
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">
                  默认本地 DNS 回环监听端口（1–65535）
                </label>
                <NumericInput
                  min={1}
                  max={65535}
                  className="input-field"
                  value={form.default_local_dns_port}
                  onChange={(v) => setForm({ ...form, default_local_dns_port: v })}
                  required
                />
              </div>
            </div>
          </div>

          {/* Docker Image & Traffic Log Retention */}
          <div className="card space-y-4 p-4 sm:p-5">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-white">
              Docker 镜像与日志存储设置
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              配置节点管理页“安装命令”生成的默认节点端 Docker 镜像（管理端镜像为{' '}
              <code className="font-mono">saitomikuya/shadoworbit:latest</code>），以及流量明细日志保存上限。
            </p>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium">节点端 Docker 镜像</label>
                <input
                  type="text"
                  className="input-field font-mono text-xs"
                  value={form.agent_docker_image}
                  onChange={(e) => setForm({ ...form, agent_docker_image: e.target.value })}
                  placeholder="saitomikuya/shadoworbit-agent:latest"
                  required
                />
                <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                  默认：<code>saitomikuya/shadoworbit-agent:latest</code>
                </p>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">
                  流量日志保存上限（条，100–1,000,000）
                </label>
                <NumericInput
                  min={100}
                  max={1000000}
                  className="input-field font-mono"
                  value={form.traffic_log_max_entries}
                  onChange={(v) => setForm({ ...form, traffic_log_max_entries: v })}
                  required
                />
                <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                  按分钟粒度记录节点用户流量消耗，超出上限时自动删除最早记录（默认 10000 条）。
                </p>
              </div>
            </div>
          </div>

          <div className="flex justify-end">
            <button type="submit" disabled={saving} className="btn-primary w-full sm:w-auto px-6">
              <Save className="h-4 w-4" />
              {saving ? '保存中...' : '保存设置'}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
