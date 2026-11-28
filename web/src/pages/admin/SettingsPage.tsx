import React, { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Bell, Cloud, Globe2, RefreshCw, Save, Sliders, Sparkles } from 'lucide-react';
import { api, ApiError } from '../../api/client';
import type { HuaweiCloudZone, SystemSettings, UpdateSettingsRequest } from '../../types/api';
import { useToast } from '../../contexts/ToastContext';
import { NumericInput } from '../../components/NumericInput';
import { randomHex } from '../../utils/format';
import { DnsRulesSection } from './DnsRulesPage';
import { WebhooksSection } from './WebhooksPage';

type SettingsTab = 'general' | 'cloud-dns' | 'dns-rules' | 'webhooks';

const HUAWEICLOUD_ENDPOINT_PRESETS = [
  { label: '香港 (ap-southeast-1 · 国际版推荐)', value: 'https://dns.ap-southeast-1.myhuaweicloud.com' },
  { label: '新加坡 (ap-southeast-3)', value: 'https://dns.ap-southeast-3.myhuaweicloud.com' },
  { label: '全局默认 (dns.myhuaweicloud.com)', value: 'https://dns.myhuaweicloud.com' },
  { label: '自定义 Endpoint', value: '__custom__' },
];

export function SettingsPage() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = searchParams.get('tab');
  const activeTab: SettingsTab =
    rawTab === 'dns-rules'
      ? 'dns-rules'
      : rawTab === 'webhooks'
        ? 'webhooks'
        : rawTab === 'cloud-dns'
          ? 'cloud-dns'
          : 'general';

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

  // Huawei Cloud DNS state
  const [hwEndpoint, setHwEndpoint] = useState('https://dns.ap-southeast-1.myhuaweicloud.com');
  const [hwAK, setHwAK] = useState('');
  const [hwSK, setHwSK] = useState('');
  const [hwSaving, setHwSaving] = useState(false);
  const [hwTesting, setHwTesting] = useState(false);
  const [hwZones, setHwZones] = useState<HuaweiCloudZone[] | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getSettings();
      setForm(data);
      setHwEndpoint(data.huaweicloud_dns_endpoint || 'https://dns.ap-southeast-1.myhuaweicloud.com');
      setHwAK(data.huaweicloud_dns_ak || '');
      setHwSK('');
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
        site_title: form.site_title,
        announcement: form.announcement,
        percentage_only: form.percentage_only,
        admin_sub_token: form.admin_sub_token,
        alert_cooldown_minutes: form.alert_cooldown_minutes,
        warning_threshold_percent: form.warning_threshold_percent,
        offline_timeout_seconds: form.offline_timeout_seconds,
        default_upstream_dns: form.default_upstream_dns,
        default_local_dns_port: form.default_local_dns_port,
        agent_docker_image: dockerImage,
        traffic_log_max_entries: form.traffic_log_max_entries,
        alert_user_expired: form.alert_user_expired,
        alert_user_quota_exhausted: form.alert_user_quota_exhausted,
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
          onClick={() => switchTab('cloud-dns')}
          className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors ${
            activeTab === 'cloud-dns'
              ? 'bg-indigo-600 text-white dark:bg-indigo-500'
              : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-800 dark:hover:bg-slate-800'
          }`}
        >
          <Cloud className="h-4 w-4" />
          云解析 DNS
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
      ) : activeTab === 'cloud-dns' ? (
        <div className="space-y-6">
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setHwSaving(true);
              try {
                const payload: UpdateSettingsRequest = {
                  huaweicloud_dns_endpoint: hwEndpoint.trim(),
                  huaweicloud_dns_ak: hwAK.trim(),
                };
                if (hwSK.trim()) {
                  payload.huaweicloud_dns_sk = hwSK.trim();
                }
                const updated = await api.updateSettings(payload);
                setForm(updated);
                setHwEndpoint(updated.huaweicloud_dns_endpoint);
                setHwAK(updated.huaweicloud_dns_ak);
                setHwSK('');
                toast.success('华为云国际版 DNS 配置已保存');
              } catch (err) {
                toast.error(err instanceof ApiError ? err.message : '保存华为云 DNS 配置失败');
              } finally {
                setHwSaving(false);
              }
            }}
            className="card space-y-5 p-4 sm:p-5"
          >
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">
                华为云国际版 DNS（Cloud DNS）凭据
              </h2>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                用于「负载均衡分组」自动调度与更新域名 A 记录。SK 将在服务端持久化，页面仅展示脱敏标识。
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium">API Endpoint 预设</label>
                <select
                  className="input-field"
                  value={
                    HUAWEICLOUD_ENDPOINT_PRESETS.some((p) => p.value === hwEndpoint)
                      ? hwEndpoint
                      : '__custom__'
                  }
                  onChange={(e) => {
                    if (e.target.value !== '__custom__') {
                      setHwEndpoint(e.target.value);
                    }
                  }}
                >
                  {HUAWEICLOUD_ENDPOINT_PRESETS.map((p) => (
                    <option key={p.value} value={p.value}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Endpoint URL</label>
                <input
                  type="url"
                  className="input-field font-mono text-xs"
                  value={hwEndpoint}
                  onChange={(e) => setHwEndpoint(e.target.value)}
                  placeholder="https://dns.ap-southeast-1.myhuaweicloud.com"
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Access Key (AK)</label>
                <input
                  type="text"
                  className="input-field font-mono text-xs"
                  value={hwAK}
                  onChange={(e) => setHwAK(e.target.value)}
                  placeholder="输入华为云 IAM Access Key ID"
                />
              </div>
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <label className="text-xs font-medium">Secret Key (SK)</label>
                  {form?.huaweicloud_dns_sk_configured && (
                    <span className="font-mono text-[11px] text-emerald-600 dark:text-emerald-400">
                      已配置 ({form.huaweicloud_dns_sk_masked})
                    </span>
                  )}
                </div>
                <input
                  type="password"
                  className="input-field font-mono text-xs"
                  value={hwSK}
                  onChange={(e) => setHwSK(e.target.value)}
                  placeholder={
                    form?.huaweicloud_dns_sk_configured
                      ? '留空则保持现有 SK 不变'
                      : '输入华为云 IAM Secret Access Key'
                  }
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-100 pt-4 dark:border-slate-800">
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={hwTesting}
                  onClick={async () => {
                    setHwTesting(true);
                    try {
                      const res = await api.testHuaweiCloudDNS({
                        endpoint: hwEndpoint.trim(),
                        ak: hwAK.trim(),
                        sk: hwSK.trim(),
                      });
                      setHwZones(res.zones);
                      toast.success(`连接成功，共拉取到 ${res.zones_count} 个公网域名 Zone`);
                    } catch (err) {
                      toast.error(err instanceof ApiError ? err.message : '测试华为云 DNS 连接失败');
                    } finally {
                      setHwTesting(false);
                    }
                  }}
                  className="btn-secondary"
                >
                  <RefreshCw className={`h-4 w-4 ${hwTesting ? 'animate-spin' : ''}`} />
                  {hwTesting ? '正在测试...' : '测试连接并拉取域名'}
                </button>
                {form?.huaweicloud_dns_sk_configured && (
                  <button
                    type="button"
                    onClick={async () => {
                      if (!window.confirm('确定清除已保存的华为云 Secret Key 吗？')) return;
                      try {
                        const updated = await api.updateSettings({ clear_huaweicloud_dns_sk: true });
                        setForm(updated);
                        setHwSK('');
                        toast.success('已清除 Secret Key');
                      } catch (err) {
                        toast.error(err instanceof ApiError ? err.message : '清除失败');
                      }
                    }}
                    className="btn-danger text-xs"
                  >
                    清除 SK
                  </button>
                )}
              </div>
              <button type="submit" disabled={hwSaving} className="btn-primary">
                <Save className="h-4 w-4" />
                {hwSaving ? '保存中...' : '保存凭据'}
              </button>
            </div>
          </form>

          {hwZones !== null && (
            <div className="card space-y-3 p-4 sm:p-5">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                  已获取的公网 Zone 列表（{hwZones.length}）
                </h3>
              </div>
              {hwZones.length === 0 ? (
                <p className="text-xs text-slate-500">当前账号下暂无公网域名 Zone。</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-left text-xs dark:divide-slate-800">
                    <thead className="text-slate-500">
                      <tr>
                        <th className="py-2 pr-4 font-medium">域名</th>
                        <th className="py-2 pr-4 font-medium">Zone ID</th>
                        <th className="py-2 pr-4 font-medium">状态</th>
                        <th className="py-2 pr-4 font-medium">默认 TTL</th>
                        <th className="py-2 font-medium">记录数</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70">
                      {hwZones.map((z) => (
                        <tr key={z.id}>
                          <td className="py-2 pr-4 font-semibold text-slate-900 dark:text-white">{z.name}</td>
                          <td className="py-2 pr-4 font-mono text-[11px] text-slate-500">{z.id}</td>
                          <td className="py-2 pr-4">{z.status}</td>
                          <td className="py-2 pr-4 font-mono">{z.ttl}s</td>
                          <td className="py-2 font-mono">{z.record_num}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
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
