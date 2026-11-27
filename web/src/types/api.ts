export type NodeStatus = 'online' | 'offline' | 'traffic_paused';
export type SnellVersion = 'v4' | 'v5';
export type SnellObfs = 'off' | 'http' | 'tls';
export type DNSIPPreference = 'prefer-ipv4' | 'prefer-ipv6' | 'ipv4-only' | 'auto';
export type SSCipher = '2022-blake3-aes-128-gcm' | '2022-blake3-aes-256-gcm';
export type TrafficCountMode = 'both' | 'tx_only' | 'rx_only' | 'max_dir';
export type ThresholdAction = 'stop_all' | 'stop_ss_only';
export type ServiceCtlAction = 'restart_snell' | 'restart_singbox' | 'restart_all';
export type SubTarget = 'mihomo' | 'surge' | 'shadowrocket';
export type SubMode = 'full' | 'proxy';
export type TemplateClientType = 'surge_admin' | 'mihomo_user' | 'surge_user';
export type KernelName = 'sing-box' | 'snell-server' | 'shadow-tls';
export type WebhookProvider = 'feishu' | 'dingtalk' | 'wecom' | 'serverchan' | 'custom';

export const CANONICAL_WEBHOOK_EVENTS = [
  'node_offline',
  'node_online',
  'process_crashed',
  'kernel_update',
  'config_error',
  'traffic_warning',
  'traffic_paused',
  'traffic_recovered',
  'user_quota_exhausted',
  'user_expired',
  'high_resource_usage',
] as const;

export interface PublicNodeView {
  id: number;
  name: string;
  region_tag: string;
  sort_order: number;
  status: NodeStatus;
  paused_reason: string;
  billing_reset_day: number;
  cpu_percent: number;
  mem_used_bytes: number;
  mem_total_bytes: number;
  uptime_seconds: number;
  rx_bps: number;
  tx_bps: number;
  total_rx_bytes: number;
  total_tx_bytes: number;
  traffic_used_bytes: number;
  traffic_limit_bytes: number;
  traffic_percent: number;
  percentage_only: boolean;
  core_a_healthy: boolean;
  core_b_healthy: boolean;
}

export interface PublicStatusSnapshot {
  site_title: string;
  announcement: string;
  percentage_only: boolean;
  nodes: PublicNodeView[];
}

export interface LoginRequest {
  password: string;
}

export interface LoginResponse {
  token: string;
}

export interface AuthMeResponse {
  authenticated: boolean;
}

export interface ChangePasswordRequest {
  old_password: string;
  new_password: string;
}

export interface SnellConfig {
  enabled: boolean;
  version: SnellVersion | '';
  public_port: number;
  inner_port: number;
  psk: string;
  obfs: SnellObfs | '';
  tfo: boolean;
  dns_ip_preference: DNSIPPreference | '';
  stls_password: string;
  stls_sni: string;
}

export interface SSConfig {
  enabled: boolean;
  tcp_port: number;
  udp_port: number;
  cipher: SSCipher | '';
  ipsk: string;
  stls_sni: string;
  tfo: boolean;
  users?: null;
}

export interface AgentVersions {
  sing_box: string;
  snell_server: string;
  shadow_tls: string;
}

export interface NodeDTO {
  id: number;
  name: string;
  region_tag: string;
  node_token?: string;
  public_ip: string;
  public_ipv6: string;
  custom_entry_host: string;
  custom_entry_port: number;
  sort_order: number;
  enabled: boolean;
  status: NodeStatus;
  paused_reason: string;
  snell_config: SnellConfig;
  ss_config: SSConfig;
  dns_unlock_enabled: boolean;
  dns_unlock_server: string;
  dns_rule_group_id: number | null;
  dns_extra_rules: string[];
  traffic_limit_bytes: number;
  traffic_threshold_bytes: number;
  traffic_count_mode: TrafficCountMode;
  threshold_action: ThresholdAction;
  billing_reset_day: number;
  cycle_rx_bytes: number;
  cycle_tx_bytes: number;
  total_rx_bytes: number;
  total_tx_bytes: number;
  last_reset_at: string | null;
  is_traffic_paused: boolean;
  config_revision: number;
  reported_config_revision: number;
  reported_versions: AgentVersions;
  agent_os: string;
  agent_arch: string;
  cpu_cores: number;
  last_seen_at: string | null;
  cpu_percent: number;
  mem_used_bytes: number;
  mem_total_bytes: number;
  disk_used_percent: number;
  uptime_seconds: number;
  rx_bps: number;
  tx_bps: number;
  core_a_healthy: boolean;
  core_b_healthy: boolean;
  created_at: string;
  updated_at: string;
}

export interface NodeUpsertRequest {
  name: string;
  region_tag: string;
  public_ip?: string;
  public_ipv6?: string;
  custom_entry_host: string;
  custom_entry_port: number;
  sort_order: number;
  enabled: boolean;
  snell_config: SnellConfig;
  ss_config: SSConfig;
  dns_unlock_enabled: boolean;
  dns_unlock_server: string;
  dns_rule_group_id: number | null;
  dns_extra_rules: string[];
  traffic_limit_bytes: number;
  traffic_threshold_bytes: number;
  traffic_count_mode: TrafficCountMode;
  threshold_action: ThresholdAction;
  billing_reset_day: number;
}

export interface InstallCmdResponse {
  node_id: number;
  panel_url: string;
  node_token: string;
  docker_image?: string;
  docker_run: string;
  docker_compose: string;
}

export interface NodeSyncResponse {
  status: string;
  synced: boolean;
  config_revision: number;
}

export interface ServiceCtlResponse {
  status: string;
  action: ServiceCtlAction;
}

export interface CalibrateTrafficRequest {
  cycle_rx_bytes: number;
  cycle_tx_bytes: number;
}

export interface DNSRuleGroup {
  id: number;
  name: string;
  description: string;
  rules: string[];
  created_at: string;
  updated_at: string;
}

export interface DNSRuleGroupRequest {
  name: string;
  description: string;
  rules: string[];
}

export interface UserDTO {
  id: number;
  username: string;
  enabled: boolean;
  sub_token: string;
  ss_upsk_16: string;
  ss_upsk_32: string;
  stls_password: string;
  traffic_quota_bytes: number;
  billing_reset_day: number;
  used_up_bytes: number;
  used_down_bytes: number;
  expire_at: string | null;
  node_ids: number[];
}

export interface CreateUserRequest {
  username: string;
  enabled?: boolean;
  traffic_quota_bytes?: number;
  billing_reset_day?: number;
  expire_at?: string | null;
  node_ids?: number[];
}

export interface UpdateUserRequest {
  username?: string;
  enabled?: boolean;
  traffic_quota_bytes?: number;
  billing_reset_day?: number;
  expire_at?: string | null;
  node_ids?: number[];
}

export interface ResetKeysRequest {
  reset_sub_token: boolean;
  reset_upsk?: boolean;
  reset_stls_password?: boolean;
}

export interface UserNodeTrafficEntry {
  node_id: number;
  node_name: string;
  region_tag: string;
  up_bytes: number;
  down_bytes: number;
  total_bytes: number;
}

export interface UserTrafficBreakdownResponse {
  user_id: number;
  username: string;
  total_up_bytes: number;
  total_down_bytes: number;
  total_bytes: number;
  items: UserNodeTrafficEntry[];
}

export interface AdminNodeTrafficEntry {
  node_id: number;
  node_name: string;
  region_tag: string;
  total_bytes: number;
}

export interface AdminTrafficResponse {
  username: string;
  total_bytes: number;
  items: AdminNodeTrafficEntry[];
}

export interface SubTemplate {
  id: number;
  name: string;
  client_type: TemplateClientType;
  content: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export interface SubTemplateRequest {
  name: string;
  client_type: TemplateClientType;
  content: string;
  is_default: boolean;
}

export interface KernelAsset {
  arch: string;
  name: string;
  download_url: string;
  sha256?: string;
  size: number;
}

export interface KernelReleaseEntry {
  version: string;
  tag_name: string;
  published_at: string;
  assets: Record<string, KernelAsset>;
}

export interface SnellVersionEntry {
  version: string;
  major: string;
  built_in: boolean;
  urls: Record<string, string>;
}

export interface KernelCatalog {
  synced_at?: string;
  'sing-box': KernelReleaseEntry[];
  'shadow-tls': KernelReleaseEntry[];
  'snell-server': SnellVersionEntry[];
}

export interface AddSnellVersionRequest {
  version: string;
  urls: Record<string, string>;
}

export interface KernelUpdateRequest {
  node_ids: number[];
  kernel: KernelName;
  version: string;
  download_url?: string;
  sha256?: string;
}

export interface KernelUpdateNodeResult {
  node_id: number;
  status: 'dispatched' | 'offline' | 'failed';
  error?: string;
}

export interface KernelUpdateBatchResult {
  dispatched: number[];
  failed: KernelUpdateNodeResult[];
  results: KernelUpdateNodeResult[];
}

export interface WebhookChannel {
  id: number;
  name: string;
  provider: WebhookProvider;
  url: string;
  secret: string;
  subscribed_events: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
  custom_template?: string;
}

export interface WebhookChannelRequest {
  name: string;
  provider: WebhookProvider;
  url: string;
  secret: string;
  subscribed_events: string[];
  enabled: boolean;
  custom_template?: string;
}

export interface DailyTrafficEntry {
  id: number;
  target_type: 'node' | 'user';
  target_id: number;
  node_id?: number;
  user_id?: number;
  date: string;
  log_date: string;
  rx_bytes: number;
  tx_bytes: number;
}

export interface DailyTrafficQuery {
  target_type?: 'node' | 'user' | '';
  target_id?: number;
  from_date?: string;
  to_date?: string;
}

export interface TrafficUsageLog {
  id: number;
  node_id: number;
  node_name: string;
  region_tag: string;
  user_id: number;
  username: string;
  log_minute: string;
  start_time?: string;
  end_time?: string;
  rx_bytes: number;
  tx_bytes: number;
  updated_at: string;
}

export interface TrafficUsageLogsResponse {
  items: TrafficUsageLog[];
  max_entries: number;
  total_stored: number;
}

export interface TrafficUsageLogQuery {
  node_id?: number;
  user_id?: number;
  from?: string;
  to?: string;
  limit?: number;
  merge?: boolean;
  merge_gap_minutes?: number;
}

export interface SystemSettings {
  site_title: string;
  announcement: string;
  percentage_only: boolean;
  admin_sub_token: string;
  alert_cooldown_minutes: number;
  warning_threshold_percent: number;
  offline_timeout_seconds: number;
  default_upstream_dns: string;
  default_local_dns_port: number;
  agent_docker_image: string;
  traffic_log_max_entries: number;
  alert_user_expired: boolean;
  alert_user_quota_exhausted: boolean;
}
