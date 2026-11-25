import type {
  AddSnellVersionRequest,
  AdminTrafficResponse,
  AuthMeResponse,
  CalibrateTrafficRequest,
  ChangePasswordRequest,
  CreateUserRequest,
  DailyTrafficEntry,
  DailyTrafficQuery,
  DNSRuleGroup,
  DNSRuleGroupRequest,
  InstallCmdResponse,
  KernelCatalog,
  KernelUpdateBatchResult,
  KernelUpdateRequest,
  LoginRequest,
  LoginResponse,
  NodeDTO,
  NodeSyncResponse,
  NodeUpsertRequest,
  PublicStatusSnapshot,
  ResetKeysRequest,
  ServiceCtlAction,
  ServiceCtlResponse,
  SnellVersionEntry,
  SubMode,
  SubTarget,
  SubTemplate,
  SubTemplateRequest,
  SystemSettings,
  TemplateClientType,
  TrafficUsageLogQuery,
  TrafficUsageLogsResponse,
  UpdateUserRequest,
  UserDTO,
  UserTrafficBreakdownResponse,
  WebhookChannel,
  WebhookChannelRequest,
} from '../types/api';

export const TOKEN_STORAGE_KEY = 'snell_admin_jwt';

export class ApiError extends Error {
  status: number;
  data?: unknown;

  constructor(status: number, message: string, data?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

type UnauthorizedHandler = () => void;
let unauthorizedHandler: UnauthorizedHandler | null = null;

export function setUnauthorizedHandler(handler: UnauthorizedHandler | null) {
  unauthorizedHandler = handler;
}

export function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setStoredToken(token: string | null) {
  try {
    if (token) {
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // ignore storage failures
  }
}

async function parseResponseBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  auth?: boolean;
  allowKernelBatch400?: boolean;
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, auth = true, allowKernelBatch400 = false } = opts;
  const headers: Record<string, string> = {};

  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (auth) {
    const token = getStoredToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }

  const res = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const data = await parseResponseBody(res);

  if (res.status === 401 && path !== '/api/v1/auth/login') {
    setStoredToken(null);
    if (unauthorizedHandler) {
      unauthorizedHandler();
    }
  }

  if (!res.ok) {
    if (
      allowKernelBatch400 &&
      res.status === 400 &&
      data &&
      typeof data === 'object' &&
      Array.isArray((data as { results?: unknown }).results)
    ) {
      return data as T;
    }

    const msg =
      data && typeof data === 'object' && typeof (data as { error?: unknown }).error === 'string'
        ? (data as { error: string }).error
        : typeof data === 'string' && data
          ? data
          : res.statusText || `HTTP ${res.status}`;
    throw new ApiError(res.status, msg, data);
  }

  return data as T;
}

export function buildPublicWsUrl(): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}/api/v1/public/ws`;
}

export function buildAdminSubUrl(
  adminSubToken: string,
  mode: SubMode = 'full',
  tplId?: number | null
): string {
  const params = new URLSearchParams();
  params.set('mode', mode);
  if (tplId && tplId > 0) {
    params.set('tpl', String(tplId));
  }
  return `${window.location.origin}/s/admin/${encodeURIComponent(adminSubToken)}/ShadowOrbit.conf?${params.toString()}`;
}

export function buildUserSubUrl(
  subToken: string,
  target: SubTarget = 'mihomo',
  mode: SubMode = 'full',
  tplId?: number | null
): string {
  const params = new URLSearchParams();
  params.set('target', target);
  if (target !== 'shadowrocket') {
    params.set('mode', mode);
    if (tplId && tplId > 0) {
      params.set('tpl', String(tplId));
    }
  }
  const filename =
    target === 'surge'
      ? 'ShadowOrbit.conf'
      : target === 'mihomo'
        ? 'ShadowOrbit.yaml'
        : 'ShadowOrbit.txt';
  return `${window.location.origin}/s/u/${encodeURIComponent(subToken)}/${filename}?${params.toString()}`;
}

export const api = {
  // Public
  getPublicStatus: () => request<PublicStatusSnapshot>('/api/v1/public/status', { auth: false }),

  // Auth
  login: (payload: LoginRequest) =>
    request<LoginResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: payload,
      auth: false,
    }),
  getMe: () => request<AuthMeResponse>('/api/v1/auth/me'),
  changePassword: (payload: ChangePasswordRequest) =>
    request<{ status: string }>('/api/v1/auth/password', {
      method: 'PUT',
      body: payload,
    }),

  // Nodes
  listNodes: () => request<NodeDTO[]>('/api/v1/admin/nodes'),
  getNode: (id: number) => request<NodeDTO>(`/api/v1/admin/nodes/${id}`),
  createNode: (payload: NodeUpsertRequest) =>
    request<NodeDTO>('/api/v1/admin/nodes', { method: 'POST', body: payload }),
  updateNode: (id: number, payload: NodeUpsertRequest) =>
    request<NodeDTO>(`/api/v1/admin/nodes/${id}`, { method: 'PUT', body: payload }),
  deleteNode: (id: number) =>
    request<{ status: string }>(`/api/v1/admin/nodes/${id}`, { method: 'DELETE' }),
  reorderNodes: (ids: number[]) =>
    request<{ status: string; ids: number[] }>('/api/v1/admin/nodes/reorder', {
      method: 'PUT',
      body: { ids },
    }),
  resetNodeTraffic: (id: number) =>
    request<NodeDTO>(`/api/v1/admin/nodes/${id}/reset-traffic`, { method: 'POST' }),
  calibrateNodeTraffic: (id: number, payload: CalibrateTrafficRequest) =>
    request<NodeDTO>(`/api/v1/admin/nodes/${id}/calibrate-traffic`, {
      method: 'POST',
      body: payload,
    }),
  serviceCtlNode: (id: number, action: ServiceCtlAction) =>
    request<ServiceCtlResponse>(`/api/v1/admin/nodes/${id}/service-ctl`, {
      method: 'POST',
      body: { action },
    }),
  syncNode: (id: number) =>
    request<NodeSyncResponse>(`/api/v1/admin/nodes/${id}/sync`, { method: 'POST' }),
  getNodeInstallCmd: (id: number) =>
    request<InstallCmdResponse>(`/api/v1/admin/nodes/${id}/install-cmd`),

  // DNS Rule Groups
  listDnsRules: () => request<DNSRuleGroup[]>('/api/v1/admin/dns-rules'),
  createDnsRule: (payload: DNSRuleGroupRequest) =>
    request<DNSRuleGroup>('/api/v1/admin/dns-rules', { method: 'POST', body: payload }),
  updateDnsRule: (id: number, payload: DNSRuleGroupRequest) =>
    request<DNSRuleGroup>(`/api/v1/admin/dns-rules/${id}`, { method: 'PUT', body: payload }),
  deleteDnsRule: (id: number) =>
    request<{ status: string }>(`/api/v1/admin/dns-rules/${id}`, { method: 'DELETE' }),

  // Users
  listUsers: () => request<UserDTO[]>('/api/v1/admin/users'),
  createUser: (payload: CreateUserRequest) =>
    request<UserDTO>('/api/v1/admin/users', { method: 'POST', body: payload }),
  updateUser: (id: number, payload: UpdateUserRequest) =>
    request<UserDTO>(`/api/v1/admin/users/${id}`, { method: 'PUT', body: payload }),
  deleteUser: (id: number) =>
    request<{ status: string }>(`/api/v1/admin/users/${id}`, { method: 'DELETE' }),
  resetUserKeys: (id: number, payload: ResetKeysRequest) =>
    request<UserDTO>(`/api/v1/admin/users/${id}/reset-keys`, {
      method: 'POST',
      body: payload,
    }),
  resetUserTraffic: (id: number) =>
    request<UserDTO>(`/api/v1/admin/users/${id}/reset-traffic`, { method: 'POST' }),
  getUserTrafficBreakdown: (id: number) =>
    request<UserTrafficBreakdownResponse>(`/api/v1/admin/users/${id}/traffic-breakdown`),
  getAdminTraffic: () => request<AdminTrafficResponse>('/api/v1/admin/admin-traffic'),
  resetAdminTraffic: () => request<{ status: string }>('/api/v1/admin/admin-traffic/reset', { method: 'POST' }),
  getUserNodes: (id: number) =>
    request<{ node_ids: number[] }>(`/api/v1/admin/users/${id}/nodes`),
  setUserNodes: (id: number, nodeIds: number[]) =>
    request<{ node_ids: number[] }>(`/api/v1/admin/users/${id}/nodes`, {
      method: 'PUT',
      body: { node_ids: nodeIds },
    }),

  // Templates
  listTemplates: (clientType?: TemplateClientType) => {
    const qs = clientType ? `?client_type=${encodeURIComponent(clientType)}` : '';
    return request<SubTemplate[]>(`/api/v1/admin/templates${qs}`);
  },
  createTemplate: (payload: SubTemplateRequest) =>
    request<SubTemplate>('/api/v1/admin/templates', { method: 'POST', body: payload }),
  updateTemplate: (id: number, payload: SubTemplateRequest) =>
    request<SubTemplate>(`/api/v1/admin/templates/${id}`, { method: 'PUT', body: payload }),
  deleteTemplate: (id: number) =>
    request<{ status: string }>(`/api/v1/admin/templates/${id}`, { method: 'DELETE' }),

  // Kernels
  getKernels: () => request<KernelCatalog>('/api/v1/admin/kernels'),
  syncKernels: () => request<KernelCatalog>('/api/v1/admin/kernels/sync', { method: 'POST' }),
  addSnellVersion: (payload: AddSnellVersionRequest) =>
    request<SnellVersionEntry>('/api/v1/admin/kernels/snell-versions', {
      method: 'POST',
      body: payload,
    }),
  deleteSnellVersion: (version: string) =>
    request<{ status: string; version: string }>(
      `/api/v1/admin/kernels/snell-versions/${encodeURIComponent(version)}`,
      { method: 'DELETE' }
    ),
  updateKernels: (payload: KernelUpdateRequest) =>
    request<KernelUpdateBatchResult>('/api/v1/admin/kernels/update', {
      method: 'POST',
      body: payload,
      allowKernelBatch400: true,
    }),

  // Webhooks
  listWebhooks: () => request<WebhookChannel[]>('/api/v1/admin/webhooks'),
  createWebhook: (payload: WebhookChannelRequest) =>
    request<WebhookChannel>('/api/v1/admin/webhooks', { method: 'POST', body: payload }),
  updateWebhook: (id: number, payload: WebhookChannelRequest) =>
    request<WebhookChannel>(`/api/v1/admin/webhooks/${id}`, { method: 'PUT', body: payload }),
  deleteWebhook: (id: number) =>
    request<{ status: string }>(`/api/v1/admin/webhooks/${id}`, { method: 'DELETE' }),
  testWebhook: (id: number) =>
    request<{ status: string }>(`/api/v1/admin/webhooks/${id}/test`, { method: 'POST' }),

  // Traffic Logs
  getDailyTraffic: (query: DailyTrafficQuery) => {
    const params = new URLSearchParams();
    if (query.target_type) params.set('target_type', query.target_type);
    if (query.target_id && query.target_id > 0) params.set('target_id', String(query.target_id));
    if (query.from_date) params.set('from_date', query.from_date);
    if (query.to_date) params.set('to_date', query.to_date);
    const qs = params.toString();
    return request<DailyTrafficEntry[]>(`/api/v1/admin/traffic/daily${qs ? `?${qs}` : ''}`);
  },
  getTrafficLogs: (query: TrafficUsageLogQuery) => {
    const params = new URLSearchParams();
    if (query.node_id && query.node_id > 0) params.set('node_id', String(query.node_id));
    if (query.user_id !== undefined && query.user_id >= 0) params.set('user_id', String(query.user_id));
    if (query.from) params.set('from', query.from);
    if (query.to) params.set('to', query.to);
    if (query.limit && query.limit > 0) params.set('limit', String(query.limit));
    if (query.merge !== undefined) params.set('merge', String(query.merge));
    if (query.merge_gap_minutes && query.merge_gap_minutes > 0) {
      params.set('merge_gap_minutes', String(query.merge_gap_minutes));
    }
    const qs = params.toString();
    return request<TrafficUsageLogsResponse>(`/api/v1/admin/traffic/logs${qs ? `?${qs}` : ''}`);
  },

  // System Settings
  getSettings: () => request<SystemSettings>('/api/v1/admin/settings'),
  updateSettings: (payload: Partial<SystemSettings>) =>
    request<SystemSettings>('/api/v1/admin/settings', { method: 'PUT', body: payload }),
};
