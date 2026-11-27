import React, { useEffect, useState } from 'react';
import { Link, NavLink, Outlet } from 'react-router-dom';
import {
  Activity,
  BarChart3,
  Cpu,
  ExternalLink,
  FileCode2,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Server,
  Settings,
  Sun,
  Users,
  X,
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useTheme } from '../../contexts/ThemeContext';
import { useToast } from '../../contexts/ToastContext';
import { api, ApiError } from '../../api/client';
import { Modal } from '../../components/Modal';

const NAV_ITEMS = [
  { to: '/admin', label: '概览', icon: LayoutDashboard, end: true },
  { to: '/admin/nodes', label: '节点管理', icon: Server, end: false },
  { to: '/admin/users', label: '用户管理', icon: Users, end: false },
  { to: '/admin/templates', label: '订阅模板', icon: FileCode2, end: false },
  { to: '/admin/kernels', label: '内核管理', icon: Cpu, end: false },
  { to: '/admin/traffic', label: '流量统计', icon: BarChart3, end: false },
  { to: '/admin/settings', label: '系统设置', icon: Settings, end: false },
];

export function AdminLayout() {
  const { logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const toast = useToast();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    if (!sidebarOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSidebarOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [sidebarOpen]);

  // Change password modal
  const [pwOpen, setPwOpen] = useState(false);
  const [oldPw, setOldPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [pwSaving, setPwSaving] = useState(false);

  const openPwModal = () => {
    setOldPw('');
    setNewPw('');
    setConfirmPw('');
    setPwOpen(true);
  };

  const closePwModal = () => {
    setPwOpen(false);
    setOldPw('');
    setNewPw('');
    setConfirmPw('');
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!oldPw || !newPw) {
      toast.error('请填写当前密码和新密码');
      return;
    }
    if (newPw !== confirmPw) {
      toast.error('两次输入的新密码不一致');
      return;
    }
    setPwSaving(true);
    try {
      await api.changePassword({ old_password: oldPw, new_password: newPw });
      toast.success('管理员密码已更新');
      setPwOpen(false);
      setOldPw('');
      setNewPw('');
      setConfirmPw('');
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : '修改密码失败');
    } finally {
      setPwSaving(false);
    }
  };

  const navContent = (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4 dark:border-slate-800">
        <Link to="/admin" className="flex items-center gap-2.5" onClick={() => setSidebarOpen(false)}>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 text-white dark:bg-indigo-500">
            <Activity className="h-4 w-4" />
          </div>
          <span className="text-base font-bold tracking-tight text-slate-900 dark:text-white">
            ShadowOrbit
          </span>
        </Link>
        <button
          type="button"
          onClick={() => setSidebarOpen(false)}
          className="rounded-lg p-1 text-slate-500 hover:bg-slate-100 lg:hidden dark:hover:bg-slate-800"
          aria-label="关闭侧边栏"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-indigo-50 text-indigo-700 dark:bg-indigo-950/70 dark:text-indigo-300'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/70 dark:hover:text-slate-100'
                }`
              }
            >
              <Icon className="h-4 w-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      <div className="border-t border-slate-200 p-3 dark:border-slate-800">
        <a
          href="/"
          target="_blank"
          rel="noopener noreferrer"
          onClick={() => setSidebarOpen(false)}
          className="flex items-center justify-between rounded-lg px-3 py-2 text-xs font-medium text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
        >
          <span>公开状态页</span>
          <ExternalLink className="h-3.5 w-3.5" />
        </a>
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen overflow-x-hidden bg-slate-50 dark:bg-slate-950">
      {/* Desktop Sidebar (fixed so footer links stay anchored at bottom-left on long pages) */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 lg:block">
        {navContent}
      </aside>

      {/* Mobile Sidebar */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-40 flex lg:hidden">
          <div className="fixed inset-0 bg-slate-950/60" onClick={() => setSidebarOpen(false)} />
          <aside className="relative z-10 h-full w-64 max-w-[80vw] bg-white shadow-xl dark:bg-slate-900">
            {navContent}
          </aside>
        </div>
      )}

      {/* Main Content */}
      <div className="flex min-w-0 flex-1 flex-col lg:pl-60">
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between gap-2 border-b border-slate-200 bg-white/85 px-3 backdrop-blur dark:border-slate-800 dark:bg-slate-900/85 sm:px-6">
          <div className="flex min-w-0 items-center gap-2.5 sm:gap-3">
            <button
              type="button"
              onClick={() => setSidebarOpen(true)}
              className="shrink-0 rounded-lg p-1.5 text-slate-600 hover:bg-slate-100 lg:hidden dark:text-slate-300 dark:hover:bg-slate-800"
              aria-label="打开菜单"
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="flex items-center gap-1.5 lg:hidden">
              <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-indigo-600 text-white dark:bg-indigo-500">
                <Activity className="h-3.5 w-3.5" />
              </div>
              <span className="truncate text-sm font-bold text-slate-900 dark:text-white">
                ShadowOrbit
              </span>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-1.5 sm:gap-2">
            <button
              type="button"
              onClick={openPwModal}
              className="btn-secondary px-2 py-1.5 text-xs sm:px-2.5"
              title="修改管理员密码"
              aria-label="修改管理员密码"
            >
              <KeyRound className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">修改密码</span>
            </button>
            <button
              type="button"
              onClick={toggleTheme}
              className="btn-secondary p-1.5"
              aria-label="切换明暗主题"
            >
              {theme === 'dark' ? <Sun className="h-4 w-4 text-amber-400" /> : <Moon className="h-4 w-4" />}
            </button>
            <button
              type="button"
              onClick={logout}
              className="btn-secondary px-2 py-1.5 text-xs text-rose-600 hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-950/50 sm:px-2.5"
              aria-label="退出登录"
              title="退出登录"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">退出登录</span>
            </button>
          </div>
        </header>

        <main className="flex-1 p-3 sm:p-6 lg:p-8">
          <Outlet />
        </main>
      </div>

      <Modal
        open={pwOpen}
        onClose={closePwModal}
        title="修改管理员密码"
        maxWidthClass="max-w-md"
        footer={
          <>
            <button type="button" onClick={closePwModal} className="btn-secondary">
              取消
            </button>
            <button
              type="submit"
              form="change-pw-form"
              disabled={pwSaving}
              className="btn-primary"
            >
              {pwSaving ? '保存中...' : '确认修改'}
            </button>
          </>
        }
      >
        <form id="change-pw-form" onSubmit={handleChangePassword} className="space-y-4">
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">
              当前密码
            </label>
            <input
              type="password"
              className="input-field"
              value={oldPw}
              onChange={(e) => setOldPw(e.target.value)}
              placeholder="请输入当前密码"
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">
              新密码
            </label>
            <input
              type="password"
              className="input-field"
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              placeholder="请输入新密码（不超过 72 字节）"
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">
              确认新密码
            </label>
            <input
              type="password"
              className="input-field"
              value={confirmPw}
              onChange={(e) => setConfirmPw(e.target.value)}
              placeholder="请再次输入新密码"
              required
            />
          </div>
        </form>
      </Modal>
    </div>
  );
}
