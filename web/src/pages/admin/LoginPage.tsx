import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Lock, Moon, Shield, Sun, User } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useTheme } from '../../contexts/ThemeContext';
import { ApiError } from '../../api/client';

export function LoginPage() {
  const { login } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('请输入用户名和密码');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await login(username.trim(), password);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('登录失败');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="relative flex min-h-screen flex-col justify-center bg-slate-50 px-4 pb-10 pt-16 dark:bg-slate-950 sm:px-6 lg:px-8">
      <div className="absolute right-4 top-4 flex items-center gap-2">
        <Link to="/" className="btn-secondary px-3 py-1.5 text-xs">
          <ArrowLeft className="h-3.5 w-3.5" />
          公开状态页
        </Link>
        <button
          type="button"
          onClick={toggleTheme}
          className="btn-secondary p-2"
          aria-label="切换明暗主题"
        >
          {theme === 'dark' ? <Sun className="h-4 w-4 text-amber-400" /> : <Moon className="h-4 w-4" />}
        </button>
      </div>

      <div className="mx-auto w-full max-w-md">
        <div className="flex flex-col items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-indigo-600 text-white shadow-md dark:bg-indigo-500">
            <Shield className="h-6 w-6" />
          </div>
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            ShadowOrbit 管理后台
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            登录后可管理节点、用户、订阅配置与告警通道
          </p>
        </div>

        <form onSubmit={handleSubmit} className="card mt-8 space-y-5 p-6 sm:p-8">
          {error && (
            <div className="rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/50 dark:text-rose-300">
              {error}
            </div>
          )}

          <div>
            <label htmlFor="login-username" className="mb-1.5 block text-xs font-medium text-slate-700 dark:text-slate-300">
              管理员用户名
            </label>
            <div className="relative">
              <User className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
              <input
                id="login-username"
                type="text"
                autoComplete="username"
                className="input-field pl-9"
                placeholder="请输入管理员用户名"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
          </div>

          <div>
            <label htmlFor="login-password" className="mb-1.5 block text-xs font-medium text-slate-700 dark:text-slate-300">
              密码
            </label>
            <div className="relative">
              <Lock className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
              <input
                id="login-password"
                type="password"
                autoComplete="current-password"
                className="input-field pl-9"
                placeholder="请输入密码"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
          </div>

          <button type="submit" disabled={submitting} className="btn-primary w-full py-2.5">
            {submitting ? '正在登录...' : '立即登录'}
          </button>
        </form>
      </div>
    </div>
  );
}
