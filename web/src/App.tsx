import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ThemeProvider } from './contexts/ThemeContext';
import { ToastProvider } from './contexts/ToastContext';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { StatusPage } from './pages/status/StatusPage';
import { LoginPage } from './pages/admin/LoginPage';
import { AdminLayout } from './pages/admin/AdminLayout';
import { OverviewPage } from './pages/admin/OverviewPage';
import { NodesPage } from './pages/admin/NodesPage';
import { UsersPage } from './pages/admin/UsersPage';
import { TemplatesPage } from './pages/admin/TemplatesPage';
import { KernelsPage } from './pages/admin/KernelsPage';
import { TrafficPage } from './pages/admin/TrafficPage';
import { SettingsPage } from './pages/admin/SettingsPage';

function AdminGate() {
  const { loading, isAuthenticated } = useAuth();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 text-sm text-slate-500 dark:bg-slate-950 dark:text-slate-400">
        正在验证登录状态...
      </div>
    );
  }
  if (!isAuthenticated) {
    return <LoginPage />;
  }
  return <AdminLayout />;
}

export function App() {
  return (
    <ThemeProvider>
      <ToastProvider>
        <AuthProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/" element={<StatusPage />} />
              <Route path="/admin" element={<AdminGate />}>
                <Route index element={<OverviewPage />} />
                <Route path="nodes" element={<NodesPage />} />
                <Route path="users" element={<UsersPage />} />
                <Route path="dns-rules" element={<Navigate to="/admin/settings?tab=dns-rules" replace />} />
                <Route path="templates" element={<TemplatesPage />} />
                <Route path="kernels" element={<KernelsPage />} />
                <Route path="webhooks" element={<Navigate to="/admin/settings?tab=webhooks" replace />} />
                <Route path="traffic" element={<TrafficPage />} />
                <Route path="settings" element={<SettingsPage />} />
                <Route path="*" element={<Navigate to="/admin" replace />} />
              </Route>
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </BrowserRouter>
        </AuthProvider>
      </ToastProvider>
    </ThemeProvider>
  );
}

export default App;
