import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import {
  api,
  getStoredToken,
  setStoredToken,
  setUnauthorizedHandler,
} from '../api/client';

interface AuthContextValue {
  username: string | null;
  loading: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [username, setUsername] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const logout = useCallback(() => {
    setStoredToken(null);
    setUsername(null);
  }, []);

  const refreshSession = useCallback(async () => {
    const token = getStoredToken();
    if (!token) {
      setUsername(null);
      setLoading(false);
      return;
    }
    try {
      const me = await api.getMe();
      setUsername(me.username);
    } catch {
      setStoredToken(null);
      setUsername(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUsername(null);
    });
    void refreshSession();
    return () => setUnauthorizedHandler(null);
  }, [refreshSession]);

  const login = useCallback(async (user: string, password: string) => {
    const res = await api.login({ username: user, password });
    setStoredToken(res.token);
    setUsername(res.username);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        username,
        loading,
        isAuthenticated: Boolean(username),
        login,
        logout,
        refreshSession,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
