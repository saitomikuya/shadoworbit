import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import {
  api,
  getStoredToken,
  setStoredToken,
  setUnauthorizedHandler,
} from '../api/client';

interface AuthContextValue {
  loading: boolean;
  isAuthenticated: boolean;
  login: (password: string) => Promise<void>;
  logout: () => void;
  refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);

  const logout = useCallback(() => {
    setStoredToken(null);
    setIsAuthenticated(false);
  }, []);

  const refreshSession = useCallback(async () => {
    const token = getStoredToken();
    if (!token) {
      setIsAuthenticated(false);
      setLoading(false);
      return;
    }
    try {
      await api.getMe();
      setIsAuthenticated(true);
    } catch {
      setStoredToken(null);
      setIsAuthenticated(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setIsAuthenticated(false);
    });
    void refreshSession();
    return () => setUnauthorizedHandler(null);
  }, [refreshSession]);

  const login = useCallback(async (password: string) => {
    const res = await api.login({ password });
    setStoredToken(res.token);
    setIsAuthenticated(true);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        loading,
        isAuthenticated,
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
