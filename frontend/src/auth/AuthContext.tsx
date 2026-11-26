import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { apiRequest, ApiError } from '../api/client'
import { AuthContext } from './context'
import { clearAccessToken, setAccessToken } from './tokenStore'

const unauthorizedEvent = 'sentinelkey:unauthorized'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  const signOut = useCallback(() => {
    clearAccessToken()
    setIsAuthenticated(false)
  }, [])

  const signIn = useCallback(async (candidate: string) => {
    const token = candidate.trim()
    if (!token) throw new ApiError(400, 'Paste a development or OIDC bearer token.')

    clearAccessToken()
    setIsAuthenticated(false)
    setAccessToken(token)
    try {
      await apiRequest('/api/v1/tenants')
      setIsAuthenticated(true)
    } catch (error) {
      clearAccessToken()
      setIsAuthenticated(false)
      throw error
    }
  }, [])

  useEffect(() => {
    window.addEventListener(unauthorizedEvent, signOut)
    return () => window.removeEventListener(unauthorizedEvent, signOut)
  }, [signOut])

  const value = useMemo(
    () => ({
      isAuthenticated,
      signIn,
      signOut,
    }),
    [isAuthenticated, signIn, signOut],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
