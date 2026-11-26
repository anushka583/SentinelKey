import { createContext } from 'react'

export interface AuthContextValue {
  isAuthenticated: boolean
  signIn: (token: string) => Promise<void>
  signOut: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)
