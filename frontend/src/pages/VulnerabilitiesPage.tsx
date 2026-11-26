import { Bug } from 'lucide-react'
import { RoutePlaceholder } from '../components/RoutePlaceholder'

export function VulnerabilitiesPage() {
  return (
    <RoutePlaceholder
      title="Vulnerabilities"
      description="Track tenant-scoped findings, remediation status, and overdue risk."
      endpoint="/api/v1/vulnerabilities"
      icon={Bug}
    />
  )
}
