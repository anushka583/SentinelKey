import { BellRing } from 'lucide-react'
import { RoutePlaceholder } from '../components/RoutePlaceholder'

export function AlertsPage() {
  return (
    <RoutePlaceholder
      title="Alerts"
      description="Triage rule-generated alerts and track their resolution status."
      endpoint="/api/v1/alerts"
      icon={BellRing}
    />
  )
}
