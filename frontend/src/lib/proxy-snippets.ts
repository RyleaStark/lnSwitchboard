import type { DeploymentEnv } from "@/lib/api"

export type ProxyEngine = "nginx" | "caddy" | "custom"

export type ProxyHelpItem = {
  icon: ProxyEngine
  label: string
  title: string
  description: string
  snippet: string
}

export function normalizeDeploymentEnv(value?: string | null): DeploymentEnv {
  const normalized = value?.trim().toUpperCase()
  if (normalized === "UMBREL" || normalized === "UMBREL_DEV") return normalized
  return "DOCKER"
}

export function proxyHostForDeployment(value?: string | null): string {
  const depEnv = normalizeDeploymentEnv(value)
  if (depEnv === "UMBREL") return "lnswitchboard-public"
  if (depEnv === "UMBREL_DEV") return "lnswitchboard-public"
  return "lnswitchboard-public"
}

export function proxyUpstreamForDeployment(value?: string | null, port = "21212"): string {
  return `${proxyHostForDeployment(value)}:${port}`
}

export function buildProxyHelpItems(value?: string | null, publicHost = "your-domain.example"): ProxyHelpItem[] {
  const upstream = proxyUpstreamForDeployment(value)
  return [
    {
      icon: "nginx",
      label: "NGINX",
      title: "NGINX Reverse Proxy",
      description: "Forward the public hostname to lnSwitchboard's isolated public listener.",
      snippet: `location / {
  proxy_pass http://${upstream};
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}`,
    },
    {
      icon: "caddy",
      label: "Caddy",
      title: "Caddy Reverse Proxy",
      description: "Forward the public hostname to lnSwitchboard's isolated public listener.",
      snippet: `${publicHost} {
  reverse_proxy ${upstream}
}`,
    },
    {
      icon: "custom",
      label: "Custom",
      title: "Custom Reverse Proxy",
      description: "Use these requirements with any reverse proxy that can reach lnSwitchboard's public listener.",
      snippet: `Public hostname: ${publicHost}
Upstream: http://${upstream}
Preserve the original Host header.
Forward the original client IP only from a configured trusted proxy.
Never route public traffic to port 22121.`,
    },
  ]
}
