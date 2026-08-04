import type { DeploymentEnv } from "@/lib/api"

export type ProxyEngine = "nginx" | "caddy" | "cloudflare"

export type ProxyHelpItem = {
  icon: ProxyEngine
  label: string
  title: string
  description: string
  snippet: string
}

export function normalizeDeploymentEnv(value?: string | null): DeploymentEnv {
  const normalized = value?.trim().toUpperCase().replace("_", "-")
  if (normalized === "UMBREL" || normalized === "UMBREL-DEV") return normalized
  return "DOCKER"
}

export function proxyHostForDeployment(value?: string | null): string {
  const depEnv = normalizeDeploymentEnv(value)
  if (depEnv === "UMBREL") return "lnswitchboard_app_1"
  if (depEnv === "UMBREL-DEV") return "extended-umbrella-lnswitchboard_app_1"
  return "127.0.0.1"
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
      icon: "cloudflare",
      label: "Cloudflare Tunnel",
      title: "Cloudflare Tunnel Reverse Proxy",
      description: "Route the public hostname to lnSwitchboard's isolated public listener.",
      snippet: `tunnel: <tunnel-id>
credentials-file: /etc/cloudflared/<tunnel-id>.json

ingress:
  - hostname: ${publicHost}
    service: http://${upstream}
  - service: http_status:404`,
    },
  ]
}
