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

export function proxyUpstreamForDeployment(value?: string | null, port = "22121"): string {
  return `${proxyHostForDeployment(value)}:${port}`
}

export function buildProxyHelpItems(value?: string | null, publicHost = "your-domain.example"): ProxyHelpItem[] {
  const upstream = proxyUpstreamForDeployment(value)
  return [
    {
      icon: "nginx",
      label: "NGINX",
      title: "NGINX Reverse Proxy",
      description: "Expose only the public LNURL and Nostr well-known routes through NGINX.",
      snippet: `location /.well-known/lnurlp/ {
  proxy_pass http://${upstream};
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}

location = /.well-known/nostr.json {
  proxy_pass http://${upstream};
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
}`,
    },
    {
      icon: "caddy",
      label: "Caddy",
      title: "Caddy Reverse Proxy",
      description: "Expose the public LNURL and Nostr routes with Caddy matchers.",
      snippet: `${publicHost} {
  reverse_proxy /.well-known/lnurlp/* ${upstream}
  reverse_proxy /.well-known/nostr.json ${upstream}
}`,
    },
    {
      icon: "cloudflare",
      label: "Cloudflare Tunnel",
      title: "Cloudflare Tunnel Reverse Proxy",
      description: "Route only the public well-known paths through a Cloudflare Tunnel ingress rule.",
      snippet: `tunnel: <tunnel-id>
credentials-file: /etc/cloudflared/<tunnel-id>.json

ingress:
  - hostname: ${publicHost}
    path: /.well-known/lnurlp/*
    service: http://${upstream}
  - hostname: ${publicHost}
    path: /.well-known/nostr.json
    service: http://${upstream}
  - service: http_status:404`,
    },
  ]
}
