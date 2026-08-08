"""Embedded lnSwitchboard proxy Worker source, version marker, and mesh constants.

The proxy Worker is deployed into the operator's Cloudflare account by
lnSwitchboard and is the only public ingress path. Privacy is a hard owner
requirement: the Worker performs no logging, no telemetry, no analytics, and
its only network egress is ``env.MESH.fetch()`` to the internal lnSwitchboard
listener over the Cloudflare Mesh VPC binding.
"""

from __future__ import annotations

import re

# Bump on every change to WORKER_SOURCE; the service upgrades drifted scripts.
LNS_WORKER_VERSION = "2026.08.08.4"

WORKER_SCRIPT_NAME = "lnswitchboard-proxy"
INTERNAL_HOSTNAME = "lns.internal"
PUBLIC_PORT = 21212

# Cloudflare Mesh VPC network binding attached to the proxy Worker.
MESH_BINDING_NAME = "MESH"
MESH_NETWORK_ID = "cf1:network"
WORKER_COMPATIBILITY_DATE = "2026-08-08"

# Ownership marker applied to every Cloudflare resource lnSwitchboard creates.
MANAGED_COMMENT = "Managed by lnSwitchboard"

_SOURCE_TEMPLATE = '''// lnSwitchboard proxy Worker. Deployed and managed by lnSwitchboard; do not edit.
//
// Privacy (hard requirement): this Worker never logs, never emits telemetry or
// analytics, binds no analytics datasets, and its only network egress is
// env.MESH.fetch() to the internal lnSwitchboard listener. Request and
// response payloads are forwarded verbatim and are never inspected, logged,
// or transformed.
const LNS_WORKER_VERSION = "__LNS_WORKER_VERSION__";
const INTERNAL_ORIGIN = "http://__INTERNAL_HOSTNAME__:__PUBLIC_PORT__";

// RFC 9110 section 7.6.1 hop-by-hop headers must not be forwarded.
const HOP_BY_HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

function stripHopByHop(headers) {
  const connection = headers.get("connection");
  if (connection !== null) {
    for (const value of connection.split(",")) {
      const name = value.trim().toLowerCase();
      if (/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) {
        headers.delete(name);
      }
    }
  }
  for (const name of HOP_BY_HOP_HEADERS) {
    headers.delete(name);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const publicHostname = url.hostname.toLowerCase();
    const isWorkersDev =
      publicHostname === "workers.dev" || publicHostname.endsWith(".workers.dev");
    if (isWorkersDev || !(
      url.pathname.startsWith("/.well-known/lnurlp/") ||
      url.pathname === "/.well-known/nostr.json"
    )) {
      return new Response("Not found", {
        status: 404,
        headers: { "cache-control": "no-store" },
      });
    }
    const forwarded = new Request(INTERNAL_ORIGIN + url.pathname + url.search, request);
    stripHopByHop(forwarded.headers);
    // Pass the public hostname explicitly; the mesh-side Host header is the
    // internal hostname, so the app cannot otherwise recover it.
    const publicHost = request.headers.get("Host");
    if (publicHost !== null) {
      forwarded.headers.set("X-LNS-Public-Host", publicHost);
    }
    forwarded.headers.delete("X-LNS-Mesh-Key");
    forwarded.headers.set("X-LNS-Mesh-Key", env.LNS_MESH_INGRESS_KEY);
    try {
      const upstream = await env.MESH.fetch(forwarded);
      const responseHeaders = new Headers(upstream.headers);
      stripHopByHop(responseHeaders);
      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: responseHeaders,
      });
    } catch {
      // Fixed sanitized failure: never surface exception text or internals.
      return new Response("lnSwitchboard origin unavailable", {
        status: 503,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
        },
      });
    }
  },
};
'''

WORKER_SOURCE = (
    _SOURCE_TEMPLATE.replace("__LNS_WORKER_VERSION__", LNS_WORKER_VERSION)
    .replace("__INTERNAL_HOSTNAME__", INTERNAL_HOSTNAME)
    .replace("__PUBLIC_PORT__", str(PUBLIC_PORT))
)

_VERSION_PATTERN = re.compile(r'const LNS_WORKER_VERSION = "([^"]+)"')


def extract_worker_version(source: str) -> str | None:
    """Return the version marker embedded in a deployed script, if present."""
    match = _VERSION_PATTERN.search(source)
    return match.group(1) if match is not None else None
