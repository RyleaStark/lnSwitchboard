import {
  buildProxyHelpItems,
  normalizeDeploymentEnv,
  proxyHostForDeployment,
  proxyUpstreamForDeployment,
} from "@/lib/proxy-snippets"

describe("proxy deployment snippets", () => {
  it("defaults to docker localhost when DEP_ENV is not supplied", () => {
    expect(normalizeDeploymentEnv(undefined)).toBe("DOCKER")
    expect(proxyHostForDeployment(undefined)).toBe("lnswitchboard-public")
    expect(proxyUpstreamForDeployment(undefined)).toBe("lnswitchboard-public:21212")
  })

  it("maps Umbrel deployment names to app container hosts", () => {
    expect(proxyHostForDeployment("UMBREL")).toBe("lnswitchboard_public")
    expect(proxyHostForDeployment("umbrel_dev")).toBe("extended-umbrella-lnswitchboard_public")
  })

  it("renders snippets using the selected deployment upstream", () => {
    const snippets = buildProxyHelpItems("UMBREL_DEV", "pay.example.com")
    expect(snippets.find((item) => item.label === "NGINX")?.snippet).toContain(
      "http://extended-umbrella-lnswitchboard_public:21212",
    )
    expect(snippets.find((item) => item.label === "Caddy")?.snippet).toContain(
      "pay.example.com",
    )
    expect(snippets.find((item) => item.label === "Custom")?.snippet).toContain(
      "Upstream: http://extended-umbrella-lnswitchboard_public:21212",
    )
    expect(snippets.find((item) => item.label === "Cloudflare Tunnel")).toBeUndefined()
    const combined = snippets.map((item) => item.snippet).join("\n")
    expect(combined).not.toContain(":22121")
    expect(combined).not.toContain("lnprofile")
  })
})
