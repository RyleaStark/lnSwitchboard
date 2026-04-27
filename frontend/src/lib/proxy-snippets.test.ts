import {
  buildProxyHelpItems,
  normalizeDeploymentEnv,
  proxyHostForDeployment,
  proxyUpstreamForDeployment,
} from "@/lib/proxy-snippets"

describe("proxy deployment snippets", () => {
  it("defaults to docker localhost when DEP_ENV is not supplied", () => {
    expect(normalizeDeploymentEnv(undefined)).toBe("DOCKER")
    expect(proxyHostForDeployment(undefined)).toBe("127.0.0.1")
    expect(proxyUpstreamForDeployment(undefined)).toBe("127.0.0.1:22121")
  })

  it("maps Umbrel deployment names to app container hosts", () => {
    expect(proxyHostForDeployment("UMBREL")).toBe("lnswitchboard_app_1")
    expect(proxyHostForDeployment("umbrel_dev")).toBe("extended-umbrella-lnswitchboard_app_1")
  })

  it("renders snippets using the selected deployment upstream", () => {
    const snippets = buildProxyHelpItems("UMBREL-DEV", "pay.example.com")
    expect(snippets.find((item) => item.label === "NGINX")?.snippet).toContain(
      "http://extended-umbrella-lnswitchboard_app_1:22121",
    )
    expect(snippets.find((item) => item.label === "Caddy")?.snippet).toContain(
      "pay.example.com",
    )
    expect(snippets.find((item) => item.label === "Cloudflare Tunnel")?.snippet).toContain(
      "service: http://extended-umbrella-lnswitchboard_app_1:22121",
    )
  })
})
