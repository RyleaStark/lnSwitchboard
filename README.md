# lnSwitchboard

lnSwitchboard turns your node into a sovereign Lightning Address switchboard (router). Point your reverse proxy at it, drop in an invoice macaroon, and it will answer LNURL-pay requests with wallet-friendly metadata, sane rate limiting, and a clean activity log so you always know who's zapping sats to your stack.

## Why node runners use lnSwitchboard
- Keep the sensitive admin surface local on port `22121` while exposing only the public `/.well-known/lnurlp/` path to the wider Lightning world.
- Map any username, tag, and vanity handle to the same Lightning backend without touching channel policy.
- Simple UI that displays the basics, and the latest pay/discovery/verify events so you can spot spammy zaps or griefing attempts at a glance.
- Works with every LNURL-savvy wallet and service provider (Alby, Bitcoin Well, Phoenix, Breez, Zeus, Cashu bridges, you name it) because it sticks to the core LUDs and keeps metadata honest.

## Quick example
1. Point your apex/root domain (say `example.com`) to the web server of choice (Nginx, Caddy, HAProxy, Cloudflare Tunnel, etc.) that will sit in front of lnSwitchboard.
2. In your reverse proxy (Nginx, Caddy, HAProxy, Cloudflare Tunnel, etc.) forward only `https://example.com/.well-known/lnurlp/*` to `http://{ln_switchboard_ip}:22121/.well-known/lnurlp/*`.
3. Share any Lightning Address that ends with `@example.com`. `alice@example.com`, `crew@example.com`, and tagged aliases like `merch+promo@example.com` or `vip+bones@example.com` all hit the same backend without extra config.

Once the reverse proxy is in front of the root domain, every string before the `@` (tags included) resolves through lnSwitchboard, so anyone can zap sats to whatever handle you hand out.

## Supported LUDs
lnSwitchboard currently implements the following LNURL specs. Each link points back to the canonical LUD on GitHub for easy reference:

- [LUD-06 · `payRequest` base spec](https://github.com/lnurl/luds/blob/luds/06.md)
- [LUD-09 · `successAction` field for `payRequest`](https://github.com/lnurl/luds/blob/luds/09.md)
- [LUD-12 · Comments in `payRequest`](https://github.com/lnurl/luds/blob/luds/12.md)
- [LUD-16 · Paying to static internet identifiers](https://github.com/lnurl/luds/blob/luds/16.md)
- [LUD-17 · Protocol schemes and raw URLs](https://github.com/lnurl/luds/blob/luds/17.md)
- [LUD-18 · Payer identity in `payRequest`](https://github.com/lnurl/luds/blob/luds/18.md)
- [LUD-20 · Long payment descriptions](https://github.com/lnurl/luds/blob/luds/20.md)
- [LUD-21 · `verify` base spec](https://github.com/lnurl/luds/blob/luds/21.md)


## Support & credits
- Sats keep the project zapping: `lnSwitchboard+tips@bigbones.net`
- Copyright © [Rylea Stark](https://github.com/RyleaStark). All rights reserved unless otherwise noted.
