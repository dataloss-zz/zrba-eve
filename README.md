# Zeta Reticuli Blackpill Alliance

EVE Online corporation site with ESI (EVE Swagger Interface) login.

## Files
- index.html – the site
- server.py – local server for SSO token exchange (avoids CORS)

## Local run
1. python3 server.py
2. Open http://localhost:8080/
3. Set ESI Callback URL to http://localhost:8080/callback

## Cloudflare Pages
Connect this repo to Cloudflare Pages. The login token exchange needs a Worker (not included yet).
