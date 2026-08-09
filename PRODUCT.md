# RiseVPN Control — Product Contract
<!-- impeccable:product-schema 1 -->

## Platform

Responsive Russian-language web platform: public marketing site, authenticated customer cabinet, and role-based administration console. The control plane is deployed on one Russian VPS behind Caddy and serves generated VPN subscriptions to v2RayTun-compatible clients.

## Stack

- Go 1.26 modular monolith for the HTTP API, background jobs, node control channel, Telegram authentication, notifications, and embedded frontend assets.
- PostgreSQL is the system of record; Redis is limited to sessions, rate limits, replay protection, and short-lived cache.
- React, TypeScript, and Vite for the public site, customer cabinet, and administration console.
- Docker Compose with Caddy, the control application, PostgreSQL, Redis, and an encrypted backup/restore-test job.
- RiseVPN Node and the shared versioned protocol remain in this monorepo.

## Users

- A prospective customer deciding whether to start a free three-day Trial.
- A customer monitoring subscription state, usage, balance, devices, and the automatically selected location.
- Support staff managing users, subscriptions, devices, and justified manual balance entries.
- Operators managing nodes, compliance, updates, alerts, and network health.
- Auditors reading immutable financial and security records.
- Owners managing all operations, administrators, and sensitive keys.

## Product Purpose

RiseVPN provides a simple VPN subscription with centralized account, device, quota, location, and compliance management. Locations serve Hysteria 2 over UDP and a CDN-compatible VLESS WebSocket TLS fallback. The first production contour targets 10,000 accounts, 2,000 concurrently connected devices, and 100 locations on a single VPS deployment.

The main customer promise is low-friction access: sign in through Telegram, start Trial, bind one device through the subscription request, and receive exactly one working connection selected by the platform.

## Positioning

RiseVPN should feel like dependable network infrastructure rather than a generic neon “cybersecurity” landing page. The live network, transparent tariff limits, privacy boundaries, and legible operational status are the product evidence.

The owner intends to market RiseVPN as a legal VPN. Public legal claims are a launch-gated assertion, not verified product evidence: commercial launch requires written legal advice, validation of the compliance process under applicable Russian law, and completion of personal-data operator obligations.

## Operating Context

- Public registration uses official Telegram OIDC Authorization Code with PKCE and requests only `openid`, `profile`, and optional `telegram:bot_access`; phone numbers are not collected.
- The Telegram bot sends notifications only and does not manage accounts.
- All plans use automatic location selection. Customers do not receive a manual location override in v1.
- A subscription response contains exactly one connection selected by the platform. Auto-selection admits only healthy, compatible, non-draining nodes with fresh compliance state and uses browser RTT first, load/capacity second, and controller RTT/GeoIP as fallback. A location changes only for at least 15% expected improvement.
- Nodes may operate without the controller for up to 24 hours using signed, bounded quota leases.
- The production compliance source is the third-party Antifilter domain list, polled every 15 minutes with strict validation and a signed last-known-good snapshot. It must never be presented as an official state registry.

## Capabilities and Constraints

- Plans: Trial (3 days, 30 Mbit/s, 1 device, 20 GB, no P2P); Lite (149 ₽/30 days, 50 Mbit/s, 1 device, 150 GB, then 5 Mbit/s); Plus (299 ₽/30 days, 200 Mbit/s, 3 devices, 600 GB, then 10 Mbit/s); Ultra (499 ₽/30 days, 7 devices, 2 TB, then 20 Mbit/s).
- Trial begins on the first successful subscription fetch that binds `X-HWID`; reuse is blocked by Telegram identity and an HMAC-derived hardware identifier.
- Each device slot has a separate credential and opaque subscription token. Self-service rebinding is permitted once per 24 hours and rotates the credential while immediately revoking the old session.
- Paid subscriptions use fixed 30-day periods. Upgrades apply immediately with proportional price and quota; downgrades apply on renewal.
- Insufficient paid balance enters a 24-hour Grace state at 1 Mbit/s without P2P and then blocks access. Trial has no Grace.
- Wallets use an append-only integer-kopeck ledger; negative balance is forbidden. v1 has no payment provider, and the top-up action opens a designed “Payment coming soon” 404 page.
- The v2RayTun subscription includes exactly one `hysteria2://` URI and the required profile, usage, expiry, and refresh headers. Compatibility with a current real client is a release gate.
- No first-party desktop/mobile client, payment integration, HA, or Kubernetes is included in v1.
- Full technical indistinguishability of VPN traffic is not promised.
- Retention is explicit: sign-ins, sessions, and IP addresses for 90 days; aggregated traffic for 13 months; financial ledger and security audit for 5 years. Website history, destination IP addresses, and traffic contents are never stored.

## Brand Commitments

- The only fixed brand asset is the name RiseVPN; the visual system is created from first principles.
- The public site uses Persuade mode; the cabinet and admin console use Operate mode.
- Language is direct, calm, and specific. It does not invent testimonials, customer counts, uptime, geography, legal guarantees, or performance claims.
- The live network and real operational data are the primary proof mechanism.
- The interface is Russian-first, responsive, keyboard accessible, compatible with reduced motion, free of horizontal overflow, and targets WCAG 2.2 AA.

## Evidence on Hand

- A working RiseVPN Node v0.2 implementation with enrollment bundle, versioned ACK control channel, outbound mTLS connection, local authentication, usage collection, compliance handling, installer, signed release workflow, and a minimal Hysteria patch series.
- Public official documentation for Telegram Login, Hysteria 2 URI/configuration, and v2RayTun subscription headers/device limits.
- No verified testimonials, commercial adoption numbers, published uptime history, or completed legal opinion are available.

## Product Principles

1. One clear connection: every plan receives one automatically selected location, with safe provisioning before migration.
2. Explain real state: quota, renewal, Grace, Trial expiry, device binding, and network health are visible and unambiguous.
3. Minimize retained data: never store website history, destination addresses, or traffic contents.
4. Money and authority are auditable: financial entries are append-only and privileged actions always record actor, reason, and outcome.
5. Degrade safely: retain last-known-good compliance, bound offline quota, retry commands idempotently, and roll back failed node updates.
6. No fabricated confidence: distinguish implemented controls, third-party sources, operational targets, and unresolved launch gates.

## Accessibility & Inclusion

- WCAG 2.2 AA contrast and interaction targets.
- Complete keyboard navigation with visible focus and no keyboard traps.
- Status never depends on color alone; charts and maps have textual equivalents.
- Reduced-motion behavior is supported for network visualization and transitions.
- Dates, durations, bytes, speeds, and ruble amounts are localized consistently for Russian users.
- Urgent Trial and Grace warnings remain prominent without using hostile or panic-inducing language.
