# KAVACH

**A control layer for AI agents: firewall, flight recorder and kill switch in one.**

Built for DevHack 2026 (Sahyadri DEVHOST) · Problem Statement 2.1: AI Agent Safety and Control · Team JSN CREATIVE

## The problem
AI agents no longer just chat. They send emails, move money, edit databases and read customer data, often with no human watching. Today's guardrails check what an agent *says*. Almost nothing checks what it *does*. One hidden instruction in an email, one wrong plan, or one over-broad permission can leak data, delete records or send payments before anyone notices. Afterwards, there is usually no trustworthy record of what happened.

## Our solution
KAVACH sits between an AI agent and the business systems it uses. Every action the agent tries is intercepted, scored for risk, and given one of four outcomes:

| Outcome | What happens |
|---|---|
| Allow | Safe, routine work runs untouched |
| Modify | The action runs, but private data or hidden instructions are removed first |
| Hold | A human must approve before it runs (for example, over WhatsApp) |
| Block | The action never runs |

Every decision is written to a tamper-evident audit log, and one button halts the agent instantly.

## What makes it different
- **Controls actions, not words.** It works at the tool-call level, so it can stop a leak even when the agent's text looks harmless.
- **Context-aware risk score.** Each action is scored on how hard it is to undo, how much it can affect, and how sensitive the data is.
- **Rules in plain English.** A non-technical owner can type "Hold payments above 20000" and it takes effect.
- **Prompt-injection defence.** Hidden instructions in inbound text are stripped, and canary tokens expose attempts to leak data.
- **Human in the loop.** Risky actions wait for an owner to approve or deny.
- **Tamper-evident audit log.** Each entry is sealed with SHA-256 to the one before it. Editing an old entry breaks every seal after it, and verification shows exactly where.
- **Kill switch.** One click halts the agent, and any pending approval is denied.

## What is in this demo
A frontend-only simulation that shows the full KAVACH experience in the browser:
- A simulated support agent ("Aria") with five scenarios: routine refund, prompt injection, runaway database cleanup, private data in a reply, and a large payment to a new vendor.
- A live feed showing each action, its risk score, the decision and the reason.
- Editable rules, an adjustable risk limit and a plain-English rule box.
- Approve and Deny buttons for held actions.
- A kill switch with Resume.
- A SHA-256 audit chain with Verify and a button that edits an old entry so you can watch tampering get caught.
- A red-team suite that runs the attack scenarios and reports how many harmful actions were stopped, held or cleaned.

**Honest note:** the agent, rules and risk scores are simulated in the browser. The audit hashing is real SHA-256. The demo shows how the control layer behaves, not a live connection to a real agent.

## Run it
Open `index.html` by double-clicking it. No install, no server, no internet needed.

## Tech
HTML, CSS and vanilla JavaScript. Web Crypto API for SHA-256. No external libraries.

## Planned full build
- Node.js + TypeScript gateway that proxies real agent tool calls (MCP and REST)
- JSON policy-as-code, with plain-English rules compiled by an LLM and checked by a deterministic validator
- LLM-based intent judge alongside the rule engine
- PostgreSQL (Supabase) for the audit chain, Redis for rate limits and circuit breaker
- Next.js dashboard with a live feed over Socket.IO
- WhatsApp and Slack approvals

## Business potential
Open-core model: a free self-hosted gateway, paid cloud plans priced per agent per month, an enterprise tier with SSO and compliance reports, and a marketplace of industry policy packs. Demand is driven by data-protection and AI-governance expectations such as India's DPDP Act, the EU AI Act and ISO 42001.

## Demo video flow (4 minutes)
1. Routine refund: everything is allowed, so KAVACH does not get in the way.
2. Prompt injection: the hidden instruction is removed, then the leak is blocked by the canary rule.
3. Runaway cleanup: held, then press Approve or Deny.
4. Private data in a reply: Aadhaar and phone numbers are removed.
5. Type your own rule, such as "Hold payments above 20000", then run the large payment.
6. Press Kill switch mid-run, then Resume.
7. Audit log: Verify (clean), Edit an old entry, Verify again (tampering caught).
8. Run the red-team suite and read out the result.

## Team
FORGE CREATIVE · Yenepoya University
