# KAVACH demo (frontend only)
Open `index.html` by double-clicking it. No install, no server, no internet needed.
Everything is simulated in the browser: the agent, the rules, the risk scores and the SHA-256 audit chain.

## 4-minute video flow
1. Routine refund: everything is allowed (shows it does not get in the way).
2. Prompt injection: hidden instruction is removed, then the leak is blocked by the canary rule.
3. Runaway cleanup: held, press Approve or Deny (human in the loop).
4. Private data in a reply: Aadhaar and phone are removed in front of the judges.
5. Add your own rule in plain English, e.g. "Hold payments above 20000", then run the large payment.
6. Press Kill switch mid-run, then Resume.
7. Audit log: Verify (clean), Edit an old entry, Verify again (tampering caught).
8. Run red-team suite and read out the result.
