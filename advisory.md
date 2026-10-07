# Bilibili Desktop: Insecure Sender URL Validation in Privileged In-App Browser Bridge

**Short title:** Bilibili Desktop IPC sender URL allowlist bypass (CWE-346)

**Status:** Awaiting vendor confirmation / coordination

---

## Summary

Bilibili Desktop (a.k.a. Bilibili PC Client) for Windows injects a privileged Electron preload bridge into an in-app browser window and validates IPC sender URLs with a loose regular-expression substring match instead of structured hostname parsing. An attacker-controlled page that is loaded inside that in-app browser can present a sender URL string containing an allowlisted hostname substring while the browser resolves the request to an attacker-controlled host, bypassing the allowlist and invoking privileged IPC channels.

In testing on Bilibili Desktop 1.17.9 for Windows, this allowed an untrusted renderer page to invoke a privileged native path-opening IPC channel, resulting in local program execution under the logged-in user.

## Affected Product

| Field | Value |
| --- | --- |
| Vendor | Shanghai Hode Information Technology Co., Ltd. (Bilibili) |
| Product | Bilibili Desktop / Bilibili PC Client |
| Affected version (tested) | 1.17.9 |
| Likely affected range | All versions using the affected in-app browser bridge and sender URL allowlist (1.x line prior to a vendor fix); vendor should confirm range. |
| Platform confirmed | Windows 11 (10.0.26200) |
| Platform unconfirmed | macOS — same Electron IPC and native shell path-opening logic may apply, but this advisory is based on Windows-only verification. |
| Electron runtime observed | Electron 22.3.27, Chromium 108.0.5359.215, Node.js 16.17.1 |

## Vulnerability Classification

- Primary: CWE-346 — Origin Validation Error
- Contributing: CWE-184 — Incomplete List of Disallowed Inputs (allowlist accepts substring lookalikes)
- Attack class: privileged IPC abuse / local program execution

## Description

The affected client creates a privileged in-app browser window (`Universal BrowserWindow`) that injects the same Electron preload script into every page it loads, regardless of origin. The preload script exposes a native bridge to renderer JavaScript through `contextBridge.exposeInMainWorld`, including a generic IPC dispatcher that any loaded page can call.

The main process validates the sender URL of every IPC call before dispatching sensitive channels. The validation extracts an allowlisted-looking domain from the raw sender URL string via a regular-expression substring match (e.g. `([a-z0-9-]+\.bilibili\.com)`), instead of parsing the URL and checking the actual `hostname` field.

Because the check operates on the URL string and not on the URL parsed by the renderer, a URL whose hostname does not match the allowlist can still produce an allowlisted-looking substring in the raw URL string. The renderer still resolves the URL using standard URL parsing (RFC 3986), so the browser navigates to the attacker-controlled host while the main-process allowlist accepts the IPC call.

The in-app browser also unconditionally allows navigation away from the allowlisted origin without removing the preload bridge, so a third-party page reached by clicking within the in-app browser inherits the privileged context.

## Impact

- An untrusted page rendered inside the Bilibili Desktop in-app browser can invoke privileged IPC channels.
- In the verified case, a privileged native path-opening IPC channel was invoked successfully from an attacker-controlled page, launching a local Windows program under the logged-in user.
- Successful exploitation gives the attacker code execution in the user context, which can be leveraged for persistence, data theft, lateral movement, or further payload delivery.
- No authentication or special local privileges are required.
- User interaction is required (the user must navigate within the in-app browser to a page controlled by the attacker, e.g. via a crafted link or a navigation chain through a legitimate Bilibili page that links to third-party sites).

## CVSS

Primary scoring recommendation:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8 (High)
```

Rationale:
- `AV:N` — the attacker can host the malicious page on the public internet and induce the client to load it inside the in-app browser.
- `AC:L` — exploitation requires only a crafted URL pattern, no special conditions.
- `PR:N` — no authentication or local privileges required.
- `UI:R` — the user must click or navigate within the in-app browser.
- `S:U` — the renderer and main process belong to the same application security authority; the execution context is the local user, not a separate security authority in the strict CVSS sense.
- `C:H/I:H/A:H` — full impact on confidentiality, integrity, and availability of the user account.

If the assigning CNA treats renderer-to-main IPC invocation as crossing a security authority boundary, `S:C` may be considered and the score becomes `9.6 (Critical)`. The reporter recommends `8.8 (High)` as the defensible primary score.

## Remediation Recommendations

1. Stop injecting the privileged preload bridge into pages whose origin is not on a verified allowlist. Either omit `webPreferences.preload` for untrusted origins, or open untrusted pages in a non-privileged `BrowserWindow` without the native bridge.
2. Replace regular-expression sender URL validation with structured URL parsing using the actual `hostname` field, e.g. `new URL(senderUrl).hostname` and only accept exact hostnames or true subdomain suffixes.
3. Treat userinfo-bearing URLs (e.g. `http://allowlisted.example@attacker.example/`) as untrusted: the userinfo portion must not be considered part of the hostname.
4. Remove unconditional trust for `file://` senders unless the loaded local file is explicitly produced by the application itself.
5. Re-navigate the in-app browser to the system browser (or a non-privileged window) whenever the user navigates outside the verified allowlist, so the privileged bridge is dropped on cross-origin navigation.
6. Do not expose privileged native channels such as local path-opening, file-system, or script-execution methods through a generic IPC dispatcher to renderer JavaScript. Move sensitive operations behind main-process-only logic.

## Disclosure Timeline

| Date (UTC) | Event |
| --- | --- |
| 2026-06-29 | Initial audit of the affected desktop client began. |
| 2026-06-30 | Vulnerability chain reproduced locally on Bilibili Desktop 1.17.9 for Windows. |
| 2026-06-30 | Sender URL bypass vectors confirmed. |
| 2026-06-30 | Remote trigger through the in-app browser confirmed. |
| 2026-07-02 | Internal report and PoC materials prepared. |
| 2026-07-02 | First vendor notification sent to `security@bilibili.com`, including technical details, PoC materials, and video evidence. |
| 2026-07-21 | Follow-up vendor notification sent to `security@bilibili.com` with a Baidu Netdisk package link containing the same evidence. |
| 2026-08-03 | As of the report date, no acknowledgement, ticket reference, or technical response has been received from Bilibili. |
| 2026-08-05 (planned) | Submission to MITRE CNA of Last Resort (CNA-LR) is planned after 14 days have elapsed since the second vendor notification without acknowledgement. |

The reporter attempted vendor coordination twice. As of 2026-08-03, Bilibili had not acknowledged receipt, assigned a ticket, or provided any technical response.

## Credits

Discovered and reported by: Siyang Wu (LeoWSY-hashblue)

## References

- Vendor: <https://www.bilibili.com/>
- Bilibili Security Response Center: <https://security.bilibili.com/>
- Electron Security Best Practices: <https://www.electronjs.org/docs/latest/tutorial/security>
- CWE-346 — Origin Validation Error: <https://cwe.mitre.org/data/definitions/346.html>
- CWE-184 — Incomplete List of Disallowed Inputs: <https://cwe.mitre.org/data/definitions/184.html>
- RFC 3986 §3.2.1 — URI Userinfo: <https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1>

---

## Distribution Note

This document is intended for public reference (NVD entry, vendor advisory, security researcher awareness) **after** Bilibili has had a reasonable opportunity to respond and remediate. It deliberately omits:

- the exact PoC URL pattern that bypasses the allowlist;
- any working weaponized HTML or server harness;
- attacker infrastructure details (VPS IP, ports, tunnel configuration).

Private reproduction materials, including the full technical report and PoC video, are held privately by the reporter and will only be shared with the vendor or a CNA on request.