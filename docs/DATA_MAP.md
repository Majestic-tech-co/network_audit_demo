# Data map (Phase 1)

Storage: PostgreSQL (`db` container, volume `postgres_data`), Redis (queue/cache, capture state), Docker volumes `scan_results` (nmap XML + `.pcap` captures) and `scan_quarantine`. No Supabase or other hosted database is used.

| Data | PII? | Where | Notes |
|------|------|-------|-------|
| email, username, role, last_login | Yes | `users` | email unique; LDAP users also get display name/email from AD |
| password hash (bcrypt) | Credential | `users.hashed_password` | null for LDAP users |
| `assigned_device_ip` | Yes (links person→device) | `users` | |
| agent token (sha256 hash), label ("<name>'s device") | Yes (label) | `agent_tokens` | raw token shown once |
| IP, MAC, hostname, OS, registered_user_id | Yes (identifies a person's device) | `devices`, `ports` | |
| malware file paths/names/hashes, process lists, installed software | Yes (user activity) | `findings.file_path`, `raw_data` | collected by agent on employee machines |
| AI provider key, LDAP bind password, UniFi key | Secret | `organizations` (AES-GCM encrypted) | |
| Packet captures | Yes (may contain credentials/content) | `/app/scan_results/captures/*.pcap` | deleted after `RETENTION_CAPTURE_DAYS` (default 7) |
| Org logo | No | `organizations.logo_data` | |

## Third-party flows
- **AI providers (OpenAI / Anthropic / Gemini, or local Ollama)** – receive finding + device details (hostname, IP, file paths). Choose Ollama to keep data in-house.
- **SMTP / Slack / Teams** – finding notifications (hostnames/IPs) if configured.
- **VirusTotal** – hash lookups only if enabled.
- **UniFi controller / LDAP-AD** – inbound data from the customer's own infrastructure.

## GDPR / CCPA flags (to resolve with the operating organization)
1. **Employee monitoring** – the agent reports processes, installed software and file paths; needs a lawful basis, employee notice, and in some jurisdictions works-council consultation. A draft notice is at `/privacy`.
2. **Third-party transfer to AI providers** – needs a DPA and an international-transfer basis if non-EU.
3. ~~No retention policy~~ — **done**: a daily task deletes finished scans + findings + raw nmap output after `RETENTION_SCAN_DAYS` (180), stale devices with no findings after `RETENTION_DEVICE_DAYS` (365) and `.pcap` files after `RETENTION_CAPTURE_DAYS` (7); `0` disables a rule. **Operator must state these periods in the privacy notice.** Not covered: the Docker `scan_quarantine` volume and Postgres backups (set your own backup expiry).
4. ~~No erasure/export~~ — **done**: `GET /api/users/{id}/export` (access request) and `DELETE /api/users/{id}` (erasure; admin only). Erasure anonymizes the account (so scan history/audit references stay valid), revokes sessions, deletes agent tokens, and by default deletes the user's registered devices and their findings (`?erase_devices=false` keeps the devices, unlinked). Backups and AI-provider/notification copies are outside the application's reach.
5. **Packet captures** may contain third-party personal data and credentials; restricted to writer/admin and auto-deleted (see 3).
6. Privacy notice is a **draft**; the controller identity, contact and retention periods must be filled in.
