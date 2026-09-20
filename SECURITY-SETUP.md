# PA MedLog Talent LLC — V9 Security Setup

The theme includes application-layer hardening, but a WordPress theme alone cannot provide "high security". Complete these production steps in Hostinger before launch.

## Required hosting/account controls
1. Force HTTPS and keep the SSL certificate active.
2. Enable Hostinger malware scanning/WAF features available on the plan.
3. Enable 2FA for Hostinger and every WordPress administrator.
4. Use unique administrator usernames and long generated passwords. Never share admin accounts.
5. Keep WordPress core, PHP, plugins and this theme updated. Remove unused themes/plugins.
6. Configure automatic daily backups and verify that a restore works.
7. Use a reputable SMTP provider/plugin for reliable form notifications; enable SPF, DKIM and DMARC for pamedlogtalent.com.
8. Add login rate limiting / bot protection using a reputable security plugin or Hostinger security feature.
9. Add Cloudflare or another managed WAF/CDN if appropriate for your deployment.
10. Restrict database and SFTP credentials to the minimum people required; rotate credentials after contractors leave.

## Theme protections included
- Nonces on public forms and sensitive admin actions.
- Honeypot and submission-time checks.
- Per-IP form rate limiting.
- Input sanitization and length limits.
- Resume MIME validation and 5 MB size limit.
- Randomized protected resume filenames and deny rules.
- Admin-only resume downloads and lead CSV exports.
- XML-RPC disabled.
- Public REST user enumeration reduced.
- Generic login errors.
- WordPress theme/plugin file editor disabled.
- Security headers: nosniff, SAMEORIGIN, referrer policy, permissions policy and HSTS on HTTPS.

## Important
Do not add a strict Content-Security-Policy without testing all WordPress plugins, analytics, forms and payment integrations. A broken CSP can disable legitimate site functions. Configure CSP at the server/WAF layer after inventorying required domains.

Candidate documents contain personal information. Define a retention period, access policy and deletion process. The website's legal/privacy text should be reviewed by qualified counsel for the jurisdictions where the business operates.
