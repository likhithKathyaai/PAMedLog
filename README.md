# PA MedLog Talent LLC WordPress Theme

Production WordPress theme for PA MedLog Talent LLC.

Current baseline: **V10.6**

## Features
- Responsive enterprise UI/UX
- Employer and candidate journeys
- IT Projects, AI Solutions, Training, Resources and Partners
- Case Studies and Lead Center
- Protected candidate resume handling
- Enquiry email notifications
- KATHYA floating assistant UI
- Optional server-side generative AI integration
- Mobile navigation and optimized mobile footer
- WordPress security hardening

## Install
1. Download or clone this repository.
2. Place the theme folder inside `wp-content/themes/`.
3. Activate it from **WordPress Admin → Appearance → Themes**.
4. Save **Settings → Permalinks** once.
5. Clear WordPress/Hostinger caches.

## Secrets
Never commit API keys, SMTP passwords or `wp-config.php`.

For the KATHYA generative AI backend, define the API key on the server, for example in `wp-config.php`:

```php
define('PAMEDLOG_OPENAI_API_KEY', 'YOUR_KEY_HERE');
```

See `SECURITY-SETUP.md` for production deployment guidance.
