PA MedLog Talent LLC — V10.3 Live Generative AI

KATHYA Assistant now uses a server-side OpenAI Responses API integration.

REQUIRED CONFIGURATION
Add this to wp-config.php ABOVE the line that says "That’s all, stop editing":

define('PAMEDLOG_OPENAI_API_KEY', 'YOUR_OPENAI_API_KEY');

Optional model override:
define('PAMEDLOG_OPENAI_MODEL', 'gpt-5.6-luna');

IMPORTANT
- Never put the API key in JavaScript, theme CSS, page HTML, or WordPress Customizer.
- Restrict access to wp-config.php at the hosting/file-system level.
- The default model is gpt-5.6-luna for a cost-sensitive website assistant.
- API usage is billed separately by OpenAI.
- The endpoint includes nonce validation, per-IP rate limiting, message limits, server-side prompt controls, store=false, and safe error handling.
- Test on staging before production.
