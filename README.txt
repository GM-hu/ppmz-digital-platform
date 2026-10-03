PPMZ DIGITAL PLATFORM — SECURE FOUNDATION v6

Production-oriented deployment package for the PPMZ organizational platform.

FEATURES
- Secure server-side authentication and role authorization.
- Central Secretariat master control.
- Team President scoped biodata submission.
- Central approval/rejection workflow.
- Public verification by full name or PPMZ ID with limited public fields.
- Audit logging.
- Green/gold PPMZ mobile interface and official logo.
- Health endpoint at /health.
- Production security headers.
- Secure session cookie when NODE_ENV=production.
- Render deployment manifest and Dockerfile included.

LOCAL START
npm install
node server.js
Open http://localhost:8080

CLOUD
See DEPLOYMENT_CHECKLIST.txt and render.yaml.
Set NODE_ENV=production, PPMZ_ADMIN_USERNAME, and PPMZ_ADMIN_PASSWORD.
Use persistent storage for /data. Do not expose /data publicly.

IMPORTANT
This package is deployment-ready but is not itself hosted by this ZIP. A hosting account/domain is required for a public Internet URL. For higher scale, replace JSON persistence with PostgreSQL and use managed object storage for photographs/documents.
