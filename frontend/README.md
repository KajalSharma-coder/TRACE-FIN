# TRACE//FIN frontend foundation

This directory contains the Phase 2 React/TypeScript/Vite/Tailwind shell plus the Phase 3 login integration. It is intentionally separate from the existing Streamlit application.

## Local development

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.api.main:app --reload --port 8000
cd frontend
Copy-Item .env.example .env.local
npm install
npm run dev
```

Open `http://localhost:5173`. The shell checks the existing `GET /api/health` endpoint through the Vite `/api` proxy. Set `VITE_TRACEFIN_API_URL` in `.env.local` when the frontend must call a non-local backend origin.

## Checks

```powershell
npm run check
npm run build
```

The login form uses the backend authentication contract and sends credentials only to the configured API over `fetch` with credentials included. The backend issues an HttpOnly session cookie and uses a separate CSRF token. For local HTTP development, set `TRACEFIN_AUTH_COOKIE_SECURE=false` before starting Uvicorn; keep it enabled behind HTTPS. Existing Streamlit authentication remains unchanged.

## Backend routes available to this shell

- `GET /api/health` — connectivity check.
- `GET /api/auth/csrf` and `POST /api/auth/login` — secure browser sign-in.
- `GET /api/auth/session` and `POST /api/auth/logout` — session verification and logout.
- `POST /api/analyze` — existing safe analysis foundation; not called by this shell yet.

No production API URL, secret, token, or mock analysis result is bundled in the frontend.

Public registration is controlled by `TRACEFIN_PUBLIC_SIGNUP_ENABLED`. The example
configuration enables it for local/demo use; production deployments should set it
to `false` unless open registration is an intentional, monitored policy. The
browser registration endpoint is `POST /api/auth/register` and uses the same CSRF
and HttpOnly session protections as sign-in.
