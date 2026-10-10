# Harbor Admin Dashboard

A modern admin dashboard in a single Python file. `main.py` contains the FastAPI backend, SQLite database, authentication, and the full HTML/CSS/JavaScript frontend. There is no Node.js, no npm, and no build step.

## Features

- **Secure authentication**: scrypt password hashing, server-side sessions in HttpOnly cookies, CSRF protection, and login throttling
- **Admin-only API**: every data route checks the administrator role on the server
- **User management**: create, view, edit, delete, activate/deactivate, and bulk delete with confirmation
- **Search**: by name, email, or role, handled by the server
- **Filters**: status, role, and registration date range, all combinable
- **Sorting and pagination**: validated, whitelisted sort columns and a configurable page size
- **Dashboard**: live stat cards, a user growth line chart, a status/role doughnut chart, and a revenue bar chart (Chart.js)
- **Activity log and notifications**: stored in SQLite
- **CSV export** of the filtered results, with spreadsheet formula-injection protection
- **UI**: collapsible sidebar, dark/light theme, responsive layout, toasts, modals, and empty states

## Tech stack

Python, FastAPI, SQLite, vanilla JavaScript, Chart.js, and Lucide icons (loaded from CDNs).

## Getting started

```bash
git clone https://github.com/<your-username>/harbor-admin-dashboard.git
cd harbor-admin-dashboard

python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
python main.py
```

Open http://127.0.0.1:8000 in your browser.

**Demo login:** `admin@example.com` / `ChangeMe123!`
Change this before sharing the app with anyone (see Configuration).

## Configuration

Settings are read from environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_EMAIL` | `admin@example.com` | Initial administrator email |
| `ADMIN_PASSWORD` | `ChangeMe123!` | Initial administrator password |
| `ADMIN_NAME` | `Demo Admin` | Administrator display name |
| `SESSION_SECRET` | random per start | Secret used to protect session tokens |
| `COOKIE_SECURE` | `0` | Set to `1` when serving over HTTPS |
| `DB_PATH` | `dashboard.db` next to `main.py` | SQLite database location |
| `HOST` / `PORT` | `127.0.0.1` / `8000` | Server address |

Example (PowerShell):

```powershell
$env:ADMIN_EMAIL="you@company.com"
$env:ADMIN_PASSWORD="a-long-strong-password"
$env:SESSION_SECRET="a-long-random-string"
python main.py
```

The initial admin is created only the first time the database is created. To apply new credentials, stop the app, delete `dashboard.db`, and start it again. This also resets the sample data.

## Database

The SQLite file is created automatically on first start with these tables: `users`, `admins`, `sessions`, `activity`, and `meta`. 48 sample users are added once. They are not re-added after a restart, even if you delete all users.

## API overview

All endpoints except `/` and `/api/login` require an authenticated administrator. State-changing requests also need the `X-CSRF-Token` header, which the built-in frontend sends automatically.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Dashboard or login page |
| POST | `/api/login` | Sign in |
| POST | `/api/logout` | Sign out |
| GET | `/api/me` | Current administrator |
| GET | `/api/users` | List with search, filters, sorting, pagination |
| POST | `/api/users` | Create a user |
| GET / PUT / DELETE | `/api/users/{id}` | Read, update, delete |
| PATCH | `/api/users/{id}/status` | Change status |
| POST | `/api/users/bulk-delete` | Delete several users |
| GET | `/api/users/export` | CSV export of filtered results |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/charts` | Chart data |
| GET | `/api/activity` | Activity log |
| GET | `/api/notifications` | Notification summary |

## Security notes

This is a solid starting point, not a certified production setup. Before deploying:

- Set strong `ADMIN_PASSWORD` and `SESSION_SECRET` values
- Serve over HTTPS and set `COOKIE_SECURE=1`
- Put the app behind a reverse proxy with rate limiting
- The login throttle is in-memory and resets on restart

## License

MIT
