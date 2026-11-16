# SOC Dashboard - Setup & Run Instructions

## Prerequisites
- Node.js v16+ and npm
- Python 3.8+
- git

## Quick Start

### 1. **Setup Backend (FastAPI)**

```bash
# Navigate to project root
cd /home/casper/projects/Mini-SOC-dashboead-Treath-Detection

# Create a virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Run the backend server
python backend/main.py
# OR using uvicorn directly
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

The backend will start at `http://localhost:8000`

---

### 2. **Setup Frontend (React)**

In a **new terminal window**:

```bash
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Start React development server
npm start
```

The frontend will start at `http://localhost:3000` and automatically open in your browser.

---

## Project Structure

```
Mini-SOC-dashboead-Treath-Detection/
├── backend/                    # FastAPI backend
│   ├── main.py                # Entry point and API endpoints
│   ├── dataBase.py            # MongoDB connection (lazy, optional)
│   ├── models.py              # LogEntry / Alert schema (API contract)
│   ├── parsers.py             # One parser per log source (8 sources + journald)
│   ├── ingestion.py           # Normalizer, batch SHA-256 hashing, storage, queries
│   ├── detection.py           # Threat detection logic (to do)
│   └── utils.py               # Timestamps, hashing, IP helpers
├── collector/                 # Live log collection
│   ├── journalLogs.py         # journalctl follower
│   ├── sylog.py               # /var/log/syslog follower
│   ├── syslogListener.py      # UDP syslog listener (RFC 5424 / 3164)
│   └── fileTail.py            # Live tailing of <log_source>.log files
├── simulation/
│   ├── linuxAuth.py           # Real ssh / sudo attempts on localhost
│   └── logGenerator.py        # Synthetic logs for all sources + attack scenarios
├── tests/                     # pytest suite (MongoDB mocked with mongomock)
├── frontend/                  # React frontend
├── data/
│   └── sample_logs.json       # Small generated sample: [{log_source, raw}, ...]
├── requirements.txt           # Python dependencies
└── requirements-dev.txt       # + test dependencies
```

---

## MongoDB

The API stores everything in MongoDB at `mongodb://localhost:27017`, database `soc_dashboard`
(override with `MONGO_URI` / `MONGO_DB`). The API still starts without it and returns empty results.

On this machine MongoDB 8.0 is installed without root from the official tarball in
`~/.local/opt/mongodb`, with its data in `~/.local/share/mongodb`, and runs as a user service
bound to 127.0.0.1 only (no authentication, so do not expose the port):

```bash
systemctl --user status mongod      # start | stop | restart | disable
```

On another machine, install MongoDB the usual way (package, Docker, or the same tarball
from https://www.mongodb.com/try/download/community).

## Ingestion Pipeline

```bash
# Generate one hour of logs for all 8 sources, with 10 attack scenarios mixed in
python simulation/logGenerator.py --seed 42            # writes data/generated/<log_source>.log
python simulation/logGenerator.py --seed 42 --ingest   # ...and stores them in MongoDB
python simulation/logGenerator.py --list               # list the attack scenarios

# Real-time streaming: tail the files in one terminal, stream into them in another
python collector/fileTail.py data/generated
python simulation/logGenerator.py --stream --rate 20

# UDP syslog listener (port 514 needs root, so 5514 by default)
python collector/syslogListener.py --port 5514
logger -n 127.0.0.1 -P 5514 -d --rfc5424 "hello from logger"
```

Every batch of ingested lines gets a SHA-256 hash; `GET /api/batches/{id}/verify`
recomputes it to detect logs changed after ingestion.

`SOC_COLLECTOR` controls the collector started with the API:
`auto` (default), `journald`, `syslog` or `off`.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests
```

---

## Common Issues & Solutions

### Backend won't start
- Ensure Python virtual environment is activated
- Check if port 8000 is available: `lsof -i :8000`
- Verify all dependencies installed: `pip install -r requirements.txt`

### Frontend won't start
- Clear node_modules: `rm -rf node_modules` then `npm install`
- Check if port 3000 is available: `lsof -i :3000`
- Make sure you're in the `frontend/` directory

### API Connection Issues
- Frontend is configured to proxy to `http://localhost:8000`
- Ensure backend is running before starting frontend
- Check browser console (F12) for CORS errors

---

## Development Mode

Both servers support hot-reload:
- **Backend**: Changes to Python files auto-reload (with `--reload`)
- **Frontend**: Changes to React files auto-reload

Leave both terminal windows open during development.

---

## Building for Production

### Backend
```bash
# No build needed, just run with uvicorn in production mode
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Frontend
```bash
cd frontend
npm run build
# This creates an optimized build in frontend/build/
```

---

## API Endpoints

- `GET /api/logs` - Normalized logs; filters: `log_source`, `event_type`, `source_ip`, `username`, `search`, `limit`, `offset`
- `GET /api/stats` - Counts, trends against the previous period, severity counts and threat score
- `GET /api/alerts` - Suspicious events shown as alerts until the detection engine exists; filters: `severity`, `status`, `search`, `limit`, `offset`
- `GET /api/threats` - Unresolved IDS alerts
- `GET /api/timeline` - Latest high and critical alerts
- `GET /api/event-types` - Top event types and log sources
- `GET /api/source-ips` - Top source IPs
- `POST /api/alerts/{id}/acknowledge`, `POST|PATCH /api/alerts/{id}/resolve`, `POST /api/alerts/{id}/reopen`, `POST /api/threats/{id}/investigate` - Triage status, stored in MongoDB
- `GET /api/batches/{id}/verify` - Integrity check of an ingested batch

All dashboard endpoints accept `time_range` = `1h`, `24h` (default), `7d` or `30d`.
The dashboard reads all of them and refreshes every 10 seconds.

---

## Next Steps

1. ✅ Dashboard UI is ready to display
2. 📝 Implement backend API endpoints in `backend/main.py`
3. 🔗 Connect frontend components to backend APIs
4. 📊 Add data visualization libraries (optional)
5. 🔄 Implement WebSocket for real-time updates
