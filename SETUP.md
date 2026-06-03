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
│   ├── main.py                # Entry point
│   ├── database.py            # Database connection
│   ├── detection.py           # Threat detection logic
│   ├── ingestion.py           # Data ingestion
│   ├── models.py              # Data models
│   └── utils.py               # Utilities
├── frontend/                  # React frontend
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── components/        # Reusable components
│   │   │   ├── Alerts.jsx
│   │   │   └── Stats.jsx
│   │   ├── pages/
│   │   │   └── Dashboard.jsx
│   │   ├── styles/            # CSS styling
│   │   ├── App.jsx
│   │   └── index.js
│   ├── package.json           # Node dependencies
│   └── .gitignore
├── data/
│   └── sample_logs.json
└── requirements.txt           # Python dependencies
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

## API Endpoints (to implement)

These endpoints are called from the dashboard:
- `GET /api/stats` - Get dashboard statistics
- `GET /api/alerts` - Get security alerts
- `GET /api/threats` - Get active threats
- `POST /api/alerts/{id}/acknowledge` - Acknowledge an alert
- `POST /api/threats/{id}/investigate` - Start investigation

See the `// TODO:` comments in component files for implementation points.

---

## Next Steps

1. ✅ Dashboard UI is ready to display
2. 📝 Implement backend API endpoints in `backend/main.py`
3. 🔗 Connect frontend components to backend APIs
4. 📊 Add data visualization libraries (optional)
5. 🔄 Implement WebSocket for real-time updates
