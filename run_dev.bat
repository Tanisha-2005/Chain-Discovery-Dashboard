@echo off
echo ====================================================================
echo   🛡️ Starting Chain Discovery Dashboard Development Environment
echo ====================================================================

:: 1. Launch FastAPI Backend
echo [+] Launching FastAPI server on http://localhost:8000...
start cmd /k "title Chain Discovery Dashboard Backend && cd backend && python main.py --server"

:: 2. Launch Vite React Frontend
echo [+] Launching Vite React development server on http://localhost:5173...
start cmd /k "title Chain Discovery Dashboard Frontend && cd frontend && npm run dev"

echo ====================================================================
echo   [OK] Both components launched!
echo   - Interactive Web Dashboard: http://localhost:5173
echo   - FastAPI Backend Swagger Docs: http://localhost:8000/docs
echo ====================================================================
pause
