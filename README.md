# KEC Budget Tracker
Department-level budget tracking system for Kongu Engineering College.

## Quick Start

### 1. Database (PostgreSQL)
```sql
CREATE DATABASE kec_budget_db;
```
Then run the backend once — it auto-creates all tables.

### 2. Backend
```bash
cd backend
pip install flask flask-cors psycopg2-binary PyJWT bcrypt Werkzeug python-dotenv
python app.py
# Runs on http://localhost:5001
```

### 3. Frontend
```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:5174
```

## Default Admin
- URL: http://localhost:5174/admin-login
- Email: admin@kec.ac.in
- Password: admin123
- Admin Secret (to register new admin): `kec-admin-2026`

## Flow
1. Admin logs in → sets sanctioned budget amounts per category
2. Users register → log expenses with bill upload
3. Amount auto-deducted from sanctioned budget
4. Admin tracks all expenses, approves/rejects, views bill proofs
5. Dashboard shows budget utilisation with charts

## Budget Categories (KEC IQAC Format)
- a) Recurring (Consumables, Service & Maintenance, Software Renewal)
- b) Programmes (Association, R&D, Clubs, Guest Lectures)
- c) Non-Recurring Equipment
- d) Non-Recurring Computers/Printers/Projectors
- e) Non-Recurring Software
- f) Non-Recurring Furniture
- g) Lab & Classroom Requirements
- Imprest Money Register
