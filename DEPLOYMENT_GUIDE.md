# PulseCheck — Complete Cloudflare Deployment Guide

You will deploy TWO things:
1. WORKER (backend API) → Cloudflare Workers + D1 Database
2. FRONTEND (index.html) → Cloudflare Pages

Total cost: FREE

---

## STAGE 1 — Create D1 Database

1. Go to https://dash.cloudflare.com
2. Click "Workers & Pages" in the left sidebar
3. Click "D1 SQL Database" in the left sidebar
4. Click "Create database"
5. Name it: pulsecheck-db
6. Click "Create"
7. COPY THE DATABASE ID (looks like: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
   ➜ You need this in Stage 2

---

## STAGE 2 — Deploy the Worker (Backend)

1. Go to https://dash.cloudflare.com
2. Click "Workers & Pages" in the left sidebar
3. Click "Create" → "Create Worker"
4. Name it: pulsecheck-api
5. Click "Deploy" (ignore the default code for now)
6. Click "Edit Code" on the next screen
7. DELETE all the existing code in the editor
8. PASTE the entire contents of worker.js
9. Click "Save and Deploy"

### Connect the D1 Database to your Worker:
10. Go back to your Worker overview page
11. Click "Settings" tab
12. Click "Bindings"
13. Click "Add" → "D1 Database"
14. Set Variable name: DB
15. Select database: pulsecheck-db
16. Click "Save"
17. Click "Deploy" again to redeploy with the binding

### Get your Worker URL:
18. On the Worker overview page, copy your Worker URL
    It looks like: https://pulsecheck-api.YOUR-SUBDOMAIN.workers.dev
    ➜ You need this in Stage 3

---

## STAGE 3 — Update Frontend with Worker URL

1. Open frontend/index.html in any text editor (Notepad, VS Code, etc.)
2. Find this line near the top (around line 46):
   const API = 'http://localhost:3001/api';
3. Replace it with your Worker URL:
   const API = 'https://pulsecheck-api.YOUR-SUBDOMAIN.workers.dev/api';
4. Save the file

---

## STAGE 4 — Deploy Frontend to Cloudflare Pages

1. Go to https://dash.cloudflare.com
2. Click "Workers & Pages" in the left sidebar
3. Click "Create" → "Pages"
4. Click "Direct Upload"
5. Name your project: pulsecheck
6. Click "Create project"
7. Drag and drop ONLY the index.html file (or the frontend folder)
8. Click "Deploy site"
9. Wait ~10 seconds
10. Cloudflare gives you a live URL like: https://pulsecheck.pages.dev

---

## STAGE 5 — Test Everything

1. Open your Pages URL: https://pulsecheck.pages.dev
2. Login with: admin / admin123
3. You should see the dashboard with sample data
4. Try adding an employee — if it saves, everything is working!

---

## Login Details
- Username: admin
- Password: admin123

---

## For Future Updates

### Update the frontend:
1. Edit index.html
2. Go to Cloudflare Pages → your project → Deployments
3. Click "Upload" and drop the new index.html

### Update the backend (worker):
1. Edit worker.js
2. Go to Cloudflare Workers → pulsecheck-api
3. Click "Edit Code" → paste updated code → Save and Deploy

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Login says "cannot connect" | Check the API URL in index.html matches your Worker URL exactly |
| Login says "invalid credentials" | Use admin / admin123 |
| Data not saving | Check the D1 binding is set to variable name "DB" |
| Worker errors | Go to Workers → pulsecheck-api → Logs to see error details |
