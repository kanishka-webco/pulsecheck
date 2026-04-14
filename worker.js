// PulseCheck — Cloudflare Worker Backend
// Handles all API requests, uses D1 for persistence

const JWT_SECRET = 'pulsecheck_secret_2025'; // Change this in production via env variable

// ─── CORS HEADERS ─────────────────────────────────────────────────────────
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ─── JWT (lightweight, no library needed) ─────────────────────────────────
const base64url = (str) => btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
const base64urlDecode = (str) => atob(str.replace(/-/g, '+').replace(/_/g, '/'));

async function signJWT(payload, secret) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${base64url(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key, Uint8Array.from(base64urlDecode(sig), c => c.charCodeAt(0)), new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(base64urlDecode(body));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch { return null; }
}

// ─── PASSWORD HASHING (using SubtleCrypto) ────────────────────────────────
async function hashPassword(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + 'pulsecheck_salt'));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, hash) {
  return (await hashPassword(password)) === hash;
}

// ─── HELPERS ──────────────────────────────────────────────────────────────
const uuid = () => crypto.randomUUID();
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
const err = (msg, status = 400) => json({ error: msg }, status);

const getMonthKey = (date = new Date()) =>
  `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;

const getBand = (pts) => {
  if (pts >= 85) return { label: 'Excellent', color: 'green' };
  if (pts >= 70) return { label: 'Satisfactory', color: 'blue' };
  if (pts >= 55) return { label: 'Needs Improvement', color: 'orange' };
  return { label: 'Critical Review', color: 'red' };
};

// ─── AUTH MIDDLEWARE ───────────────────────────────────────────────────────
async function requireAuth(request, env) {
  const token = request.headers.get('Authorization')?.split(' ')[1];
  if (!token) return null;
  return await verifyJWT(token, env.JWT_SECRET || JWT_SECRET);
}

// ─── DB INIT ──────────────────────────────────────────────────────────────
async function initDB(db) {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS admin (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT,
      name TEXT
    );
    CREATE TABLE IF NOT EXISTS employees (
      id TEXT PRIMARY KEY,
      name TEXT,
      jobTitle TEXT,
      department TEXT,
      email TEXT,
      phone TEXT,
      startDate TEXT,
      status TEXT DEFAULT 'active',
      avatar TEXT,
      createdAt TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      employeeId TEXT,
      monthKey TEXT,
      startingPoints INTEGER DEFAULT 100,
      currentPoints INTEGER DEFAULT 100,
      maxPoints INTEGER DEFAULT 150,
      status TEXT DEFAULT 'active',
      createdAt TEXT,
      UNIQUE(employeeId, monthKey)
    );
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      employeeId TEXT,
      type TEXT,
      category TEXT,
      points INTEGER,
      note TEXT,
      proof TEXT,
      monthKey TEXT,
      status TEXT DEFAULT 'approved',
      createdAt TEXT,
      createdBy TEXT
    );
  `);

  // Seed admin if not exists
  const adminExists = await db.prepare('SELECT id FROM admin WHERE id = ?').bind('admin-001').first();
  if (!adminExists) {
    const pwHash = await hashPassword('admin123');
    await db.prepare('INSERT INTO admin (id, username, password, name) VALUES (?, ?, ?, ?)').bind('admin-001', 'admin', pwHash, 'Admin').run();
  }
}

// ─── ROUTE HANDLERS ───────────────────────────────────────────────────────

// POST /api/auth/login
async function handleLogin(request, env) {
  const { username, password } = await request.json();
  const admin = await env.DB.prepare('SELECT * FROM admin WHERE username = ?').bind(username).first();
  if (!admin || !(await verifyPassword(password, admin.password))) return err('Invalid credentials', 401);
  const secret = env.JWT_SECRET || JWT_SECRET;
  const token = await signJWT({ id: admin.id, username: admin.username, role: 'admin', exp: Math.floor(Date.now() / 1000) + 604800 }, secret);
  return json({ token, user: { id: admin.id, username: admin.username, name: admin.name, role: 'admin' } });
}

// GET /api/employees
async function getEmployees(env) {
  const { results } = await env.DB.prepare('SELECT * FROM employees WHERE status = ? ORDER BY name').bind('active').all();
  return json(results);
}

// POST /api/employees
async function createEmployee(request, env, user) {
  const body = await request.json();
  const emp = {
    id: uuid(),
    name: body.name,
    jobTitle: body.jobTitle,
    department: body.department || 'Marketing',
    email: body.email,
    phone: body.phone || '',
    startDate: body.startDate || new Date().toISOString().split('T')[0],
    status: 'active',
    avatar: body.name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase(),
    createdAt: new Date().toISOString(),
  };
  await env.DB.prepare('INSERT INTO employees (id,name,jobTitle,department,email,phone,startDate,status,avatar,createdAt) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(emp.id, emp.name, emp.jobTitle, emp.department, emp.email, emp.phone, emp.startDate, emp.status, emp.avatar, emp.createdAt).run();
  // Create session for current month
  const monthKey = getMonthKey();
  await env.DB.prepare('INSERT OR IGNORE INTO sessions (id,employeeId,monthKey,startingPoints,currentPoints,maxPoints,status,createdAt) VALUES (?,?,?,100,100,150,"active",?)').bind(uuid(), emp.id, monthKey, new Date().toISOString()).run();
  return json(emp);
}

// PUT /api/employees/:id
async function updateEmployee(request, env, id) {
  const body = await request.json();
  await env.DB.prepare('UPDATE employees SET name=?,jobTitle=?,department=?,email=?,phone=?,startDate=? WHERE id=?').bind(body.name, body.jobTitle, body.department, body.email, body.phone || '', body.startDate, id).run();
  const emp = await env.DB.prepare('SELECT * FROM employees WHERE id=?').bind(id).first();
  return json(emp);
}

// DELETE /api/employees/:id
async function deleteEmployee(env, id) {
  await env.DB.prepare('UPDATE employees SET status="inactive" WHERE id=?').bind(id).run();
  return json({ success: true });
}

// GET /api/sessions
async function getSessions(request, env) {
  const url = new URL(request.url);
  const monthKey = url.searchParams.get('monthKey') || getMonthKey();
  const employeeId = url.searchParams.get('employeeId');

  // Init sessions for this month for all active employees
  const { results: emps } = await env.DB.prepare('SELECT * FROM employees WHERE status="active"').all();
  for (const emp of emps) {
    await env.DB.prepare('INSERT OR IGNORE INTO sessions (id,employeeId,monthKey,startingPoints,currentPoints,maxPoints,status,createdAt) VALUES (?,?,?,100,100,150,"active",?)').bind(uuid(), emp.id, monthKey, new Date().toISOString()).run();
  }

  let query = 'SELECT * FROM sessions WHERE monthKey=?';
  const params = [monthKey];
  if (employeeId) { query += ' AND employeeId=?'; params.push(employeeId); }

  const { results: sessions } = await env.DB.prepare(query).bind(...params).all();

  // Enrich with employee + events
  const enriched = await Promise.all(sessions.map(async s => {
    const employee = await env.DB.prepare('SELECT * FROM employees WHERE id=?').bind(s.employeeId).first();
    const { results: events } = await env.DB.prepare('SELECT * FROM events WHERE employeeId=? AND monthKey=? ORDER BY createdAt DESC').bind(s.employeeId, monthKey).all();
    return { ...s, employee, events };
  }));

  return json(enriched);
}

// GET /api/events
async function getEvents(request, env) {
  const url = new URL(request.url);
  const employeeId = url.searchParams.get('employeeId');
  const monthKey = url.searchParams.get('monthKey');
  let query = 'SELECT * FROM events WHERE 1=1';
  const params = [];
  if (employeeId) { query += ' AND employeeId=?'; params.push(employeeId); }
  if (monthKey) { query += ' AND monthKey=?'; params.push(monthKey); }
  query += ' ORDER BY createdAt DESC';
  const { results } = await env.DB.prepare(query).bind(...params).all();
  // Enrich with employee name
  const enriched = await Promise.all(results.map(async e => {
    const employee = await env.DB.prepare('SELECT * FROM employees WHERE id=?').bind(e.employeeId).first();
    return { ...e, employee };
  }));
  return json(enriched);
}

// POST /api/events
async function createEvent(request, env, user) {
  const body = await request.json();
  const { employeeId, type, category, points, note, monthKey } = body;
  if (!employeeId || !type || !category || !points || !note) return err('Missing required fields');
  const month = monthKey || getMonthKey();
  const pts = type === 'deduction' ? -Math.abs(Number(points)) : Math.abs(Number(points));
  const event = { id: uuid(), employeeId, type, category, points: pts, note, proof: body.proof || null, monthKey: month, status: 'approved', createdAt: new Date().toISOString(), createdBy: user.id };
  await env.DB.prepare('INSERT INTO events (id,employeeId,type,category,points,note,proof,monthKey,status,createdAt,createdBy) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind(event.id, event.employeeId, event.type, event.category, event.points, event.note, event.proof, event.monthKey, event.status, event.createdAt, event.createdBy).run();
  // Update session points
  const session = await env.DB.prepare('SELECT * FROM sessions WHERE employeeId=? AND monthKey=?').bind(employeeId, month).first();
  if (session) {
    const newPts = Math.min(150, Math.max(-999, session.currentPoints + pts));
    await env.DB.prepare('UPDATE sessions SET currentPoints=? WHERE id=?').bind(newPts, session.id).run();
  }
  return json(event);
}

// DELETE /api/events/:id
async function deleteEvent(env, id) {
  const event = await env.DB.prepare('SELECT * FROM events WHERE id=?').bind(id).first();
  if (!event) return err('Not found', 404);
  const session = await env.DB.prepare('SELECT * FROM sessions WHERE employeeId=? AND monthKey=?').bind(event.employeeId, event.monthKey).first();
  if (session) {
    const newPts = Math.min(150, session.currentPoints - event.points);
    await env.DB.prepare('UPDATE sessions SET currentPoints=? WHERE id=?').bind(newPts, session.id).run();
  }
  await env.DB.prepare('DELETE FROM events WHERE id=?').bind(id).run();
  return json({ success: true });
}

// GET /api/dashboard
async function getDashboard(env) {
  const monthKey = getMonthKey();
  const { results: emps } = await env.DB.prepare('SELECT * FROM employees WHERE status="active"').all();

  // Init sessions
  for (const emp of emps) {
    await env.DB.prepare('INSERT OR IGNORE INTO sessions (id,employeeId,monthKey,startingPoints,currentPoints,maxPoints,status,createdAt) VALUES (?,?,?,100,100,150,"active",?)').bind(uuid(), emp.id, monthKey, new Date().toISOString()).run();
  }

  const { results: sessions } = await env.DB.prepare('SELECT * FROM sessions WHERE monthKey=?').bind(monthKey).all();
  const enriched = await Promise.all(sessions.map(async s => {
    const employee = emps.find(e => e.id === s.employeeId);
    const { results: events } = await env.DB.prepare('SELECT * FROM events WHERE employeeId=? AND monthKey=?').bind(s.employeeId, monthKey).all();
    return { ...s, employee, events, band: getBand(s.currentPoints) };
  }));

  const { results: recentEventsRaw } = await env.DB.prepare('SELECT * FROM events WHERE monthKey=? ORDER BY createdAt DESC LIMIT 10').bind(monthKey).all();
  const recentEvents = await Promise.all(recentEventsRaw.map(async e => ({ ...e, employee: emps.find(emp => emp.id === e.employeeId) })));

  const avg = enriched.length ? Math.round(enriched.reduce((a, s) => a + s.currentPoints, 0) / enriched.length) : 0;

  return json({
    totalEmployees: emps.length,
    monthKey,
    averageScore: avg,
    sessions: enriched.sort((a, b) => b.currentPoints - a.currentPoints),
    recentEvents,
  });
}

// GET /api/employees/:id/history
async function getEmployeeHistory(env, id) {
  const { results } = await env.DB.prepare('SELECT * FROM sessions WHERE employeeId=? ORDER BY monthKey ASC').bind(id).all();
  return json(results);
}

// ─── MAIN ROUTER ──────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Init DB on every request (idempotent)
    await initDB(env.DB);

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Public route
    if (path === '/api/auth/login' && method === 'POST') return handleLogin(request, env);

    // All other routes require auth
    const user = await requireAuth(request, env);
    if (!user) return err('Unauthorized', 401);

    // Employees
    if (path === '/api/employees' && method === 'GET') return getEmployees(env);
    if (path === '/api/employees' && method === 'POST') return createEmployee(request, env, user);
    if (path.match(/^\/api\/employees\/[^/]+$/) && method === 'PUT') return updateEmployee(request, env, path.split('/')[3]);
    if (path.match(/^\/api\/employees\/[^/]+$/) && method === 'DELETE') return deleteEmployee(env, path.split('/')[3]);
    if (path.match(/^\/api\/employees\/[^/]+\/history$/) && method === 'GET') return getEmployeeHistory(env, path.split('/')[3]);

    // Sessions
    if (path === '/api/sessions' && method === 'GET') return getSessions(request, env);

    // Events
    if (path === '/api/events' && method === 'GET') return getEvents(request, env);
    if (path === '/api/events' && method === 'POST') return createEvent(request, env, user);
    if (path.match(/^\/api\/events\/[^/]+$/) && method === 'DELETE') return deleteEvent(env, path.split('/')[3]);

    // Dashboard
    if (path === '/api/dashboard' && method === 'GET') return getDashboard(env);

    return err('Not found', 404);
  }
};
