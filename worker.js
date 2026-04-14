// PulseCheck — Cloudflare Worker Backend

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ─── HELPERS ──────────────────────────────────────────────────────────────
const uuid = () => crypto.randomUUID();
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
const err = (msg, status = 400) => json({ error: msg }, status);
const getMonthKey = (date = new Date()) => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
const getBand = (pts) => {
  if (pts >= 85) return { label: 'Excellent', color: 'green' };
  if (pts >= 70) return { label: 'Satisfactory', color: 'blue' };
  if (pts >= 55) return { label: 'Needs Improvement', color: 'orange' };
  return { label: 'Critical Review', color: 'red' };
};

// ─── JWT ──────────────────────────────────────────────────────────────────
function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b64urlStr(str) {
  const bytes = new TextEncoder().encode(str);
  return b64url(bytes);
}
function b64urlDecode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function signJWT(payload, secret) {
  const header = b64urlStr(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64urlStr(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${b64url(new Uint8Array(sig))}`;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key, b64urlDecode(sig), new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch (e) { return null; }
}

// ─── PASSWORD ─────────────────────────────────────────────────────────────
async function hashPassword(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + 'pulsecheck_salt'));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function verifyPassword(password, hash) {
  return (await hashPassword(password)) === hash;
}

// ─── AUTH MIDDLEWARE ───────────────────────────────────────────────────────
async function requireAuth(request, env) {
  const token = request.headers.get('Authorization')?.split(' ')[1];
  if (!token) return null;
  const secret = env.JWT_SECRET || 'pulsecheck_secret_2025';
  return await verifyJWT(token, secret);
}

// ─── DB INIT ──────────────────────────────────────────────────────────────
async function initDB(db) {
  try {
    await db.exec(`CREATE TABLE IF NOT EXISTS admin (id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT, name TEXT)`);
    await db.exec(`CREATE TABLE IF NOT EXISTS employees (id TEXT PRIMARY KEY, name TEXT, jobTitle TEXT, department TEXT, email TEXT, phone TEXT, startDate TEXT, status TEXT DEFAULT 'active', avatar TEXT, createdAt TEXT)`);
    await db.exec(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, employeeId TEXT, monthKey TEXT, startingPoints INTEGER DEFAULT 100, currentPoints INTEGER DEFAULT 100, maxPoints INTEGER DEFAULT 150, status TEXT DEFAULT 'active', createdAt TEXT, UNIQUE(employeeId, monthKey))`);
    await db.exec(`CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, employeeId TEXT, type TEXT, category TEXT, points INTEGER, note TEXT, proof TEXT, monthKey TEXT, status TEXT DEFAULT 'approved', createdAt TEXT, createdBy TEXT)`);

    const adminExists = await db.prepare('SELECT id FROM admin WHERE id = ?').bind('admin-001').first();
    if (!adminExists) {
      const pwHash = await hashPassword('admin123');
      await db.prepare('INSERT INTO admin (id, username, password, name) VALUES (?, ?, ?, ?)').bind('admin-001', 'admin', pwHash, 'Admin').run();
    }
  } catch (e) {
    console.error('DB init error:', e.message);
  }
}

// ─── HANDLERS ─────────────────────────────────────────────────────────────

async function handleLogin(request, env) {
  try {
    const { username, password } = await request.json();
    const admin = await env.DB.prepare('SELECT * FROM admin WHERE username = ?').bind(username).first();
    if (!admin || !(await verifyPassword(password, admin.password))) return err('Invalid credentials', 401);
    const secret = env.JWT_SECRET || 'pulsecheck_secret_2025';
    const token = await signJWT({ id: admin.id, username: admin.username, role: 'admin', exp: Math.floor(Date.now() / 1000) + 604800 }, secret);
    return json({ token, user: { id: admin.id, username: admin.username, name: admin.name, role: 'admin' } });
  } catch (e) {
    return err('Login error: ' + e.message, 500);
  }
}

async function getEmployees(env) {
  const { results } = await env.DB.prepare("SELECT * FROM employees WHERE status = 'active' ORDER BY name").all();
  return json(results);
}

async function createEmployee(request, env) {
  const body = await request.json();
  const emp = {
    id: uuid(), name: body.name, jobTitle: body.jobTitle,
    department: body.department || 'Marketing', email: body.email,
    phone: body.phone || '', startDate: body.startDate || new Date().toISOString().split('T')[0],
    status: 'active',
    avatar: body.name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase(),
    createdAt: new Date().toISOString(),
  };
  await env.DB.prepare('INSERT INTO employees (id,name,jobTitle,department,email,phone,startDate,status,avatar,createdAt) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(emp.id, emp.name, emp.jobTitle, emp.department, emp.email, emp.phone, emp.startDate, emp.status, emp.avatar, emp.createdAt).run();
  const monthKey = getMonthKey();
  await env.DB.prepare('INSERT OR IGNORE INTO sessions (id,employeeId,monthKey,startingPoints,currentPoints,maxPoints,status,createdAt) VALUES (?,?,?,100,100,150,?,?)').bind(uuid(), emp.id, monthKey, 'active', new Date().toISOString()).run();
  return json(emp);
}

async function updateEmployee(request, env, id) {
  const body = await request.json();
  await env.DB.prepare('UPDATE employees SET name=?,jobTitle=?,department=?,email=?,phone=?,startDate=? WHERE id=?').bind(body.name, body.jobTitle, body.department, body.email, body.phone || '', body.startDate, id).run();
  const emp = await env.DB.prepare('SELECT * FROM employees WHERE id=?').bind(id).first();
  return json(emp);
}

async function deleteEmployee(env, id) {
  await env.DB.prepare("UPDATE employees SET status='inactive' WHERE id=?").bind(id).run();
  return json({ success: true });
}

async function initSessionsForMonth(env, monthKey) {
  const { results: emps } = await env.DB.prepare("SELECT * FROM employees WHERE status='active'").all();
  for (const emp of emps) {
    await env.DB.prepare('INSERT OR IGNORE INTO sessions (id,employeeId,monthKey,startingPoints,currentPoints,maxPoints,status,createdAt) VALUES (?,?,?,100,100,150,?,?)').bind(uuid(), emp.id, monthKey, 'active', new Date().toISOString()).run();
  }
}

async function getSessions(request, env) {
  const url = new URL(request.url);
  const monthKey = url.searchParams.get('monthKey') || getMonthKey();
  const employeeId = url.searchParams.get('employeeId');
  await initSessionsForMonth(env, monthKey);
  let query = 'SELECT * FROM sessions WHERE monthKey=?';
  const params = [monthKey];
  if (employeeId) { query += ' AND employeeId=?'; params.push(employeeId); }
  const { results: sessions } = await env.DB.prepare(query).bind(...params).all();
  const { results: emps } = await env.DB.prepare("SELECT * FROM employees WHERE status='active'").all();
  const enriched = await Promise.all(sessions.map(async s => {
    const employee = emps.find(e => e.id === s.employeeId);
    const { results: events } = await env.DB.prepare('SELECT * FROM events WHERE employeeId=? AND monthKey=? ORDER BY createdAt DESC').bind(s.employeeId, monthKey).all();
    return { ...s, employee, events };
  }));
  return json(enriched);
}

async function getEvents(request, env) {
  const url = new URL(request.url);
  const employeeId = url.searchParams.get('employeeId');
  const monthKey = url.searchParams.get('monthKey');
  let query = 'SELECT * FROM events WHERE 1=1';
  const params = [];
  if (employeeId) { query += ' AND employeeId=?'; params.push(employeeId); }
  if (monthKey) { query += ' AND monthKey=?'; params.push(monthKey); }
  query += ' ORDER BY createdAt DESC';
  const { results } = params.length ? await env.DB.prepare(query).bind(...params).all() : await env.DB.prepare(query).all();
  const { results: emps } = await env.DB.prepare("SELECT * FROM employees").all();
  const enriched = results.map(e => ({ ...e, employee: emps.find(em => em.id === e.employeeId) }));
  return json(enriched);
}

async function createEvent(request, env, user) {
  const body = await request.json();
  const { employeeId, type, category, points, note, monthKey } = body;
  if (!employeeId || !type || !category || !points || !note) return err('Missing required fields');
  const month = monthKey || getMonthKey();
  const pts = type === 'deduction' ? -Math.abs(Number(points)) : Math.abs(Number(points));
  const event = { id: uuid(), employeeId, type, category, points: pts, note, proof: body.proof || null, monthKey: month, status: 'approved', createdAt: new Date().toISOString(), createdBy: user.id };
  await env.DB.prepare('INSERT INTO events (id,employeeId,type,category,points,note,proof,monthKey,status,createdAt,createdBy) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind(event.id, event.employeeId, event.type, event.category, event.points, event.note, event.proof, event.monthKey, event.status, event.createdAt, event.createdBy).run();
  const session = await env.DB.prepare('SELECT * FROM sessions WHERE employeeId=? AND monthKey=?').bind(employeeId, month).first();
  if (session) {
    const newPts = Math.min(150, Math.max(-999, session.currentPoints + pts));
    await env.DB.prepare('UPDATE sessions SET currentPoints=? WHERE id=?').bind(newPts, session.id).run();
  }
  return json(event);
}

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

async function getDashboard(env) {
  const monthKey = getMonthKey();
  await initSessionsForMonth(env, monthKey);
  const { results: emps } = await env.DB.prepare("SELECT * FROM employees WHERE status='active'").all();
  const { results: sessions } = await env.DB.prepare('SELECT * FROM sessions WHERE monthKey=?').bind(monthKey).all();
  const enriched = await Promise.all(sessions.map(async s => {
    const employee = emps.find(e => e.id === s.employeeId);
    const { results: events } = await env.DB.prepare('SELECT * FROM events WHERE employeeId=? AND monthKey=?').bind(s.employeeId, monthKey).all();
    return { ...s, employee, events, band: getBand(s.currentPoints) };
  }));
  const { results: recentEventsRaw } = await env.DB.prepare('SELECT * FROM events WHERE monthKey=? ORDER BY createdAt DESC LIMIT 10').bind(monthKey).all();
  const recentEvents = recentEventsRaw.map(e => ({ ...e, employee: emps.find(emp => emp.id === e.employeeId) }));
  const avg = enriched.length ? Math.round(enriched.reduce((a, s) => a + s.currentPoints, 0) / enriched.length) : 0;
  return json({ totalEmployees: emps.length, monthKey, averageScore: avg, sessions: enriched.sort((a, b) => b.currentPoints - a.currentPoints), recentEvents });
}

async function getEmployeeHistory(env, id) {
  const { results } = await env.DB.prepare('SELECT * FROM sessions WHERE employeeId=? ORDER BY monthKey ASC').bind(id).all();
  return json(results);
}

// ─── MAIN ROUTER ──────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders });

    try {
      await initDB(env.DB);
    } catch (e) {
      return err('DB initialization failed: ' + e.message, 500);
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Public
    if (path === '/api/auth/login' && method === 'POST') return handleLogin(request, env);
    if (path === '/api/health') return json({ status: 'ok', time: new Date().toISOString() });

    // Auth required
    const user = await requireAuth(request, env);
    if (!user) return err('Unauthorized', 401);

    try {
      if (path === '/api/employees' && method === 'GET') return getEmployees(env);
      if (path === '/api/employees' && method === 'POST') return createEmployee(request, env);
      if (path === '/api/sessions' && method === 'GET') return getSessions(request, env);
      if (path === '/api/events' && method === 'GET') return getEvents(request, env);
      if (path === '/api/events' && method === 'POST') return createEvent(request, env, user);
      if (path === '/api/dashboard' && method === 'GET') return getDashboard(env);

      const empMatch = path.match(/^\/api\/employees\/([^/]+)$/);
      if (empMatch && method === 'PUT') return updateEmployee(request, env, empMatch[1]);
      if (empMatch && method === 'DELETE') return deleteEmployee(env, empMatch[1]);

      const histMatch = path.match(/^\/api\/employees\/([^/]+)\/history$/);
      if (histMatch && method === 'GET') return getEmployeeHistory(env, histMatch[1]);

      const evtMatch = path.match(/^\/api\/events\/([^/]+)$/);
      if (evtMatch && method === 'DELETE') return deleteEvent(env, evtMatch[1]);

      return err('Not found', 404);
    } catch (e) {
      return err('Server error: ' + e.message, 500);
    }
  }
};
