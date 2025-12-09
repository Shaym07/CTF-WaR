const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');
const NodeCache = require('node-cache');
const { marked } = require('marked');
const sanitizeHtml = require('sanitize-html');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');

const app = express();
const server = http.createServer(app);

// ==================== CONFIGURATION ====================
const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://vfhilobaycsxwbjojgjc.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'c073386cb88b7d2fc6a4ad3ea0ab5718';
const FLAG_PREFIXES = (process.env.FLAG_PREFIXES || 'WOW').split(',').map(s => s.trim());
const PLATFORM_NAME = process.env.PLATFORM_NAME || 'CTF War';

// ==================== CACHE ====================
const cache = new NodeCache({ stdTTL: 60, checkperiod: 120 });

// ==================== SUPABASE CLIENT ====================
const supabase = SUPABASE_KEY ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

// ==================== WEBSOCKET ====================
const wss = new WebSocket.Server({ server, path: '/ws' });
const wsClients = new Map();

wss.on('connection', (ws) => {
  const clientId = uuidv4();
  wsClients.set(clientId, { ws, subscribedTo: new Set() });

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'subscribe') wsClients.get(clientId).subscribedTo.add(data.channel);
      if (data.type === 'unsubscribe') wsClients.get(clientId).subscribedTo.delete(data.channel);
    } catch (e) {}
  });

  ws.on('close', () => wsClients.delete(clientId));
  ws.on('error', () => wsClients.delete(clientId));
});

function broadcast(channel, data) {
  wsClients.forEach(client => {
    if (client.ws.readyState === WebSocket.OPEN) {
      if (!channel || client.subscribedTo.has(channel) || client.subscribedTo.has('*')) {
        client.ws.send(JSON.stringify(data));
      }
    }
  });
}

// ==================== MIDDLEWARE ====================
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('combined'));

// Rate limiters
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts' } });
const submitLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, message: { error: 'Too many submissions' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 200, message: { error: 'Rate limit exceeded' } });

app.use('/auth', authLimiter);
app.use(apiLimiter);

// ==================== CTF CONFIGURATION ====================
let ctfConfig = {
  name: PLATFORM_NAME,
  description: 'Ultimate CTF Competition Platform',
  start_time: null,
  end_time: null,
  freeze_time: null,
  registration_open: true,
  ctf_started: true,
  ctf_ended: false,
  scoreboard_frozen: false,
  scoreboard_visible: true,
  registration_code: null,
  team_mode: true,
  team_size_limit: 5,
  user_mode: 'teams',
  score_visibility: 'public',
  account_visibility: 'public',
  challenge_visibility: 'public',
  paused: false,
  theme: 'dark'
};

// ==================== SCORING ALGORITHMS ====================
const scoringAlgorithms = {
  static: (initial) => initial,
  dynamic: (initial, solves, decay = 15, minimum = 50) => {
    return Math.max(minimum, Math.floor(initial * (decay / (decay + solves - 1))));
  },
  logarithmic: (initial, solves, minimum = 50) => {
    if (solves <= 1) return initial;
    return Math.max(minimum, Math.floor(initial - (initial - minimum) * Math.log10(solves) / 2));
  }
};

// ==================== ACHIEVEMENTS ====================
const achievementDefinitions = [
  { id: 'first_blood', name: 'First Blood', description: 'First to solve a challenge', icon: '🩸', points: 50 },
  { id: 'speed_demon', name: 'Speed Demon', description: 'Solve in under 5 minutes', icon: '⚡', points: 25 },
  { id: 'perfectionist', name: 'Perfectionist', description: 'Solve 10 challenges', icon: '🎯', points: 100 },
  { id: 'master', name: 'Master', description: 'Solve 25 challenges', icon: '🏆', points: 250 },
  { id: 'legend', name: 'Legend', description: 'Solve 50 challenges', icon: '👑', points: 500 },
  { id: 'team_player', name: 'Team Player', description: 'Join a team', icon: '👥', points: 25 },
  { id: 'team_captain', name: 'Team Captain', description: 'Create a team', icon: '🚀', points: 50 },
  { id: 'night_owl', name: 'Night Owl', description: 'Submit between 12AM-5AM', icon: '🦉', points: 25 },
  { id: 'early_bird', name: 'Early Bird', description: 'Submit between 5AM-8AM', icon: '🐦', points: 25 },
  { id: 'category_master_web', name: 'Web Master', description: 'Solve all Web challenges', icon: '🌐', points: 100 },
  { id: 'category_master_crypto', name: 'Crypto Master', description: 'Solve all Crypto challenges', icon: '🔐', points: 100 },
  { id: 'category_master_pwn', name: 'Pwn Master', description: 'Solve all Pwn challenges', icon: '💥', points: 100 },
  { id: 'category_master_reverse', name: 'Reverse Master', description: 'Solve all Reverse challenges', icon: '🔄', points: 100 },
  { id: 'category_master_forensics', name: 'Forensics Master', description: 'Solve all Forensics challenges', icon: '🔍', points: 100 },
  { id: 'hint_hater', name: 'Hint Hater', description: 'Solve 5 without hints', icon: '🧠', points: 75 },
  { id: 'centurion', name: 'Centurion', description: 'Reach 1000 points', icon: '💯', points: 50 },
  { id: 'millionaire', name: 'Millionaire', description: 'Reach 10000 points', icon: '💰', points: 100 },
  { id: 'writeup_author', name: 'Writeup Author', description: 'Submit a writeup', icon: '📝', points: 25 },
  { id: 'streak_3', name: 'Hot Streak', description: '3 solves in a row', icon: '🔥', points: 50 },
  { id: 'all_categories', name: 'Well Rounded', description: 'Solve in all categories', icon: '🎭', points: 150 }
];

// ==================== HELPER FUNCTIONS ====================
function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function sanitize(html) {
  return sanitizeHtml(html, {
    allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'img'],
    allowedAttributes: { 'a': ['href', 'target'], 'img': ['src', 'alt'] }
  });
}

function renderMarkdown(text) {
  if (!text) return '';
  return sanitize(marked.parse(text));
}

function validateFlag(submittedFlag, correctFlag, flagType = 'static', caseSensitive = true) {
  if (!submittedFlag || !correctFlag) return false;
  if (flagType === 'regex') {
    try {
      const regex = new RegExp(correctFlag, caseSensitive ? '' : 'i');
      return regex.test(submittedFlag);
    } catch { return false; }
  }
  if (caseSensitive) return submittedFlag === correctFlag;
  return submittedFlag.toLowerCase() === correctFlag.toLowerCase();
}

function checkCTFAccess() {
  if (ctfConfig.paused) return { allowed: false, reason: 'CTF is paused' };
  if (!ctfConfig.ctf_started) return { allowed: false, reason: 'CTF has not started' };
  if (ctfConfig.ctf_ended) return { allowed: false, reason: 'CTF has ended' };
  const now = new Date();
  if (ctfConfig.start_time && new Date(ctfConfig.start_time) > now) {
    return { allowed: false, reason: 'CTF has not started yet' };
  }
  if (ctfConfig.end_time && new Date(ctfConfig.end_time) < now) {
    return { allowed: false, reason: 'CTF has ended' };
  }
  return { allowed: true };
}

// ==================== AUTH MIDDLEWARE ====================
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token provided' });
  const decoded = verifyToken(auth.slice(7));
  if (!decoded) return res.status(401).json({ error: 'Invalid token' });
  try {
    const { data: user } = await supabase.from('users').select('*').eq('id', decoded.id).single();
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (user.banned) return res.status(403).json({ error: 'Account banned' });
    req.user = user;
    next();
  } catch (err) {
    res.status(500).json({ error: 'Auth error' });
  }
}

async function requireAdmin(req, res, next) {
  await requireAuth(req, res, () => {
    if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin required' });
    next();
  });
}

async function optionalAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (auth?.startsWith('Bearer ')) {
    const decoded = verifyToken(auth.slice(7));
    if (decoded) {
      try {
        const { data: user } = await supabase.from('users').select('*').eq('id', decoded.id).single();
        req.user = user;
      } catch {}
    }
  }
  next();
}

// ==================== ROUTES ====================
app.get('/', (req, res) => res.json({
  status: 'ok', platform: PLATFORM_NAME, version: '4.0.0',
  features: ['challenges', 'teams', 'scoreboard', 'achievements', 'writeups', 'brackets', 'dynamic_scoring', 'hints', 'announcements', 'admin_panel']
}));

app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

app.get('/config', (req, res) => {
  res.json({
    name: ctfConfig.name, description: ctfConfig.description,
    start_time: ctfConfig.start_time, end_time: ctfConfig.end_time,
    registration_open: ctfConfig.registration_open, team_mode: ctfConfig.team_mode,
    user_mode: ctfConfig.user_mode, paused: ctfConfig.paused, theme: ctfConfig.theme
  });
});

// ==================== AUTH ROUTES ====================
app.post('/auth/register', async (req, res) => {
  try {
    const { username, email, password, team_token, bracket_id, affiliation, country } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'Username, email and password required' });
    if (!ctfConfig.registration_open) return res.status(403).json({ error: 'Registration is closed' });
    if (username.length < 3 || username.length > 30) return res.status(400).json({ error: 'Username must be 3-30 characters' });

    const { data: existing } = await supabase.from('users').select('id').or(`email.eq.${email},username.eq.${username}`).limit(1);
    if (existing?.length) return res.status(400).json({ error: 'Email or username already exists' });

    const hashedPassword = await bcrypt.hash(password, 12);
    const userId = uuidv4();

    const { data: user, error } = await supabase.from('users').insert({
      id: userId, username, email, password: hashedPassword, role: 'user', score: 0,
      bracket_id: bracket_id || null, affiliation: affiliation || null, country: country || null,
      verified: false, banned: false, hidden: false, created_at: new Date().toISOString()
    }).select().single();

    if (error) throw error;

    if (team_token) {
      const { data: team } = await supabase.from('teams').select('*').eq('invite_code', team_token).single();
      if (team) {
        await supabase.from('users').update({ team_id: team.id }).eq('id', userId);
        user.team_id = team.id;
      }
    }

    const token = generateToken(user);
    res.json({ token, user: { ...user, password: undefined } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.banned) return res.status(403).json({ error: 'Account banned' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    await supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', user.id);
    const token = generateToken(user);
    res.json({ token, user: { ...user, password: undefined } });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('*, teams:team_id (id, name, captain_id)').eq('id', req.user.id).single();
    const { count: solveCount } = await supabase.from('solves').select('id', { count: 'exact' }).eq('user_id', req.user.id);
    res.json({ user: { ...user, password: undefined, solve_count: solveCount || 0 } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get user' });
  }
});

app.put('/auth/profile', requireAuth, async (req, res) => {
  try {
    const { affiliation, country, website, bio } = req.body;
    await supabase.from('users').update({ affiliation, country, website, bio, updated_at: new Date().toISOString() }).eq('id', req.user.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

app.post('/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    const valid = await bcrypt.compare(current_password, req.user.password);
    if (!valid) return res.status(400).json({ error: 'Current password incorrect' });
    const hashed = await bcrypt.hash(new_password, 12);
    await supabase.from('users').update({ password: hashed }).eq('id', req.user.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Password change failed' });
  }
});

// ==================== CHALLENGES ====================
app.get('/challenges', optionalAuth, async (req, res) => {
  try {
    const access = checkCTFAccess();
    if (!access.allowed && req.user?.role !== 'admin') return res.status(403).json({ error: access.reason });

    let query = supabase.from('challenges').select('id, title, description, category, points, difficulty, files, url, max_attempts, type, state, scoring_type, initial_points, minimum_points, decay, prerequisites, tags, created_at');
    if (req.user?.role !== 'admin') query = query.eq('state', 'visible');
    const { data: challenges, error } = await query.order('category').order('points');
    if (error) throw error;

    // Get solve counts
    const { data: solveData } = await supabase.from('solves').select('challenge_id');
    const solveCounts = {};
    solveData?.forEach(s => { solveCounts[s.challenge_id] = (solveCounts[s.challenge_id] || 0) + 1; });

    // Get user solves
    let userSolves = new Set();
    if (req.user) {
      const { data: solves } = await supabase.from('solves').select('challenge_id').eq('user_id', req.user.id);
      userSolves = new Set(solves?.map(s => s.challenge_id) || []);
    }

    // Get first bloods
    const { data: firstBloods } = await supabase.from('solves').select('challenge_id, user_id, users!inner(username)').order('created_at', { ascending: true });
    const firstBloodMap = {};
    firstBloods?.forEach(fb => { if (!firstBloodMap[fb.challenge_id]) firstBloodMap[fb.challenge_id] = fb.users?.username; });

    // Get hints
    const { data: hints } = await supabase.from('hints').select('id, challenge_id, cost');
    const hintMap = {};
    hints?.forEach(h => { if (!hintMap[h.challenge_id]) hintMap[h.challenge_id] = []; hintMap[h.challenge_id].push({ id: h.id, cost: h.cost }); });

    // Process challenges
    const processed = challenges.map(c => {
      const solveCount = solveCounts[c.id] || 0;
      let points = c.points;
      if (c.scoring_type === 'dynamic') points = scoringAlgorithms.dynamic(c.initial_points || c.points, solveCount, c.decay || 15, c.minimum_points || 50);
      else if (c.scoring_type === 'logarithmic') points = scoringAlgorithms.logarithmic(c.initial_points || c.points, solveCount, c.minimum_points || 50);

      return {
        ...c, points, solve_count: solveCount, solved_by_user: userSolves.has(c.id),
        first_blood_user: firstBloodMap[c.id] || null, hints: hintMap[c.id] || [],
        description_html: renderMarkdown(c.description)
      };
    });

    // Filter by prerequisites
    const filtered = processed.filter(c => {
      if (!c.prerequisites?.length) return true;
      return c.prerequisites.every(prereqId => userSolves.has(prereqId));
    });

    res.json({ challenges: req.user?.role === 'admin' ? processed : filtered });
  } catch (err) {
    console.error('Challenges error:', err);
    res.status(500).json({ error: 'Failed to load challenges' });
  }
});

app.get('/challenges/categories', async (req, res) => {
  try {
    const { data } = await supabase.from('challenges').select('category').eq('state', 'visible');
    const categories = [...new Set(data?.map(c => c.category) || [])];
    res.json({ categories });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load categories' });
  }
});

app.get('/challenges/:id', optionalAuth, async (req, res) => {
  try {
    const { data: challenge } = await supabase.from('challenges').select('*').eq('id', req.params.id).single();
    if (!challenge) return res.status(404).json({ error: 'Challenge not found' });
    if (challenge.state !== 'visible' && req.user?.role !== 'admin') return res.status(404).json({ error: 'Challenge not found' });

    const { data: hints } = await supabase.from('hints').select('id, cost, content').eq('challenge_id', challenge.id);
    let unlockedHints = [];
    if (req.user) {
      const { data: unlocked } = await supabase.from('hint_unlocks').select('hint_id').eq('user_id', req.user.id);
      unlockedHints = unlocked?.map(h => h.hint_id) || [];
    }

    const { data: solves } = await supabase.from('solves').select('user_id, users!inner(username), created_at').eq('challenge_id', challenge.id).order('created_at', { ascending: true }).limit(10);

    res.json({
      challenge: {
        ...challenge, flag: undefined, description_html: renderMarkdown(challenge.description),
        hints: hints?.map(h => ({ id: h.id, cost: h.cost, content: unlockedHints.includes(h.id) ? h.content : null, unlocked: unlockedHints.includes(h.id) })) || [],
        solves: solves?.map(s => ({ username: s.users?.username, time: s.created_at })) || []
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load challenge' });
  }
});

app.post('/challenges/:id/submit', requireAuth, submitLimiter, async (req, res) => {
  try {
    const access = checkCTFAccess();
    if (!access.allowed) return res.status(403).json({ error: access.reason });

    const { flag } = req.body;
    const challengeId = req.params.id;
    if (!flag) return res.status(400).json({ error: 'Flag required' });

    const { data: challenge } = await supabase.from('challenges').select('*').eq('id', challengeId).single();
    if (!challenge) return res.status(404).json({ error: 'Challenge not found' });
    if (challenge.state !== 'visible') return res.status(403).json({ error: 'Challenge not available' });

    const { data: existingSolve } = await supabase.from('solves').select('id').eq('user_id', req.user.id).eq('challenge_id', challengeId).single();
    if (existingSolve) return res.status(400).json({ error: 'Already solved', correct: true, already_solved: true });

    if (challenge.max_attempts) {
      const { count } = await supabase.from('submissions').select('id', { count: 'exact' }).eq('user_id', req.user.id).eq('challenge_id', challengeId);
      if (count >= challenge.max_attempts) return res.status(403).json({ error: 'Max attempts reached' });
    }

    await supabase.from('submissions').insert({ id: uuidv4(), user_id: req.user.id, team_id: req.user.team_id, challenge_id: challengeId, flag: flag.substring(0, 500), correct: false, created_at: new Date().toISOString() });

    const correct = validateFlag(flag.trim(), challenge.flag, challenge.flag_type || 'static', challenge.case_sensitive !== false);
    if (!correct) return res.json({ correct: false, message: 'Incorrect flag' });

    const { count: solveCount } = await supabase.from('solves').select('id', { count: 'exact' }).eq('challenge_id', challengeId);
    let points = challenge.points;
    if (challenge.scoring_type === 'dynamic') points = scoringAlgorithms.dynamic(challenge.initial_points || challenge.points, (solveCount || 0) + 1, challenge.decay || 15, challenge.minimum_points || 50);

    const isFirstBlood = solveCount === 0;

    await supabase.from('solves').insert({ id: uuidv4(), user_id: req.user.id, team_id: req.user.team_id, challenge_id: challengeId, points, first_blood: isFirstBlood, created_at: new Date().toISOString() });
    await supabase.from('users').update({ score: (req.user.score || 0) + points }).eq('id', req.user.id);

    if (req.user.team_id) {
      const { data: team } = await supabase.from('teams').select('score').eq('id', req.user.team_id).single();
      await supabase.from('teams').update({ score: (team?.score || 0) + points }).eq('id', req.user.team_id);
    }

    await supabase.from('submissions').update({ correct: true }).eq('user_id', req.user.id).eq('challenge_id', challengeId).eq('flag', flag.substring(0, 500));
    await checkAndGrantAchievements(req.user.id, { type: 'solve', challengeId, isFirstBlood, points });

    if (isFirstBlood) broadcast('scoreboard', { type: 'first_blood', challenge: challenge.title, username: req.user.username, points });
    broadcast('scoreboard', { type: 'scoreboard_update' });
    cache.del('scoreboard');

    res.json({ correct: true, points, first_blood: isFirstBlood, message: isFirstBlood ? '🩸 First Blood!' : 'Correct!' });
  } catch (err) {
    console.error('Submit error:', err);
    res.status(500).json({ error: 'Submission failed' });
  }
});

// ==================== HINTS ====================
app.post('/hints/:id/unlock', requireAuth, async (req, res) => {
  try {
    const { data: hint } = await supabase.from('hints').select('*, challenges!inner(id, title)').eq('id', req.params.id).single();
    if (!hint) return res.status(404).json({ error: 'Hint not found' });

    const { data: existing } = await supabase.from('hint_unlocks').select('id').eq('user_id', req.user.id).eq('hint_id', hint.id).single();
    if (existing) return res.json({ content: hint.content, cost: 0, already_unlocked: true });

    if (hint.cost > 0) {
      if (req.user.score < hint.cost) return res.status(400).json({ error: 'Not enough points' });
      await supabase.from('users').update({ score: req.user.score - hint.cost }).eq('id', req.user.id);
    }

    await supabase.from('hint_unlocks').insert({ id: uuidv4(), user_id: req.user.id, hint_id: hint.id, cost: hint.cost, created_at: new Date().toISOString() });
    res.json({ content: hint.content, cost: hint.cost });
  } catch (err) {
    res.status(500).json({ error: 'Failed to unlock hint' });
  }
});

// ==================== SCOREBOARD ====================
app.get('/scoreboard', async (req, res) => {
  try {
    if (!ctfConfig.scoreboard_visible) return res.json({ scoreboard: [], frozen: true, message: 'Scoreboard is hidden' });

    const cached = cache.get('scoreboard');
    if (cached) return res.json(cached);

    const { data: users } = await supabase.from('users').select('id, username, score, affiliation, country, bracket_id, team_id, teams:team_id(name)').eq('hidden', false).eq('banned', false).neq('role', 'admin').order('score', { ascending: false }).limit(100);

    const { data: solves } = await supabase.from('solves').select('user_id');
    const solveCounts = {};
    solves?.forEach(s => { solveCounts[s.user_id] = (solveCounts[s.user_id] || 0) + 1; });

    const scoreboard = users?.map((u, i) => ({
      rank: i + 1, id: u.id, username: u.username, score: u.score, solves: solveCounts[u.id] || 0,
      team_name: u.teams?.name || null, affiliation: u.affiliation, country: u.country, bracket_id: u.bracket_id
    })) || [];

    const result = { scoreboard, frozen: ctfConfig.scoreboard_frozen, freeze_time: ctfConfig.freeze_time };
    cache.set('scoreboard', result, 30);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load scoreboard' });
  }
});

app.get('/scoreboard/teams', async (req, res) => {
  try {
    const { data: teams } = await supabase.from('teams').select('id, name, score, affiliation, country, bracket_id').eq('hidden', false).eq('banned', false).order('score', { ascending: false }).limit(100);
    const scoreboard = teams?.map((t, i) => ({ rank: i + 1, ...t })) || [];
    res.json({ scoreboard });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load team scoreboard' });
  }
});

app.get('/scoreboard/graph', async (req, res) => {
  try {
    const { data: solves } = await supabase.from('solves').select('user_id, points, created_at, users!inner(username)').order('created_at', { ascending: true });
    const userScores = {};
    solves?.forEach(s => {
      const userId = s.user_id;
      if (!userScores[userId]) userScores[userId] = { username: s.users.username, scores: [], total: 0 };
      userScores[userId].total += s.points;
      userScores[userId].scores.push({ time: s.created_at, score: userScores[userId].total });
    });
    const top10 = Object.entries(userScores).sort((a, b) => b[1].total - a[1].total).slice(0, 10).map(([id, data]) => ({ username: data.username, data: data.scores }));
    res.json({ graph: top10 });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load graph' });
  }
});

// ==================== BRACKETS ====================
app.get('/brackets', async (req, res) => {
  try {
    const { data: brackets } = await supabase.from('brackets').select('*').order('name');
    res.json({ brackets: brackets || [] });
  } catch (err) {
    res.json({ brackets: [] });
  }
});

// ==================== TEAMS ====================
app.get('/teams', async (req, res) => {
  try {
    const { data: teams } = await supabase.from('teams').select('id, name, description, score, affiliation, country, captain_id, created_at').eq('hidden', false).eq('banned', false).order('score', { ascending: false });
    const { data: members } = await supabase.from('users').select('team_id');
    const memberCounts = {};
    members?.forEach(m => { if (m.team_id) memberCounts[m.team_id] = (memberCounts[m.team_id] || 0) + 1; });
    const processed = teams?.map(t => ({ ...t, member_count: memberCounts[t.id] || 0 })) || [];
    res.json({ teams: processed });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load teams' });
  }
});

app.post('/teams', requireAuth, async (req, res) => {
  try {
    const { name, description, password, affiliation, country } = req.body;
    if (!name || name.length < 2) return res.status(400).json({ error: 'Team name must be at least 2 characters' });
    if (req.user.team_id) return res.status(400).json({ error: 'You are already in a team' });

    const { data: existing } = await supabase.from('teams').select('id').eq('name', name).single();
    if (existing) return res.status(400).json({ error: 'Team name already taken' });

    const teamId = uuidv4();
    const inviteCode = uuidv4().substring(0, 8);
    const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

    const { data: team, error } = await supabase.from('teams').insert({
      id: teamId, name, description: description || '', password: hashedPassword, invite_code: inviteCode,
      captain_id: req.user.id, affiliation, country, score: req.user.score || 0, hidden: false, banned: false, created_at: new Date().toISOString()
    }).select().single();

    if (error) throw error;
    await supabase.from('users').update({ team_id: teamId }).eq('id', req.user.id);
    await checkAndGrantAchievements(req.user.id, { type: 'team_captain' });
    res.json({ team: { ...team, password: undefined, invite_code: inviteCode } });
  } catch (err) {
    console.error('Create team error:', err);
    res.status(500).json({ error: 'Failed to create team' });
  }
});

app.get('/teams/:id', async (req, res) => {
  try {
    const { data: team } = await supabase.from('teams').select('*').eq('id', req.params.id).single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    const { data: members } = await supabase.from('users').select('id, username, score, affiliation, country').eq('team_id', team.id);
    const { data: solves } = await supabase.from('solves').select('*, challenges!inner(title, category, points), users!inner(username)').eq('team_id', team.id).order('created_at', { ascending: false }).limit(20);

    res.json({
      team: { ...team, password: undefined }, members: members || [],
      solves: solves?.map(s => ({ challenge: s.challenges?.title, category: s.challenges?.category, points: s.points, solver: s.users?.username, time: s.created_at })) || []
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load team' });
  }
});

app.post('/teams/:id/join', requireAuth, async (req, res) => {
  try {
    const { password } = req.body;
    if (req.user.team_id) return res.status(400).json({ error: 'Leave current team first' });

    const { data: team } = await supabase.from('teams').select('*').eq('id', req.params.id).single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    if (team.password) {
      const valid = await bcrypt.compare(password || '', team.password);
      if (!valid) return res.status(403).json({ error: 'Incorrect team password' });
    }

    const { count } = await supabase.from('users').select('id', { count: 'exact' }).eq('team_id', team.id);
    if (ctfConfig.team_size_limit && count >= ctfConfig.team_size_limit) return res.status(400).json({ error: 'Team is full' });

    await supabase.from('users').update({ team_id: team.id }).eq('id', req.user.id);
    await supabase.from('teams').update({ score: (team.score || 0) + (req.user.score || 0) }).eq('id', team.id);
    await checkAndGrantAchievements(req.user.id, { type: 'team_player' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to join team' });
  }
});

app.post('/teams/:id/leave', requireAuth, async (req, res) => {
  try {
    if (req.user.team_id !== req.params.id) return res.status(400).json({ error: 'Not in this team' });
    const { data: team } = await supabase.from('teams').select('*').eq('id', req.params.id).single();

    if (team.captain_id === req.user.id) {
      const { data: members } = await supabase.from('users').select('id').eq('team_id', team.id).neq('id', req.user.id).limit(1);
      if (members?.length) await supabase.from('teams').update({ captain_id: members[0].id }).eq('id', team.id);
      else await supabase.from('teams').delete().eq('id', team.id);
    }

    await supabase.from('users').update({ team_id: null }).eq('id', req.user.id);
    await supabase.from('teams').update({ score: Math.max(0, (team.score || 0) - (req.user.score || 0)) }).eq('id', team.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to leave team' });
  }
});

// ==================== ACHIEVEMENTS ====================
app.get('/achievements', requireAuth, async (req, res) => {
  try {
    const { data: userAchievements } = await supabase.from('achievements').select('*').eq('user_id', req.user.id);
    const unlockedIds = new Set(userAchievements?.map(a => a.achievement_id) || []);
    const achievements = achievementDefinitions.map(a => ({
      ...a, unlocked: unlockedIds.has(a.id), unlocked_at: userAchievements?.find(ua => ua.achievement_id === a.id)?.created_at
    }));
    res.json({ achievements });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load achievements' });
  }
});

async function checkAndGrantAchievements(userId, context) {
  try {
    const { data: existing } = await supabase.from('achievements').select('achievement_id').eq('user_id', userId);
    const hasAchievement = new Set(existing?.map(a => a.achievement_id) || []);
    const toGrant = [];

    if (context.isFirstBlood && !hasAchievement.has('first_blood')) toGrant.push('first_blood');
    if (context.type === 'team_player' && !hasAchievement.has('team_player')) toGrant.push('team_player');
    if (context.type === 'team_captain' && !hasAchievement.has('team_captain')) toGrant.push('team_captain');

    if (context.type === 'solve') {
      const { count } = await supabase.from('solves').select('id', { count: 'exact' }).eq('user_id', userId);
      if (count >= 10 && !hasAchievement.has('perfectionist')) toGrant.push('perfectionist');
      if (count >= 25 && !hasAchievement.has('master')) toGrant.push('master');
      if (count >= 50 && !hasAchievement.has('legend')) toGrant.push('legend');
    }

    const { data: user } = await supabase.from('users').select('score').eq('id', userId).single();
    if (user?.score >= 1000 && !hasAchievement.has('centurion')) toGrant.push('centurion');
    if (user?.score >= 10000 && !hasAchievement.has('millionaire')) toGrant.push('millionaire');

    const hour = new Date().getHours();
    if (context.type === 'solve') {
      if (hour >= 0 && hour < 5 && !hasAchievement.has('night_owl')) toGrant.push('night_owl');
      if (hour >= 5 && hour < 8 && !hasAchievement.has('early_bird')) toGrant.push('early_bird');
    }

    for (const achievementId of toGrant) {
      const def = achievementDefinitions.find(a => a.id === achievementId);
      await supabase.from('achievements').insert({ id: uuidv4(), user_id: userId, achievement_id: achievementId, points: def?.points || 0, created_at: new Date().toISOString() });
      if (def?.points) await supabase.from('users').update({ score: (user?.score || 0) + def.points }).eq('id', userId);
    }
    return toGrant;
  } catch (err) {
    console.error('Achievement error:', err);
    return [];
  }
}

// ==================== WRITEUPS ====================
app.get('/writeups', async (req, res) => {
  try {
    const { data: writeups } = await supabase.from('writeups').select('id, title, content, likes, created_at, users!inner(username), challenges!inner(id, title, category)').eq('approved', true).order('created_at', { ascending: false }).limit(50);
    res.json({
      writeups: writeups?.map(w => ({
        id: w.id, title: w.title, content_preview: w.content?.substring(0, 200) + '...', likes: w.likes || 0,
        author: w.users?.username, challenge: w.challenges?.title, category: w.challenges?.category, created_at: w.created_at
      })) || []
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load writeups' });
  }
});

app.post('/writeups', requireAuth, async (req, res) => {
  try {
    const { title, content, challenge_id } = req.body;
    if (!title || !content || !challenge_id) return res.status(400).json({ error: 'Title, content and challenge required' });

    const { data: solve } = await supabase.from('solves').select('id').eq('user_id', req.user.id).eq('challenge_id', challenge_id).single();
    if (!solve) return res.status(403).json({ error: 'Must solve challenge before submitting writeup' });

    const { data: writeup, error } = await supabase.from('writeups').insert({
      id: uuidv4(), user_id: req.user.id, challenge_id, title, content, likes: 0, approved: true, created_at: new Date().toISOString()
    }).select().single();

    if (error) throw error;
    await checkAndGrantAchievements(req.user.id, { type: 'writeup' });
    res.json({ writeup });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit writeup' });
  }
});

app.get('/writeups/:id', async (req, res) => {
  try {
    const { data: writeup } = await supabase.from('writeups').select('*, users!inner(username), challenges!inner(id, title, category, points)').eq('id', req.params.id).single();
    if (!writeup) return res.status(404).json({ error: 'Writeup not found' });
    res.json({ writeup: { ...writeup, content_html: renderMarkdown(writeup.content), author: writeup.users?.username, challenge: writeup.challenges } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load writeup' });
  }
});

app.post('/writeups/:id/like', requireAuth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('writeup_likes').select('id').eq('user_id', req.user.id).eq('writeup_id', req.params.id).single();
    if (existing) {
      await supabase.from('writeup_likes').delete().eq('id', existing.id);
      const { data: w } = await supabase.from('writeups').select('likes').eq('id', req.params.id).single();
      await supabase.from('writeups').update({ likes: Math.max(0, (w?.likes || 1) - 1) }).eq('id', req.params.id);
      return res.json({ liked: false });
    }
    await supabase.from('writeup_likes').insert({ id: uuidv4(), user_id: req.user.id, writeup_id: req.params.id, created_at: new Date().toISOString() });
    const { data: writeup } = await supabase.from('writeups').select('likes').eq('id', req.params.id).single();
    await supabase.from('writeups').update({ likes: (writeup?.likes || 0) + 1 }).eq('id', req.params.id);
    res.json({ liked: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to like writeup' });
  }
});

// ==================== ANNOUNCEMENTS ====================
app.get('/announcements', async (req, res) => {
  try {
    const { data: announcements } = await supabase.from('announcements').select('id, title, content, created_at').order('created_at', { ascending: false }).limit(20);
    res.json({ announcements: announcements?.map(a => ({ ...a, content_html: renderMarkdown(a.content) })) || [] });
  } catch (err) {
    res.json({ announcements: [] });
  }
});

// ==================== PAGES ====================
app.get('/pages', async (req, res) => {
  try {
    const { data: pages } = await supabase.from('pages').select('id, title, slug, created_at').eq('published', true).order('title');
    res.json({ pages: pages || [] });
  } catch (err) {
    res.json({ pages: [] });
  }
});

app.get('/pages/:slug', async (req, res) => {
  try {
    const { data: page } = await supabase.from('pages').select('*').eq('slug', req.params.slug).eq('published', true).single();
    if (!page) return res.status(404).json({ error: 'Page not found' });
    res.json({ page: { ...page, content_html: renderMarkdown(page.content) } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load page' });
  }
});

// ==================== STATS ====================
app.get('/stats', async (req, res) => {
  try {
    const [users, teams, challenges, solves] = await Promise.all([
      supabase.from('users').select('id', { count: 'exact' }),
      supabase.from('teams').select('id', { count: 'exact' }),
      supabase.from('challenges').select('id', { count: 'exact' }).eq('state', 'visible'),
      supabase.from('solves').select('id', { count: 'exact' })
    ]);
    res.json({ users: users.count || 0, teams: teams.count || 0, challenges: challenges.count || 0, solves: solves.count || 0 });
  } catch (err) {
    res.json({ users: 0, teams: 0, challenges: 0, solves: 0 });
  }
});

// ==================== USER PROFILES ====================
app.get('/users/:id', async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('id, username, score, affiliation, country, website, bio, team_id, bracket_id, created_at, teams:team_id(name)').eq('id', req.params.id).eq('hidden', false).single();
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { data: solves } = await supabase.from('solves').select('challenge_id, points, first_blood, created_at, challenges!inner(title, category)').eq('user_id', user.id).order('created_at', { ascending: false });
    const { data: achievements } = await supabase.from('achievements').select('achievement_id, created_at').eq('user_id', user.id);

    res.json({
      user: {
        ...user, team_name: user.teams?.name,
        solves: solves?.map(s => ({ challenge: s.challenges?.title, category: s.challenges?.category, points: s.points, first_blood: s.first_blood, time: s.created_at })) || [],
        achievements: achievements?.map(a => ({ ...achievementDefinitions.find(d => d.id === a.achievement_id), unlocked_at: a.created_at })) || []
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load user' });
  }
});

// ==================== ADMIN ROUTES ====================
app.get('/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [users, teams, challenges, solves, submissions] = await Promise.all([
      supabase.from('users').select('id, created_at', { count: 'exact' }),
      supabase.from('teams').select('id', { count: 'exact' }),
      supabase.from('challenges').select('id, state', { count: 'exact' }),
      supabase.from('solves').select('id', { count: 'exact' }),
      supabase.from('submissions').select('id, correct', { count: 'exact' })
    ]);
    const { data: recentSolves } = await supabase.from('solves').select('*, users!inner(username), challenges!inner(title)').order('created_at', { ascending: false }).limit(10);
    res.json({
      users: users.count || 0, teams: teams.count || 0, challenges: challenges.count || 0, solves: solves.count || 0, submissions: submissions.count || 0,
      recent_activity: recentSolves?.map(s => ({ user: s.users?.username, challenge: s.challenges?.title, time: s.created_at })) || []
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load admin stats' });
  }
});

app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const { data: users } = await supabase.from('users').select('id, username, email, score, role, banned, hidden, verified, created_at, last_login').order('created_at', { ascending: false });
    res.json({ users: users || [] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load users' });
  }
});

app.put('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const { role, banned, hidden, verified, score } = req.body;
    await supabase.from('users').update({ role, banned, hidden, verified, score, updated_at: new Date().toISOString() }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    await supabase.from('users').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/admin/challenges', requireAdmin, async (req, res) => {
  try {
    const { data: challenges } = await supabase.from('challenges').select('*').order('category').order('points');
    res.json({ challenges: challenges || [] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load challenges' });
  }
});

app.post('/admin/challenges', requireAdmin, async (req, res) => {
  try {
    const { title, description, category, flag, points, difficulty, files, url, max_attempts, type, state, scoring_type, initial_points, minimum_points, decay, flag_type, case_sensitive, prerequisites, tags } = req.body;
    if (!title || !flag || !category) return res.status(400).json({ error: 'Title, flag and category required' });

    const { data: challenge, error } = await supabase.from('challenges').insert({
      id: uuidv4(), title, description: description || '', category, flag, points: points || 100, difficulty: difficulty || 'medium',
      files, url, max_attempts: max_attempts || null, type: type || 'standard', state: state || 'visible',
      scoring_type: scoring_type || 'static', initial_points: initial_points || points, minimum_points: minimum_points || 50,
      decay: decay || 15, flag_type: flag_type || 'static', case_sensitive: case_sensitive !== false,
      prerequisites: prerequisites || [], tags: tags || [], created_at: new Date().toISOString()
    }).select().single();

    if (error) throw error;
    cache.del('challenges');
    res.json({ challenge });
  } catch (err) {
    console.error('Create challenge error:', err);
    res.status(500).json({ error: 'Failed to create challenge' });
  }
});

app.put('/admin/challenges/:id', requireAdmin, async (req, res) => {
  try {
    const updates = { ...req.body, updated_at: new Date().toISOString() };
    delete updates.id;
    await supabase.from('challenges').update(updates).eq('id', req.params.id);
    cache.del('challenges');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update challenge' });
  }
});

app.delete('/admin/challenges/:id', requireAdmin, async (req, res) => {
  try {
    await supabase.from('challenges').delete().eq('id', req.params.id);
    cache.del('challenges');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete challenge' });
  }
});

app.post('/admin/hints', requireAdmin, async (req, res) => {
  try {
    const { challenge_id, content, cost } = req.body;
    const { data: hint, error } = await supabase.from('hints').insert({ id: uuidv4(), challenge_id, content, cost: cost || 0, created_at: new Date().toISOString() }).select().single();
    if (error) throw error;
    res.json({ hint });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create hint' });
  }
});

app.post('/admin/announcements', requireAdmin, async (req, res) => {
  try {
    const { title, content } = req.body;
    const { data: announcement, error } = await supabase.from('announcements').insert({ id: uuidv4(), title, content, created_at: new Date().toISOString() }).select().single();
    if (error) throw error;
    broadcast('announcements', { type: 'new_announcement', title, content: content.substring(0, 200) });
    res.json({ announcement });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create announcement' });
  }
});

app.post('/admin/pages', requireAdmin, async (req, res) => {
  try {
    const { title, slug, content, published } = req.body;
    const { data: page, error } = await supabase.from('pages').insert({
      id: uuidv4(), title, slug: slug || title.toLowerCase().replace(/\s+/g, '-'), content, published: published !== false, created_at: new Date().toISOString()
    }).select().single();
    if (error) throw error;
    res.json({ page });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create page' });
  }
});

app.post('/admin/brackets', requireAdmin, async (req, res) => {
  try {
    const { name, description } = req.body;
    const { data: bracket, error } = await supabase.from('brackets').insert({ id: uuidv4(), name, description, created_at: new Date().toISOString() }).select().single();
    if (error) throw error;
    res.json({ bracket });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create bracket' });
  }
});

app.put('/admin/config', requireAdmin, async (req, res) => {
  try {
    const allowed = ['name', 'description', 'start_time', 'end_time', 'freeze_time', 'registration_open', 'ctf_started', 'ctf_ended', 'scoreboard_frozen', 'scoreboard_visible', 'team_mode', 'team_size_limit', 'user_mode', 'score_visibility', 'paused', 'theme'];
    Object.keys(req.body).forEach(key => { if (allowed.includes(key)) ctfConfig[key] = req.body[key]; });
    res.json({ config: ctfConfig });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update config' });
  }
});

app.get('/admin/config', requireAdmin, async (req, res) => {
  res.json({ config: ctfConfig });
});

app.get('/admin/submissions', requireAdmin, async (req, res) => {
  try {
    const { data: submissions } = await supabase.from('submissions').select('id, flag, correct, created_at, users!inner(username), challenges!inner(title)').order('created_at', { ascending: false }).limit(100);
    res.json({ submissions: submissions || [] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load submissions' });
  }
});

app.get('/admin/export', requireAdmin, async (req, res) => {
  try {
    const [challenges, users, teams, solves] = await Promise.all([
      supabase.from('challenges').select('*'),
      supabase.from('users').select('id, username, email, score, role, team_id, created_at'),
      supabase.from('teams').select('*'),
      supabase.from('solves').select('*')
    ]);
    res.json({ exported_at: new Date().toISOString(), challenges: challenges.data || [], users: users.data || [], teams: teams.data || [], solves: solves.data || [] });
  } catch (err) {
    res.status(500).json({ error: 'Export failed' });
  }
});

// ==================== ERROR HANDLER ====================
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ==================== CATCH-ALL ROUTE ====================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== START SERVER ====================
server.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║                    CTF WAR API v4.0.0                     ║
╠═══════════════════════════════════════════════════════════╣
║  🚀 Server: http://localhost:${PORT}                        ║
║  📡 WebSocket: /ws                                        ║
║  🔧 Supabase: ${SUPABASE_KEY ? 'Connected' : 'Not configured'}                          ║
║  🏆 Platform: ${PLATFORM_NAME}                               ║
╚═══════════════════════════════════════════════════════════╝
Features: Dynamic Scoring, Brackets, Achievements, Teams,
          Hints, Writeups, Pages, Admin Panel, WebSocket
  `);
});
