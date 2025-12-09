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

// ==================== WEBSOCKET ====================
const wss = new WebSocket.Server({ server, path: '/ws' });
const wsClients = new Map();

wss.on('connection', (ws, req) => {
  const clientId = uuidv4();
  wsClients.set(clientId, { ws, subscribedTo: new Set() });

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'subscribe') {
        wsClients.get(clientId).subscribedTo.add(data.channel);
      }
      if (data.type === 'unsubscribe') {
        wsClients.get(clientId).subscribedTo.delete(data.channel);
      }
    } catch (e) {}
  });

  ws.on('close', () => wsClients.delete(clientId));
  ws.send(JSON.stringify({ type: 'connected', clientId }));
});

const broadcast = (channel, data) => {
  wsClients.forEach(client => {
    if (client.subscribedTo.has(channel) && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify({ channel, ...data }));
    }
  });
};

const broadcastAll = (data) => {
  wsClients.forEach(client => {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify(data));
    }
  });
};

// ==================== MIDDLEWARE ====================
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('combined'));

// Rate limiters
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts, try again later' } });
const flagLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, message: { error: 'Too many flag submissions, slow down' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 200 });

app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
app.use('/challenges/*/submit', flagLimiter);
app.use(apiLimiter);

// Supabase client
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ==================== HELPER FUNCTIONS ====================
const createToken = (user, expiresIn = '7d') => jwt.sign(user, JWT_SECRET, { expiresIn });
const verifyToken = (token) => { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } };

const getUser = (req) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return null;
  return verifyToken(auth.slice(7));
};

const requireAuth = (req, res, next) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required' });
  req.user = user;
  next();
};

const requireAdmin = (req, res, next) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required' });
  if (user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  req.user = user;
  next();
};

const requireRole = (...roles) => (req, res, next) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required' });
  if (!roles.includes(user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
  req.user = user;
  next();
};

// Sanitize markdown content
const sanitizeContent = (content) => sanitizeHtml(marked(content), {
  allowedTags: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre', 'strong', 'em', 'a', 'img', 'blockquote', 'table', 'thead', 'tbody', 'tr', 'th', 'td'],
  allowedAttributes: { a: ['href', 'target'], img: ['src', 'alt'], code: ['class'] }
});

// Activity logging
const logActivity = async (userId, action, entityType, entityId, details = {}, req = null) => {
  try {
    await supabase.from('activity_log').insert({
      user_id: userId, action, entity_type: entityType, entity_id: entityId, details,
      ip_address: req?.ip || req?.headers?.['x-forwarded-for'], user_agent: req?.headers?.['user-agent']
    });
  } catch (e) { console.error('Activity log error:', e); }
};

// ==================== SCORING ALGORITHMS ====================
const scoringAlgorithms = {
  static: (initial) => initial,

  dynamic: (initial, min, decay, solves) => {
    if (decay <= 0) return initial;
    const points = Math.ceil(((min - initial) / (decay * decay)) * (solves * solves) + initial);
    return Math.max(min, Math.min(initial, points));
  },

  logarithmic: (initial, min, solves) => {
    if (solves <= 1) return initial;
    const decay = (initial - min) / Math.log2(100);
    return Math.max(min, Math.round(initial - decay * Math.log2(solves)));
  },

  linear: (initial, min, decay, solves) => {
    return Math.max(min, initial - (decay * solves));
  },

  exponential: (initial, min, decay, solves) => {
    return Math.max(min, Math.round(initial * Math.pow(decay / 100, solves)));
  }
};

const calculatePoints = (challenge) => {
  const { points, min_points, decay, scoring_type, solve_count } = challenge;
  const algorithm = scoringAlgorithms[scoring_type] || scoringAlgorithms.static;
  return algorithm(points, min_points || 100, decay || 50, solve_count || 0);
};

// ==================== ACHIEVEMENT SYSTEM ====================
const ACHIEVEMENTS = {
  first_solve: { name: 'First Steps', description: 'Solve your first challenge', icon: 'trophy', value: 10 },
  first_blood: { name: 'First Blood', description: 'Be the first to solve a challenge', icon: 'droplet', value: 50 },
  solve_10: { name: 'Hacker', description: 'Solve 10 challenges', icon: 'terminal', value: 25 },
  solve_25: { name: 'Elite Hacker', description: 'Solve 25 challenges', icon: 'shield', value: 50 },
  solve_50: { name: 'Master Hacker', description: 'Solve 50 challenges', icon: 'crown', value: 100 },
  solve_100: { name: 'Legend', description: 'Solve 100 challenges', icon: 'star', value: 200 },
  score_1000: { name: 'Rising Star', description: 'Reach 1000 points', icon: 'zap', value: 25 },
  score_5000: { name: 'Pro Player', description: 'Reach 5000 points', icon: 'flame', value: 75 },
  score_10000: { name: 'Grandmaster', description: 'Reach 10000 points', icon: 'gem', value: 150 },
  web_master: { name: 'Web Warrior', description: 'Solve 10 Web challenges', icon: 'globe', value: 30 },
  crypto_master: { name: 'Crypto King', description: 'Solve 10 Crypto challenges', icon: 'lock', value: 30 },
  pwn_master: { name: 'Pwn Lord', description: 'Solve 10 Pwn challenges', icon: 'skull', value: 30 },
  reverse_master: { name: 'Reverse Engineer', description: 'Solve 10 Reverse challenges', icon: 'cpu', value: 30 },
  forensics_master: { name: 'Digital Detective', description: 'Solve 10 Forensics challenges', icon: 'search', value: 30 },
  misc_master: { name: 'Jack of All Trades', description: 'Solve 10 Misc challenges', icon: 'box', value: 30 },
  all_categories: { name: 'Complete Package', description: 'Solve at least one challenge in every category', icon: 'award', value: 100 },
  speed_demon: { name: 'Speed Demon', description: 'Solve a challenge within 5 minutes of release', icon: 'lightning', value: 40 },
  streak_3: { name: 'On Fire', description: 'Solve 3 challenges in a row', icon: 'fire', value: 20 },
  streak_7: { name: 'Unstoppable', description: 'Solve 7 challenges in a day', icon: 'rocket', value: 50 },
  team_player: { name: 'Team Player', description: 'Join a team', icon: 'users', value: 10 },
  team_leader: { name: 'Team Captain', description: 'Create a team', icon: 'flag', value: 15 },
  writeup_author: { name: 'Knowledge Sharer', description: 'Publish an approved writeup', icon: 'book', value: 25 },
  helpful: { name: 'Helpful', description: 'Get 10 likes on your writeups', icon: 'heart', value: 30 },
  night_owl: { name: 'Night Owl', description: 'Solve a challenge between 2-5 AM', icon: 'moon', value: 15 },
  early_bird: { name: 'Early Bird', description: 'Solve a challenge between 5-7 AM', icon: 'sun', value: 15 },
  perfectionist: { name: 'Perfectionist', description: 'Solve a challenge on first attempt', icon: 'target', value: 20 },
  persistent: { name: 'Never Give Up', description: 'Solve a challenge after 20+ attempts', icon: 'repeat', value: 25 }
};

const checkAndGrantAchievements = async (userId) => {
  const granted = [];

  try {
    // Get user stats
    const { data: solves } = await supabase.from('solves').select('challenge_id, is_first_blood, solved_at, challenges(category)').eq('user_id', userId);
    const { data: existing } = await supabase.from('user_achievements').select('achievement_name').eq('user_id', userId);
    const existingSet = new Set((existing || []).map(a => a.achievement_name));

    const { data: submissions } = await supabase.from('submissions').select('challenge_id, is_correct').eq('user_id', userId);
    const { data: user } = await supabase.from('users').select('team_id, created_at').eq('id', userId).single();
    const { data: writeups } = await supabase.from('writeups').select('id, like_count').eq('user_id', userId).eq('is_approved', true);

    const solveCount = solves?.length || 0;
    const totalScore = (solves || []).reduce((sum, s) => sum + 100, 0); // Simplified
    const firstBloods = (solves || []).filter(s => s.is_first_blood).length;
    const categories = {};
    (solves || []).forEach(s => {
      const cat = s.challenges?.category;
      if (cat) categories[cat] = (categories[cat] || 0) + 1;
    });

    const toGrant = [];

    // Check solve count achievements
    if (solveCount >= 1 && !existingSet.has('first_solve')) toGrant.push('first_solve');
    if (solveCount >= 10 && !existingSet.has('solve_10')) toGrant.push('solve_10');
    if (solveCount >= 25 && !existingSet.has('solve_25')) toGrant.push('solve_25');
    if (solveCount >= 50 && !existingSet.has('solve_50')) toGrant.push('solve_50');
    if (solveCount >= 100 && !existingSet.has('solve_100')) toGrant.push('solve_100');

    // First blood
    if (firstBloods >= 1 && !existingSet.has('first_blood')) toGrant.push('first_blood');

    // Category masters
    if ((categories['Web'] || 0) >= 10 && !existingSet.has('web_master')) toGrant.push('web_master');
    if ((categories['Crypto'] || 0) >= 10 && !existingSet.has('crypto_master')) toGrant.push('crypto_master');
    if ((categories['Pwn'] || 0) >= 10 && !existingSet.has('pwn_master')) toGrant.push('pwn_master');
    if ((categories['Reverse'] || 0) >= 10 && !existingSet.has('reverse_master')) toGrant.push('reverse_master');
    if ((categories['Forensics'] || 0) >= 10 && !existingSet.has('forensics_master')) toGrant.push('forensics_master');
    if ((categories['Misc'] || 0) >= 10 && !existingSet.has('misc_master')) toGrant.push('misc_master');

    // All categories
    const uniqueCategories = Object.keys(categories).length;
    if (uniqueCategories >= 6 && !existingSet.has('all_categories')) toGrant.push('all_categories');

    // Team achievements
    if (user?.team_id && !existingSet.has('team_player')) toGrant.push('team_player');

    // Writeup achievements
    if ((writeups?.length || 0) >= 1 && !existingSet.has('writeup_author')) toGrant.push('writeup_author');
    const totalLikes = (writeups || []).reduce((sum, w) => sum + (w.like_count || 0), 0);
    if (totalLikes >= 10 && !existingSet.has('helpful')) toGrant.push('helpful');

    // Grant achievements
    for (const achKey of toGrant) {
      const ach = ACHIEVEMENTS[achKey];
      if (ach) {
        await supabase.from('user_achievements').insert({
          user_id: userId, achievement_name: achKey, achievement_description: ach.description
        });
        granted.push({ key: achKey, ...ach });

        // Create notification
        await supabase.from('notifications').insert({
          user_id: userId, title: 'Achievement Unlocked!', message: `You earned "${ach.name}" - ${ach.description}`, type: 'achievement'
        });
      }
    }
  } catch (e) { console.error('Achievement check error:', e); }

  return granted;
};

// ==================== ROUTES ====================

// Health check
app.get('/', (req, res) => res.json({
  status: 'ok', platform: PLATFORM_NAME, version: '3.0.0',
  features: ['realtime', 'achievements', 'dynamic_scoring', 'teams', 'writeups', 'contests', 'rate_limiting']
}));
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// ==================== AUTH ====================
app.post('/auth/register', async (req, res) => {
  try {
    const { email, username, password, affiliation, country, bracket } = req.body;
    if (!email || !username || !password) return res.status(400).json({ error: 'Missing required fields' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (username.length < 3 || username.length > 32) return res.status(400).json({ error: 'Username must be 3-32 characters' });
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) return res.status(400).json({ error: 'Username can only contain letters, numbers, underscore, hyphen' });

    const { data: existing } = await supabase.from('users').select('id').or(`email.eq.${email},username.eq.${username}`).limit(1);
    if (existing?.length > 0) return res.status(400).json({ error: 'Email or username already exists' });

    const password_hash = await bcrypt.hash(password, 12);
    const { data: user, error } = await supabase.from('users').insert({
      email, username, password_hash, role: 'user', affiliation, country, bracket, is_verified: true
    }).select().single();
    if (error) throw error;

    await logActivity(user.id, 'register', 'user', user.id, { username }, req);

    const token = createToken({ id: user.id, email: user.email, username: user.username, role: user.role });
    res.json({ user: { id: user.id, email: user.email, username: user.username, role: user.role }, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.is_banned) return res.status(403).json({ error: 'Account is banned', reason: user.ban_reason });
    if (!(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Invalid credentials' });

    await supabase.from('users').update({ last_login: new Date().toISOString(), login_count: (user.login_count || 0) + 1 }).eq('id', user.id);
    await logActivity(user.id, 'login', 'user', user.id, {}, req);

    const token = createToken({ id: user.id, email: user.email, username: user.username, role: user.role, teamId: user.team_id });

    // Check achievements on login
    const newAchievements = await checkAndGrantAchievements(user.id);

    res.json({
      user: { id: user.id, email: user.email, username: user.username, role: user.role, teamId: user.team_id },
      token,
      newAchievements
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const { data } = await supabase.from('users').select('id, email, username, role, team_id, avatar_url, country, affiliation, bio, website, github, twitter, discord, bracket, created_at').eq('id', req.user.id).single();
    const { data: solves } = await supabase.from('solves').select('points_awarded, is_first_blood').eq('user_id', req.user.id);
    const { data: hintUnlocks } = await supabase.from('hint_unlocks').select('hints(penalty)').eq('user_id', req.user.id);
    const { data: achievements } = await supabase.from('user_achievements').select('*').eq('user_id', req.user.id);

    const score = (solves || []).reduce((sum, s) => sum + (s.points_awarded || 0), 0);
    const penalty = (hintUnlocks || []).reduce((sum, h) => sum + (h.hints?.penalty || 0), 0);
    const firstBloods = (solves || []).filter(s => s.is_first_blood).length;

    res.json({
      user: {
        ...data,
        score: score - penalty,
        solveCount: solves?.length || 0,
        firstBloods,
        achievements: achievements || []
      }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/auth/profile', requireAuth, async (req, res) => {
  try {
    const allowed = ['affiliation', 'country', 'bio', 'website', 'github', 'twitter', 'discord', 'avatar_url', 'bracket'];
    const filtered = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)));
    filtered.updated_at = new Date().toISOString();

    const { data } = await supabase.from('users').update(filtered).eq('id', req.user.id).select().single();
    await logActivity(req.user.id, 'profile_update', 'user', req.user.id, filtered, req);
    res.json({ user: data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const { data: user } = await supabase.from('users').select('password_hash').eq('id', req.user.id).single();
    if (!(await bcrypt.compare(currentPassword, user.password_hash))) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const password_hash = await bcrypt.hash(newPassword, 12);
    await supabase.from('users').update({ password_hash }).eq('id', req.user.id);
    await logActivity(req.user.id, 'password_change', 'user', req.user.id, {}, req);

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== CHALLENGES ====================
app.get('/challenges', async (req, res) => {
  try {
    const user = getUser(req);
    const { category, difficulty, solved: solvedFilter, search } = req.query;

    // Try cache first
    const cacheKey = `challenges_${category || 'all'}_${difficulty || 'all'}`;
    let challenges = cache.get(cacheKey);

    if (!challenges) {
      let query = supabase.from('challenges').select(`
        id, title, description, category, difficulty, points, min_points, decay, scoring_type,
        connection_info, solve_count, first_blood_points, first_blood_user_id, first_blood_at,
        max_attempts, state, docker_image, port_mapping, created_at
      `).eq('is_visible', true);

      if (category) query = query.eq('category', category);
      if (difficulty) query = query.eq('difficulty', difficulty);

      const { data } = await query.order('category').order('points', { ascending: true });
      challenges = data || [];
      cache.set(cacheKey, challenges, 30);
    }

    // Search filter
    if (search) {
      const searchLower = search.toLowerCase();
      challenges = challenges.filter(c =>
        c.title.toLowerCase().includes(searchLower) ||
        c.description.toLowerCase().includes(searchLower) ||
        c.category.toLowerCase().includes(searchLower)
      );
    }

    // Get user-specific data
    let solvedIds = [], userAttempts = {};
    if (user?.id) {
      const { data: solves } = await supabase.from('solves').select('challenge_id').eq('user_id', user.id);
      solvedIds = (solves || []).map(s => s.challenge_id);

      const { data: submissions } = await supabase.from('submissions').select('challenge_id').eq('user_id', user.id).eq('is_correct', false);
      for (const sub of submissions || []) userAttempts[sub.challenge_id] = (userAttempts[sub.challenge_id] || 0) + 1;
    }

    // Get hints and files count
    const challengeIds = challenges.map(c => c.id);
    const { data: hints } = await supabase.from('hints').select('challenge_id, id').in('challenge_id', challengeIds);
    const { data: files } = await supabase.from('challenge_files').select('challenge_id, id').in('challenge_id', challengeIds);
    const { data: tags } = await supabase.from('challenge_tag_map').select('challenge_id, challenge_tags(name, color)').in('challenge_id', challengeIds);

    const hintCount = {}, fileCount = {}, tagMap = {};
    for (const h of hints || []) hintCount[h.challenge_id] = (hintCount[h.challenge_id] || 0) + 1;
    for (const f of files || []) fileCount[f.challenge_id] = (fileCount[f.challenge_id] || 0) + 1;
    for (const t of tags || []) {
      if (!tagMap[t.challenge_id]) tagMap[t.challenge_id] = [];
      if (t.challenge_tags) tagMap[t.challenge_id].push(t.challenge_tags);
    }

    let result = challenges.map(c => ({
      ...c,
      points: calculatePoints(c),
      solved: solvedIds.includes(c.id),
      solveCount: c.solve_count || 0,
      hintCount: hintCount[c.id] || 0,
      fileCount: fileCount[c.id] || 0,
      tags: tagMap[c.id] || [],
      attempts: userAttempts[c.id] || 0
    }));

    // Filter by solved status
    if (solvedFilter === 'true') result = result.filter(c => c.solved);
    if (solvedFilter === 'false') result = result.filter(c => !c.solved);

    res.json({ challenges: result, total: result.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/challenges/categories', async (req, res) => {
  try {
    let categories = cache.get('categories');
    if (!categories) {
      const { data } = await supabase.from('challenges').select('category').eq('is_visible', true);
      const catCount = {};
      for (const c of data || []) catCount[c.category] = (catCount[c.category] || 0) + 1;
      categories = Object.entries(catCount).map(([name, count]) => ({ name, count })).sort((a, b) => a.name.localeCompare(b.name));
      cache.set('categories', categories, 60);
    }
    res.json({ categories });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/challenges/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const user = getUser(req);

    const { data: challenge } = await supabase.from('challenges').select('*').eq('id', id).eq('is_visible', true).single();
    if (!challenge) return res.status(404).json({ error: 'Challenge not found' });

    // Check prerequisites
    const { data: prereqs } = await supabase.from('challenge_prerequisites').select('prerequisite_id, challenges!challenge_prerequisites_prerequisite_id_fkey(title)').eq('challenge_id', id);
    let locked = false, missingPrereqs = [];

    if (prereqs?.length > 0 && user?.id) {
      const { data: userSolves } = await supabase.from('solves').select('challenge_id').eq('user_id', user.id);
      const solvedIds = new Set((userSolves || []).map(s => s.challenge_id));
      for (const p of prereqs) {
        if (!solvedIds.has(p.prerequisite_id)) {
          locked = true;
          missingPrereqs.push({ id: p.prerequisite_id, title: p.challenges?.title });
        }
      }
    }

    if (locked) {
      return res.json({
        id: challenge.id, title: challenge.title, category: challenge.category, difficulty: challenge.difficulty,
        points: calculatePoints(challenge), locked: true, missingPrereqs,
        message: 'Solve required challenges first'
      });
    }

    const { data: hints } = await supabase.from('hints').select('id, penalty, order_index, content').eq('challenge_id', id).eq('is_visible', true).order('order_index');
    const { data: files } = await supabase.from('challenge_files').select('id, filename, file_size, file_path').eq('challenge_id', id);
    const { data: tags } = await supabase.from('challenge_tag_map').select('challenge_tags(name, color)').eq('challenge_id', id);

    // Get solvers
    const { data: solvers } = await supabase.from('solves').select('user_id, solved_at, is_first_blood, users(username, avatar_url)').eq('challenge_id', id).order('solved_at').limit(20);

    let unlockedHints = [], solved = false, userAttempts = 0;
    if (user?.id) {
      const { data: unlocks } = await supabase.from('hint_unlocks').select('hint_id').eq('user_id', user.id);
      unlockedHints = (unlocks || []).map(u => u.hint_id);
      const { data: solve } = await supabase.from('solves').select('id').eq('user_id', user.id).eq('challenge_id', id).single();
      solved = !!solve;
      const { count } = await supabase.from('submissions').select('*', { count: 'exact', head: true }).eq('user_id', user.id).eq('challenge_id', id);
      userAttempts = count || 0;
    }

    let firstBlood = null;
    if (challenge.first_blood_user_id) {
      const { data: fbUser } = await supabase.from('users').select('username, avatar_url').eq('id', challenge.first_blood_user_id).single();
      firstBlood = { username: fbUser?.username, avatar: fbUser?.avatar_url, at: challenge.first_blood_at };
    }

    const points = calculatePoints(challenge);
    const hintsWithContent = (hints || []).map(h => ({
      id: h.id, penalty: h.penalty, order: h.order_index,
      unlocked: unlockedHints.includes(h.id) || solved,
      content: (unlockedHints.includes(h.id) || solved) ? h.content : null
    }));

    res.json({
      id: challenge.id, title: challenge.title, description: sanitizeContent(challenge.description),
      category: challenge.category, difficulty: challenge.difficulty, points, originalPoints: challenge.points,
      scoringType: challenge.scoring_type, connectionInfo: challenge.connection_info,
      maxAttempts: challenge.max_attempts, solveCount: challenge.solve_count || 0,
      firstBlood, firstBloodPoints: challenge.first_blood_points,
      hints: hintsWithContent, files, tags: (tags || []).map(t => t.challenge_tags),
      solved, locked: false, userAttempts,
      solvers: (solvers || []).map(s => ({
        username: s.users?.username, avatar: s.users?.avatar_url,
        solvedAt: s.solved_at, firstBlood: s.is_first_blood
      })),
      dockerEnabled: !!challenge.docker_image
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/challenges/:id/submit', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { flag } = req.body;
    if (!flag) return res.status(400).json({ error: 'Flag is required' });

    const { data: challenge } = await supabase.from('challenges').select('*').eq('id', id).eq('is_visible', true).single();
    if (!challenge) return res.status(404).json({ error: 'Challenge not found' });

    // Check prerequisites
    const { data: prereqs } = await supabase.from('challenge_prerequisites').select('prerequisite_id').eq('challenge_id', id);
    if (prereqs?.length > 0) {
      const { data: userSolves } = await supabase.from('solves').select('challenge_id').eq('user_id', req.user.id);
      const solvedIds = new Set((userSolves || []).map(s => s.challenge_id));
      for (const p of prereqs) {
        if (!solvedIds.has(p.prerequisite_id)) {
          return res.status(403).json({ error: 'Complete required challenges first' });
        }
      }
    }

    const { data: existingSolve } = await supabase.from('solves').select('id').eq('user_id', req.user.id).eq('challenge_id', id).single();
    if (existingSolve) return res.status(400).json({ error: 'Already solved' });

    if (challenge.max_attempts > 0) {
      const { count } = await supabase.from('submissions').select('*', { count: 'exact', head: true }).eq('user_id', req.user.id).eq('challenge_id', id).eq('is_correct', false);
      if ((count || 0) >= challenge.max_attempts) return res.status(400).json({ error: 'Maximum attempts reached' });
    }

    // Flag validation
    let isCorrect = false;
    const flagType = challenge.flag_type || 'static';
    const submittedFlag = flag.trim();

    if (flagType === 'regex') {
      try { isCorrect = new RegExp(challenge.flag).test(submittedFlag); } catch { isCorrect = false; }
    } else if (flagType === 'case_insensitive') {
      isCorrect = challenge.flag.toLowerCase() === submittedFlag.toLowerCase();
    } else {
      const parseFlag = (f) => {
        const m = f.match(/^([A-Za-z0-9_]+)\{(.+)\}$/);
        return m ? { prefix: m[1], value: m[2] } : { prefix: null, value: f.trim() };
      };
      const submitted = parseFlag(submittedFlag);
      const correct = parseFlag(challenge.flag);

      if (correct.prefix) {
        isCorrect = submitted.prefix !== null &&
          (submitted.prefix === correct.prefix || FLAG_PREFIXES.includes(submitted.prefix)) &&
          submitted.value === correct.value;
      } else {
        isCorrect = challenge.flag === submittedFlag;
      }
    }

    // Calculate points
    const { count: solveCount } = await supabase.from('solves').select('*', { count: 'exact', head: true }).eq('challenge_id', id);
    const isFirstBlood = isCorrect && (solveCount || 0) === 0;
    const basePoints = calculatePoints(challenge);
    let pointsAwarded = isCorrect ? basePoints : 0;
    let firstBloodBonus = 0;

    if (isFirstBlood && challenge.first_blood_points) {
      firstBloodBonus = challenge.first_blood_points;
      pointsAwarded += firstBloodBonus;
    }

    // Record submission
    const { data: submission } = await supabase.from('submissions').insert({
      user_id: req.user.id, challenge_id: id, submitted_flag: submittedFlag, is_correct: isCorrect,
      points_awarded: pointsAwarded, team_id: req.user.teamId || null,
      ip_address: req.ip, user_agent: req.headers['user-agent']
    }).select().single();

    await logActivity(req.user.id, isCorrect ? 'solve' : 'wrong_flag', 'challenge', id, { isCorrect, isFirstBlood }, req);

    if (isCorrect) {
      // Record solve
      await supabase.from('solves').insert({
        user_id: req.user.id, challenge_id: id, submission_id: submission.id,
        points_awarded: pointsAwarded, is_first_blood: isFirstBlood, team_id: req.user.teamId || null,
        ip_address: req.ip, user_agent: req.headers['user-agent']
      });

      // Update challenge stats
      const updates = { solve_count: (challenge.solve_count || 0) + 1 };
      if (isFirstBlood) {
        updates.first_blood_user_id = req.user.id;
        updates.first_blood_at = new Date().toISOString();
      }
      await supabase.from('challenges').update(updates).eq('id', id);

      // Clear cache
      cache.del(`challenges_all_all`);
      cache.del(`challenges_${challenge.category}_all`);

      // Check achievements
      const newAchievements = await checkAndGrantAchievements(req.user.id);

      // Get total score
      const { data: allSolves } = await supabase.from('solves').select('points_awarded').eq('user_id', req.user.id);
      const { data: hintUnlocks } = await supabase.from('hint_unlocks').select('hints(penalty)').eq('user_id', req.user.id);
      const totalPoints = (allSolves || []).reduce((sum, s) => sum + (s.points_awarded || 0), 0);
      const hintPenalty = (hintUnlocks || []).reduce((sum, u) => sum + (u.hints?.penalty || 0), 0);

      // Broadcast solve via WebSocket
      broadcast('scoreboard', {
        type: 'solve',
        userId: req.user.id,
        username: req.user.username,
        challengeId: id,
        challengeTitle: challenge.title,
        points: pointsAwarded,
        isFirstBlood,
        timestamp: new Date().toISOString()
      });

      if (isFirstBlood) {
        broadcastAll({
          type: 'first_blood',
          username: req.user.username,
          challengeTitle: challenge.title,
          timestamp: new Date().toISOString()
        });
      }

      return res.json({
        correct: true, points: pointsAwarded, basePoints, firstBloodBonus, isFirstBlood,
        totalScore: totalPoints - hintPenalty,
        message: isFirstBlood ? '🩸 First Blood! Congratulations!' : '✅ Correct! Challenge solved!',
        newAchievements
      });
    }

    res.json({ correct: false, message: '❌ Incorrect flag. Try again!' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== HINTS ====================
app.post('/hints/:id/unlock', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: hint } = await supabase.from('hints').select('*, challenges(id, is_visible)').eq('id', id).single();
    if (!hint || !hint.challenges?.is_visible) return res.status(404).json({ error: 'Hint not found' });

    const { data: existing } = await supabase.from('hint_unlocks').select('id').eq('user_id', req.user.id).eq('hint_id', id).single();
    if (existing) return res.json({ hint: { id: hint.id, content: hint.content, penalty: hint.penalty }, alreadyUnlocked: true });

    await supabase.from('hint_unlocks').insert({ user_id: req.user.id, hint_id: id, team_id: req.user.teamId || null });
    await supabase.from('hints').update({ unlock_count: (hint.unlock_count || 0) + 1 }).eq('id', id);
    await logActivity(req.user.id, 'hint_unlock', 'hint', id, { penalty: hint.penalty }, req);

    res.json({ hint: { id: hint.id, content: hint.content, penalty: hint.penalty }, unlocked: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== SCOREBOARD ====================
app.get('/scoreboard', async (req, res) => {
  try {
    const { type = 'users', limit = 100, page = 1, bracket } = req.query;
    const limitNum = Math.min(parseInt(limit), 500);
    const offset = (parseInt(page) - 1) * limitNum;

    if (type === 'teams') {
      const { data: solves } = await supabase.from('solves').select('team_id, points_awarded, solved_at').not('team_id', 'is', null).order('solved_at');

      const teamScores = {};
      for (const s of solves || []) {
        if (!teamScores[s.team_id]) teamScores[s.team_id] = { score: 0, solves: 0, lastSolve: s.solved_at, history: [] };
        teamScores[s.team_id].score += s.points_awarded || 0;
        teamScores[s.team_id].solves++;
        if (s.solved_at > teamScores[s.team_id].lastSolve) teamScores[s.team_id].lastSolve = s.solved_at;
        teamScores[s.team_id].history.push({ time: s.solved_at, score: teamScores[s.team_id].score });
      }

      const teamIds = Object.keys(teamScores);
      const { data: teams } = await supabase.from('teams').select('id, name, avatar_url, country, affiliation').in('id', teamIds);
      const teamMap = Object.fromEntries((teams || []).map(t => [t.id, t]));

      const leaderboard = Object.entries(teamScores)
        .map(([id, data]) => ({
          teamId: id, name: teamMap[id]?.name || 'Unknown',
          avatar: teamMap[id]?.avatar_url, country: teamMap[id]?.country,
          affiliation: teamMap[id]?.affiliation, ...data
        }))
        .sort((a, b) => b.score - a.score || new Date(a.lastSolve) - new Date(b.lastSolve))
        .map((entry, i) => ({ rank: i + 1, ...entry }));

      return res.json({
        leaderboard: leaderboard.slice(offset, offset + limitNum),
        total: leaderboard.length, type: 'teams', page: parseInt(page)
      });
    }

    // User leaderboard
    let userQuery = supabase.from('users').select('id, username, avatar_url, country, affiliation, bracket').eq('is_hidden', false);
    if (bracket) userQuery = userQuery.eq('bracket', bracket);
    const { data: users } = await userQuery;

    const userIds = (users || []).map(u => u.id);
    const { data: solves } = await supabase.from('solves').select('user_id, points_awarded, solved_at, is_first_blood').in('user_id', userIds).order('solved_at');
    const { data: hintUnlocks } = await supabase.from('hint_unlocks').select('user_id, hints(penalty)').in('user_id', userIds);

    const userScores = {};
    for (const s of solves || []) {
      if (!userScores[s.user_id]) userScores[s.user_id] = { score: 0, solves: 0, lastSolve: s.solved_at, penalty: 0, firstBloods: 0, history: [] };
      userScores[s.user_id].score += s.points_awarded || 0;
      userScores[s.user_id].solves++;
      if (s.is_first_blood) userScores[s.user_id].firstBloods++;
      if (s.solved_at > userScores[s.user_id].lastSolve) userScores[s.user_id].lastSolve = s.solved_at;
      userScores[s.user_id].history.push({ time: s.solved_at, score: userScores[s.user_id].score });
    }

    for (const h of hintUnlocks || []) {
      if (userScores[h.user_id]) userScores[h.user_id].penalty += h.hints?.penalty || 0;
    }

    const userMap = Object.fromEntries((users || []).map(u => [u.id, u]));

    const leaderboard = Object.entries(userScores)
      .filter(([id]) => userMap[id])
      .map(([id, data]) => ({
        userId: id, username: userMap[id]?.username || 'Unknown',
        avatar: userMap[id]?.avatar_url, country: userMap[id]?.country,
        affiliation: userMap[id]?.affiliation, bracket: userMap[id]?.bracket,
        score: data.score - data.penalty, solves: data.solves,
        firstBloods: data.firstBloods, lastSolve: data.lastSolve, history: data.history
      }))
      .sort((a, b) => b.score - a.score || new Date(a.lastSolve) - new Date(b.lastSolve))
      .map((entry, i) => ({ rank: i + 1, ...entry }));

    res.json({
      leaderboard: leaderboard.slice(offset, offset + limitNum),
      total: leaderboard.length, type: 'users', page: parseInt(page)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/scoreboard/graph', async (req, res) => {
  try {
    const { type = 'users', top = 10 } = req.query;
    const topNum = Math.min(parseInt(top), 20);

    // Get top players/teams
    const { data: solves } = await supabase.from('solves').select('user_id, team_id, points_awarded, solved_at').order('solved_at');

    if (type === 'teams') {
      const teamScores = {};
      for (const s of solves || []) {
        if (!s.team_id) continue;
        if (!teamScores[s.team_id]) teamScores[s.team_id] = { total: 0, history: [] };
        teamScores[s.team_id].total += s.points_awarded || 0;
        teamScores[s.team_id].history.push({ time: s.solved_at, score: teamScores[s.team_id].total });
      }

      const topTeams = Object.entries(teamScores).sort((a, b) => b[1].total - a[1].total).slice(0, topNum);
      const teamIds = topTeams.map(([id]) => id);
      const { data: teams } = await supabase.from('teams').select('id, name').in('id', teamIds);
      const teamMap = Object.fromEntries((teams || []).map(t => [t.id, t.name]));

      const graph = topTeams.map(([id, data]) => ({ id, name: teamMap[id] || 'Unknown', history: data.history }));
      return res.json({ graph, type: 'teams' });
    }

    const userScores = {};
    for (const s of solves || []) {
      if (!userScores[s.user_id]) userScores[s.user_id] = { total: 0, history: [] };
      userScores[s.user_id].total += s.points_awarded || 0;
      userScores[s.user_id].history.push({ time: s.solved_at, score: userScores[s.user_id].total });
    }

    const topUsers = Object.entries(userScores).sort((a, b) => b[1].total - a[1].total).slice(0, topNum);
    const userIds = topUsers.map(([id]) => id);
    const { data: users } = await supabase.from('users').select('id, username').in('id', userIds);
    const userMap = Object.fromEntries((users || []).map(u => [u.id, u.username]));

    const graph = topUsers.map(([id, data]) => ({ id, name: userMap[id] || 'Unknown', history: data.history }));
    res.json({ graph, type: 'users' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== TEAMS ====================
app.get('/teams', async (req, res) => {
  try {
    const { search, page = 1, limit = 20 } = req.query;
    const limitNum = Math.min(parseInt(limit), 100);
    const offset = (parseInt(page) - 1) * limitNum;

    let query = supabase.from('teams').select('id, name, description, avatar_url, country, affiliation, is_public, max_members, created_at', { count: 'exact' }).eq('is_public', true);
    if (search) query = query.ilike('name', `%${search}%`);

    const { data: teams, count } = await query.order('created_at', { ascending: false }).range(offset, offset + limitNum - 1);

    // Get member counts and scores
    const teamIds = (teams || []).map(t => t.id);
    const { data: members } = await supabase.from('team_members').select('team_id').in('team_id', teamIds);
    const { data: solves } = await supabase.from('solves').select('team_id, points_awarded').in('team_id', teamIds);

    const memberCount = {}, teamScore = {};
    for (const m of members || []) memberCount[m.team_id] = (memberCount[m.team_id] || 0) + 1;
    for (const s of solves || []) teamScore[s.team_id] = (teamScore[s.team_id] || 0) + (s.points_awarded || 0);

    const result = (teams || []).map(t => ({
      ...t, memberCount: memberCount[t.id] || 0, score: teamScore[t.id] || 0
    }));

    res.json({ teams: result, total: count, page: parseInt(page) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/teams', requireAuth, async (req, res) => {
  try {
    const { name, description, isPublic = true, password } = req.body;
    if (!name) return res.status(400).json({ error: 'Team name is required' });
    if (name.length < 3 || name.length > 64) return res.status(400).json({ error: 'Team name must be 3-64 characters' });

    const { data: currentUser } = await supabase.from('users').select('team_id').eq('id', req.user.id).single();
    if (currentUser?.team_id) return res.status(400).json({ error: 'You are already in a team' });

    const invite_code = uuidv4();
    const { data: team, error } = await supabase.from('teams').insert({
      name, description, leader_id: req.user.id, is_public: isPublic, invite_code,
      password: password ? await bcrypt.hash(password, 10) : null
    }).select().single();
    if (error) return res.status(400).json({ error: error.message });

    await supabase.from('users').update({ team_id: team.id }).eq('id', req.user.id);
    await supabase.from('team_members').insert({ team_id: team.id, user_id: req.user.id });

    await logActivity(req.user.id, 'team_create', 'team', team.id, { name }, req);
    await checkAndGrantAchievements(req.user.id);

    res.json({ team: { ...team, inviteCode: invite_code } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/teams/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: team } = await supabase.from('teams').select('*').eq('id', id).single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    const { data: members } = await supabase.from('team_members').select('user_id, joined_at, users(id, username, avatar_url, country, role)').eq('team_id', id);
    const { data: solves } = await supabase.from('solves').select('points_awarded, challenge_id, solved_at, is_first_blood, challenges(title, category)').eq('team_id', id).order('solved_at', { ascending: false });
    const { data: achievements } = await supabase.from('team_achievements').select('*').eq('team_id', id);

    const score = (solves || []).reduce((sum, s) => sum + (s.points_awarded || 0), 0);
    const firstBloods = (solves || []).filter(s => s.is_first_blood).length;

    // Get rank
    const { data: allTeamSolves } = await supabase.from('solves').select('team_id, points_awarded').not('team_id', 'is', null);
    const teamScores = {};
    for (const s of allTeamSolves || []) teamScores[s.team_id] = (teamScores[s.team_id] || 0) + (s.points_awarded || 0);
    const sortedTeams = Object.entries(teamScores).sort((a, b) => b[1] - a[1]);
    const rank = sortedTeams.findIndex(([tid]) => tid === id) + 1;

    res.json({
      ...team,
      members: (members || []).map(m => ({ ...m.users, joinedAt: m.joined_at, isLeader: m.user_id === team.leader_id })),
      score, rank: rank || null, solveCount: solves?.length || 0, firstBloods,
      achievements: achievements || [],
      recentSolves: (solves || []).slice(0, 10).map(s => ({
        challengeId: s.challenge_id, title: s.challenges?.title,
        category: s.challenges?.category, points: s.points_awarded,
        firstBlood: s.is_first_blood, solvedAt: s.solved_at
      }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/teams/:id/join', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { inviteCode, password } = req.body;

    const { data: team } = await supabase.from('teams').select('*').eq('id', id).single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    // Check invite code or password
    if (!team.is_public) {
      if (team.invite_code && team.invite_code !== inviteCode) {
        if (team.password && !(await bcrypt.compare(password || '', team.password))) {
          return res.status(403).json({ error: 'Invalid invite code or password' });
        }
      }
    }

    const { count } = await supabase.from('team_members').select('*', { count: 'exact', head: true }).eq('team_id', id);
    if ((count || 0) >= team.max_members) return res.status(400).json({ error: 'Team is full' });

    const { data: currentUser } = await supabase.from('users').select('team_id').eq('id', req.user.id).single();
    if (currentUser?.team_id) return res.status(400).json({ error: 'You are already in a team' });

    await supabase.from('users').update({ team_id: id }).eq('id', req.user.id);
    await supabase.from('team_members').insert({ team_id: id, user_id: req.user.id });

    await logActivity(req.user.id, 'team_join', 'team', id, { teamName: team.name }, req);
    await checkAndGrantAchievements(req.user.id);

    res.json({ success: true, message: 'Joined team successfully' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/teams/:id/leave', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: team } = await supabase.from('teams').select('leader_id, name').eq('id', id).single();
    if (team?.leader_id === req.user.id) return res.status(400).json({ error: 'Transfer leadership first' });

    await supabase.from('users').update({ team_id: null }).eq('id', req.user.id);
    await supabase.from('team_members').delete().eq('team_id', id).eq('user_id', req.user.id);

    await logActivity(req.user.id, 'team_leave', 'team', id, { teamName: team?.name }, req);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/teams/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: team } = await supabase.from('teams').select('leader_id').eq('id', id).single();
    if (team?.leader_id !== req.user.id) return res.status(403).json({ error: 'Only team leader can update' });

    const allowed = ['name', 'description', 'avatar_url', 'country', 'affiliation', 'website', 'is_public', 'max_members'];
    const filtered = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)));

    const { data } = await supabase.from('teams').update(filtered).eq('id', id).select().single();
    res.json({ team: data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/teams/:id/transfer', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { newLeaderId } = req.body;

    const { data: team } = await supabase.from('teams').select('leader_id').eq('id', id).single();
    if (team?.leader_id !== req.user.id) return res.status(403).json({ error: 'Only team leader can transfer' });

    const { data: member } = await supabase.from('team_members').select('user_id').eq('team_id', id).eq('user_id', newLeaderId).single();
    if (!member) return res.status(400).json({ error: 'User is not a team member' });

    await supabase.from('teams').update({ leader_id: newLeaderId }).eq('id', id);
    await logActivity(req.user.id, 'team_transfer', 'team', id, { newLeaderId }, req);

    res.json({ success: true, message: 'Leadership transferred' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/teams/:id/kick', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { userId } = req.body;

    const { data: team } = await supabase.from('teams').select('leader_id').eq('id', id).single();
    if (team?.leader_id !== req.user.id) return res.status(403).json({ error: 'Only team leader can kick' });
    if (userId === req.user.id) return res.status(400).json({ error: 'Cannot kick yourself' });

    await supabase.from('users').update({ team_id: null }).eq('id', userId);
    await supabase.from('team_members').delete().eq('team_id', id).eq('user_id', userId);

    await logActivity(req.user.id, 'team_kick', 'team', id, { kickedUserId: userId }, req);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== WRITEUPS ====================
app.get('/writeups', async (req, res) => {
  try {
    const { challenge_id, user_id, page = 1, limit = 20, sort = 'likes' } = req.query;
    const limitNum = Math.min(parseInt(limit), 50);
    const offset = (parseInt(page) - 1) * limitNum;

    let query = supabase.from('writeups').select(`
      id, title, user_id, challenge_id, is_public, view_count, like_count, created_at, updated_at,
      users(username, avatar_url), challenges(title, category)
    `, { count: 'exact' }).eq('is_public', true).eq('is_approved', true);

    if (challenge_id) query = query.eq('challenge_id', challenge_id);
    if (user_id) query = query.eq('user_id', user_id);

    if (sort === 'likes') query = query.order('like_count', { ascending: false });
    else if (sort === 'views') query = query.order('view_count', { ascending: false });
    else query = query.order('created_at', { ascending: false });

    const { data, count } = await query.range(offset, offset + limitNum - 1);
    res.json({ writeups: data || [], total: count, page: parseInt(page) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/writeups', requireAuth, async (req, res) => {
  try {
    const { challengeId, title, content } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Title and content required' });

    const { data: solve } = await supabase.from('solves').select('id').eq('user_id', req.user.id).eq('challenge_id', challengeId).single();
    if (!solve) return res.status(400).json({ error: 'Solve the challenge first' });

    const { data: writeup } = await supabase.from('writeups').insert({
      user_id: req.user.id, challenge_id: challengeId, title, content: sanitizeContent(content), is_public: false, is_approved: false
    }).select().single();

    await logActivity(req.user.id, 'writeup_create', 'writeup', writeup.id, { title }, req);
    res.json({ writeup });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/writeups/:id', async (req, res) => {
  try {
    const { data: writeup } = await supabase.from('writeups').select('*, users(username, avatar_url), challenges(title, category, difficulty)').eq('id', req.params.id).single();
    if (!writeup) return res.status(404).json({ error: 'Not found' });

    if (!writeup.is_public || !writeup.is_approved) {
      const user = getUser(req);
      if (writeup.user_id !== user?.id && user?.role !== 'admin') return res.status(404).json({ error: 'Not found' });
    }

    await supabase.from('writeups').update({ view_count: (writeup.view_count || 0) + 1 }).eq('id', req.params.id);
    res.json({ ...writeup, content: writeup.content });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/writeups/:id', requireAuth, async (req, res) => {
  try {
    const { data: writeup } = await supabase.from('writeups').select('user_id').eq('id', req.params.id).single();
    if (writeup?.user_id !== req.user.id) return res.status(403).json({ error: 'Not authorized' });

    const { title, content } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    if (title) updates.title = title;
    if (content) updates.content = sanitizeContent(content);

    const { data } = await supabase.from('writeups').update(updates).eq('id', req.params.id).select().single();
    res.json({ writeup: data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/writeups/:id', requireAuth, async (req, res) => {
  try {
    const { data: writeup } = await supabase.from('writeups').select('user_id').eq('id', req.params.id).single();
    if (writeup?.user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Not authorized' });

    await supabase.from('writeups').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/writeups/:id/like', requireAuth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('writeup_likes').select('id').eq('writeup_id', req.params.id).eq('user_id', req.user.id).single();
    if (existing) {
      await supabase.from('writeup_likes').delete().eq('id', existing.id);
      await supabase.rpc('decrement_writeup_likes', { writeup_id: req.params.id });
      return res.json({ liked: false });
    }

    await supabase.from('writeup_likes').insert({ writeup_id: req.params.id, user_id: req.user.id });
    const { data: writeup } = await supabase.from('writeups').select('like_count, user_id').eq('id', req.params.id).single();
    await supabase.from('writeups').update({ like_count: (writeup?.like_count || 0) + 1 }).eq('id', req.params.id);

    // Check helpful achievement for writeup author
    if (writeup?.user_id) await checkAndGrantAchievements(writeup.user_id);

    res.json({ liked: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== STATS ====================
app.get('/stats', async (req, res) => {
  try {
    let stats = cache.get('platform_stats');
    if (!stats) {
      const { count: userCount } = await supabase.from('users').select('*', { count: 'exact', head: true });
      const { count: teamCount } = await supabase.from('teams').select('*', { count: 'exact', head: true });
      const { count: challengeCount } = await supabase.from('challenges').select('*', { count: 'exact', head: true }).eq('is_visible', true);
      const { count: solveCount } = await supabase.from('solves').select('*', { count: 'exact', head: true });
      const { count: submissionCount } = await supabase.from('submissions').select('*', { count: 'exact', head: true });
      const { count: writeupCount } = await supabase.from('writeups').select('*', { count: 'exact', head: true }).eq('is_approved', true);

      const { data: categories } = await supabase.from('challenges').select('category, difficulty').eq('is_visible', true);
      const catCount = {}, diffCount = {};
      for (const c of categories || []) {
        catCount[c.category] = (catCount[c.category] || 0) + 1;
        diffCount[c.difficulty] = (diffCount[c.difficulty] || 0) + 1;
      }

      stats = {
        users: userCount || 0, teams: teamCount || 0, challenges: challengeCount || 0,
        solves: solveCount || 0, submissions: submissionCount || 0, writeups: writeupCount || 0,
        categories: catCount, difficulties: diffCount
      };
      cache.set('platform_stats', stats, 60);
    }
    res.json(stats);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ANNOUNCEMENTS ====================
app.get('/announcements', async (req, res) => {
  try {
    const { data } = await supabase.from('announcements').select('*').eq('is_active', true).lte('starts_at', new Date().toISOString()).order('priority', { ascending: false }).order('created_at', { ascending: false });
    res.json({ announcements: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== NOTIFICATIONS ====================
app.get('/notifications', requireAuth, async (req, res) => {
  try {
    const { unread_only, page = 1, limit = 50 } = req.query;
    const limitNum = Math.min(parseInt(limit), 100);
    const offset = (parseInt(page) - 1) * limitNum;

    let query = supabase.from('notifications').select('*', { count: 'exact' }).or(`user_id.eq.${req.user.id},user_id.is.null`);
    if (unread_only === 'true') query = query.eq('is_read', false);

    const { data, count } = await query.order('created_at', { ascending: false }).range(offset, offset + limitNum - 1);

    const { count: unreadCount } = await supabase.from('notifications').select('*', { count: 'exact', head: true }).or(`user_id.eq.${req.user.id},user_id.is.null`).eq('is_read', false);

    res.json({ notifications: data || [], total: count, unreadCount, page: parseInt(page) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/notifications/:id/read', requireAuth, async (req, res) => {
  try {
    await supabase.from('notifications').update({ is_read: true }).eq('id', req.params.id).eq('user_id', req.user.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/notifications/read-all', requireAuth, async (req, res) => {
  try {
    await supabase.from('notifications').update({ is_read: true }).eq('user_id', req.user.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== USERS ====================
app.get('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: profile } = await supabase.from('users').select('id, username, avatar_url, country, affiliation, bio, website, github, twitter, discord, bracket, created_at, team_id').eq('id', id).eq('is_hidden', false).single();
    if (!profile) return res.status(404).json({ error: 'Not found' });

    const { data: solves } = await supabase.from('solves').select('challenge_id, points_awarded, solved_at, is_first_blood, challenges(title, category, difficulty)').eq('user_id', id).order('solved_at', { ascending: false });
    const { data: achievements } = await supabase.from('user_achievements').select('*').eq('user_id', id);
    const { data: hintUnlocks } = await supabase.from('hint_unlocks').select('hints(penalty)').eq('user_id', id);

    const score = (solves || []).reduce((sum, s) => sum + (s.points_awarded || 0), 0);
    const penalty = (hintUnlocks || []).reduce((sum, h) => sum + (h.hints?.penalty || 0), 0);
    const firstBloods = (solves || []).filter(s => s.is_first_blood).length;

    // Category breakdown
    const categoryStats = {};
    for (const s of solves || []) {
      const cat = s.challenges?.category;
      if (cat) categoryStats[cat] = (categoryStats[cat] || 0) + 1;
    }

    // Get rank
    const { data: allScores } = await supabase.from('solves').select('user_id, points_awarded');
    const userScores = {};
    for (const s of allScores || []) userScores[s.user_id] = (userScores[s.user_id] || 0) + (s.points_awarded || 0);
    const sortedUsers = Object.entries(userScores).sort((a, b) => b[1] - a[1]);
    const rank = sortedUsers.findIndex(([uid]) => uid === id) + 1;

    let team = null;
    if (profile.team_id) {
      const { data: t } = await supabase.from('teams').select('id, name, avatar_url').eq('id', profile.team_id).single();
      team = t;
    }

    res.json({
      ...profile, score: score - penalty, rank: rank || null, solveCount: solves?.length || 0,
      firstBloods, team, categoryStats,
      achievements: (achievements || []).map(a => ({ ...a, details: ACHIEVEMENTS[a.achievement_name] })),
      recentSolves: (solves || []).slice(0, 15).map(s => ({
        challengeId: s.challenge_id, title: s.challenges?.title, category: s.challenges?.category,
        difficulty: s.challenges?.difficulty, points: s.points_awarded, firstBlood: s.is_first_blood, solvedAt: s.solved_at
      }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/users/:id/solves', async (req, res) => {
  try {
    const { id } = req.params;
    const { page = 1, limit = 50 } = req.query;
    const limitNum = Math.min(parseInt(limit), 100);
    const offset = (parseInt(page) - 1) * limitNum;

    const { data, count } = await supabase.from('solves').select(`
      challenge_id, points_awarded, solved_at, is_first_blood,
      challenges(id, title, category, difficulty, points)
    `, { count: 'exact' }).eq('user_id', id).order('solved_at', { ascending: false }).range(offset, offset + limitNum - 1);

    res.json({ solves: data || [], total: count, page: parseInt(page) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== CONTESTS ====================
app.get('/contests', async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const limitNum = Math.min(parseInt(limit), 50);
    const offset = (parseInt(page) - 1) * limitNum;
    const now = new Date().toISOString();

    let query = supabase.from('contests').select('*', { count: 'exact' }).eq('is_public', true);

    if (status === 'active') {
      query = query.lte('start_time', now).gte('end_time', now);
    } else if (status === 'upcoming') {
      query = query.gt('start_time', now);
    } else if (status === 'ended') {
      query = query.lt('end_time', now);
    }

    const { data, count } = await query.order('start_time', { ascending: false }).range(offset, offset + limitNum - 1);

    res.json({ contests: data || [], total: count, page: parseInt(page) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/contests/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: contest } = await supabase.from('contests').select('*').eq('id', id).single();
    if (!contest) return res.status(404).json({ error: 'Not found' });

    const { data: challenges } = await supabase.from('contest_challenges').select('challenge_id, order_index, is_bonus, challenges(id, title, category, points, solve_count)').eq('contest_id', id).order('order_index');
    const { count: participantCount } = await supabase.from('contest_participants').select('*', { count: 'exact', head: true }).eq('contest_id', id);

    const user = getUser(req);
    let registered = false;
    if (user?.id) {
      const { data: reg } = await supabase.from('contest_participants').select('id').eq('contest_id', id).eq('user_id', user.id).single();
      registered = !!reg;
    }

    res.json({
      ...contest,
      challenges: (challenges || []).map(c => ({ ...c.challenges, orderIndex: c.order_index, isBonus: c.is_bonus })),
      participantCount: participantCount || 0,
      registered
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/contests/:id/register', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: contest } = await supabase.from('contests').select('*').eq('id', id).single();
    if (!contest) return res.status(404).json({ error: 'Not found' });
    if (!contest.registration_open) return res.status(400).json({ error: 'Registration closed' });

    const now = new Date();
    if (contest.registration_deadline && new Date(contest.registration_deadline) < now) {
      return res.status(400).json({ error: 'Registration deadline passed' });
    }

    const { data: existing } = await supabase.from('contest_participants').select('id').eq('contest_id', id).eq('user_id', req.user.id).single();
    if (existing) return res.status(400).json({ error: 'Already registered' });

    if (contest.max_participants > 0) {
      const { count } = await supabase.from('contest_participants').select('*', { count: 'exact', head: true }).eq('contest_id', id);
      if ((count || 0) >= contest.max_participants) return res.status(400).json({ error: 'Contest is full' });
    }

    await supabase.from('contest_participants').insert({
      contest_id: id, user_id: req.user.id, team_id: req.user.teamId || null
    });

    await logActivity(req.user.id, 'contest_register', 'contest', id, { contestName: contest.name }, req);
    res.json({ success: true, message: 'Registered successfully' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ACHIEVEMENTS ====================
app.get('/achievements', async (req, res) => {
  try {
    const user = getUser(req);
    let userAchievements = [];

    if (user?.id) {
      const { data } = await supabase.from('user_achievements').select('achievement_name').eq('user_id', user.id);
      userAchievements = (data || []).map(a => a.achievement_name);
    }

    const achievements = Object.entries(ACHIEVEMENTS).map(([key, value]) => ({
      key, ...value, earned: userAchievements.includes(key)
    }));

    res.json({ achievements });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== CONFIG ====================
app.get('/config', async (req, res) => {
  try {
    const { data } = await supabase.from('config').select('key, value');
    const config = {};
    for (const c of data || []) config[c.key] = c.value;

    res.json({
      platformName: config.platform_name || PLATFORM_NAME,
      flagFormat: `${FLAG_PREFIXES[0]}{...}`,
      flagPrefix: FLAG_PREFIXES[0],
      registrationEnabled: config.registration_enabled !== 'false',
      teamMode: config.team_mode === 'true',
      brackets: (config.brackets || 'Open,Student,Professional').split(','),
      scoringAlgorithms: Object.keys(scoringAlgorithms),
      maxTeamSize: parseInt(config.max_team_size) || 5
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ADMIN ROUTES ====================
// (Admin routes remain comprehensive - challenges, users, announcements, writeups, contests, config)

app.get('/admin/challenges', requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('challenges').select('*, hints(id, content, penalty), challenge_files(id, filename, file_size)').order('created_at', { ascending: false });
    res.json({ challenges: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/challenges', requireAdmin, async (req, res) => {
  try {
    const { title, description, category, difficulty, points, flag, flagType, minPoints, decay, scoringType, connectionInfo, maxAttempts, firstBloodPoints, isVisible, hints, tags, prerequisites } = req.body;
    if (!title || !category || !flag || !points) return res.status(400).json({ error: 'Missing required fields' });

    let { data: comp } = await supabase.from('competitions').select('id').order('created_at', { ascending: false }).limit(1).single();
    if (!comp) {
      const { data: newComp } = await supabase.from('competitions').insert({ name: 'Default', start_time: new Date().toISOString(), end_time: new Date(Date.now() + 365*24*60*60*1000).toISOString(), is_public: true }).select().single();
      comp = newComp;
    }

    const { data: challenge, error } = await supabase.from('challenges').insert({
      title, description, category, difficulty: difficulty || 'medium', points: Number(points), flag,
      flag_type: flagType || 'static', min_points: minPoints || 100, decay: decay || 50,
      scoring_type: scoringType || 'static', connection_info: connectionInfo,
      max_attempts: maxAttempts || 0, first_blood_points: firstBloodPoints || 0,
      is_visible: isVisible !== false, competition_id: comp.id, author_id: req.user.id
    }).select().single();

    if (error) return res.status(400).json({ error: error.message });

    // Add hints
    if (hints?.length) {
      for (let i = 0; i < hints.length; i++) {
        await supabase.from('hints').insert({ challenge_id: challenge.id, content: hints[i].content, penalty: hints[i].penalty || 0, order_index: i });
      }
    }

    // Add tags
    if (tags?.length) {
      for (const tagName of tags) {
        let { data: tag } = await supabase.from('challenge_tags').select('id').eq('name', tagName).single();
        if (!tag) {
          const { data: newTag } = await supabase.from('challenge_tags').insert({ name: tagName }).select().single();
          tag = newTag;
        }
        if (tag) await supabase.from('challenge_tag_map').insert({ challenge_id: challenge.id, tag_id: tag.id });
      }
    }

    // Add prerequisites
    if (prerequisites?.length) {
      for (const prereqId of prerequisites) {
        await supabase.from('challenge_prerequisites').insert({ challenge_id: challenge.id, prerequisite_id: prereqId });
      }
    }

    cache.flushAll();
    await logActivity(req.user.id, 'challenge_create', 'challenge', challenge.id, { title }, req);

    broadcast('challenges', { type: 'new_challenge', challengeId: challenge.id, title: challenge.title, category: challenge.category });

    res.json({ challenge });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/admin/challenges/:id', requireAdmin, async (req, res) => {
  try {
    const allowed = ['title', 'description', 'category', 'difficulty', 'points', 'flag', 'flag_type', 'min_points', 'decay', 'scoring_type', 'connection_info', 'max_attempts', 'first_blood_points', 'is_visible', 'docker_image', 'port_mapping'];
    const filtered = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)));

    const { data } = await supabase.from('challenges').update(filtered).eq('id', req.params.id).select().single();
    cache.flushAll();
    await logActivity(req.user.id, 'challenge_update', 'challenge', req.params.id, filtered, req);

    res.json({ challenge: data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/admin/challenges/:id', requireAdmin, async (req, res) => {
  try {
    await supabase.from('challenges').delete().eq('id', req.params.id);
    cache.flushAll();
    await logActivity(req.user.id, 'challenge_delete', 'challenge', req.params.id, {}, req);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const { search, page = 1, limit = 50 } = req.query;
    const limitNum = Math.min(parseInt(limit), 200);
    const offset = (parseInt(page) - 1) * limitNum;

    let query = supabase.from('users').select('id, email, username, role, team_id, is_banned, is_hidden, created_at, last_login, login_count, country, affiliation', { count: 'exact' });
    if (search) query = query.or(`username.ilike.%${search}%,email.ilike.%${search}%`);

    const { data, count } = await query.order('created_at', { ascending: false }).range(offset, offset + limitNum - 1);
    res.json({ users: data || [], total: count, page: parseInt(page) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/admin/users/:id/role', requireAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['user', 'admin', 'moderator'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
    await supabase.from('users').update({ role }).eq('id', req.params.id);
    await logActivity(req.user.id, 'user_role_change', 'user', req.params.id, { role }, req);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/users/:id/ban', requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    await supabase.from('users').update({ is_banned: true, banned_at: new Date().toISOString(), banned_by: req.user.id, ban_reason: reason }).eq('id', req.params.id);
    await logActivity(req.user.id, 'user_ban', 'user', req.params.id, { reason }, req);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/users/:id/unban', requireAdmin, async (req, res) => {
  try {
    await supabase.from('users').update({ is_banned: false, banned_at: null, banned_by: null, ban_reason: null }).eq('id', req.params.id);
    await logActivity(req.user.id, 'user_unban', 'user', req.params.id, {}, req);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/announcements', requireAdmin, async (req, res) => {
  try {
    const { title, content, priority = 'normal' } = req.body;
    const { data } = await supabase.from('announcements').insert({ title, content, priority, created_by: req.user.id, is_active: true }).select().single();

    broadcastAll({ type: 'announcement', title, priority });
    res.json({ announcement: data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/activity', requireAdmin, async (req, res) => {
  try {
    const { user_id, action, entity_type, page = 1, limit = 100 } = req.query;
    const limitNum = Math.min(parseInt(limit), 500);
    const offset = (parseInt(page) - 1) * limitNum;

    let query = supabase.from('activity_log').select('*, users(username)', { count: 'exact' });
    if (user_id) query = query.eq('user_id', user_id);
    if (action) query = query.eq('action', action);
    if (entity_type) query = query.eq('entity_type', entity_type);

    const { data, count } = await query.order('created_at', { ascending: false }).range(offset, offset + limitNum - 1);
    res.json({ activities: data || [], total: count, page: parseInt(page) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/stats', requireAdmin, async (req, res) => {
  try {
    const { count: userCount } = await supabase.from('users').select('*', { count: 'exact', head: true });
    const { count: activeToday } = await supabase.from('users').select('*', { count: 'exact', head: true }).gte('last_login', new Date(Date.now() - 24*60*60*1000).toISOString());
    const { count: submissionsToday } = await supabase.from('submissions').select('*', { count: 'exact', head: true }).gte('submitted_at', new Date(Date.now() - 24*60*60*1000).toISOString());
    const { count: solvesToday } = await supabase.from('solves').select('*', { count: 'exact', head: true }).gte('solved_at', new Date(Date.now() - 24*60*60*1000).toISOString());

    res.json({
      totalUsers: userCount || 0,
      activeToday: activeToday || 0,
      submissionsToday: submissionsToday || 0,
      solvesToday: solvesToday || 0,
      wsConnections: wsClients.size
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/config', requireAdmin, async (req, res) => {
  try {
    const updates = req.body;
    for (const [key, value] of Object.entries(updates)) {
      await supabase.from('config').upsert({ key, value: String(value), updated_at: new Date().toISOString() }, { onConflict: 'key' });
    }
    cache.del('platform_stats');
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/cache/clear', requireAdmin, async (req, res) => {
  cache.flushAll();
  res.json({ success: true, message: 'Cache cleared' });
});

// ==================== ERROR HANDLER ====================
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ==================== CATCH-ALL ROUTE ====================
// Serve frontend for any non-API routes (SPA support)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== START SERVER ====================
server.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║                    CTF WAR API v3.0.0                     ║
║═══════════════════════════════════════════════════════════║
║  Platform: ${PLATFORM_NAME.padEnd(44)}║
║  Port: ${String(PORT).padEnd(49)}║
║  WebSocket: Enabled                                       ║
║  Rate Limiting: Enabled                                   ║
║  Caching: Enabled                                         ║
║  Achievements: 25+ available                              ║
║  Scoring: static, dynamic, logarithmic, linear, exponential║
╚═══════════════════════════════════════════════════════════╝
  `);
});
