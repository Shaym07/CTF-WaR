const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

// Environment variables
const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://vfhilobaycsxwbjojgjc.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'c073386cb88b7d2fc6a4ad3ea0ab5718';
const FLAG_PREFIXES = (process.env.FLAG_PREFIXES || 'WOW').split(',').map(s => s.trim());

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Helper functions
const createToken = (user) => jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });

const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
};

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

// Dynamic scoring
const calculateDynamicPoints = (initial, min, decay, solves) => {
  if (decay <= 0) return initial;
  const points = Math.ceil(((min - initial) / (decay * decay)) * (solves * solves) + initial);
  return Math.max(min, Math.min(initial, points));
};

// ==================== HEALTH ====================
app.get('/', (req, res) => res.json({ status: 'ok', platform: 'CTF War', version: '2.0.0' }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ==================== AUTH ====================
app.post('/auth/register', async (req, res) => {
  try {
    const { email, username, password, affiliation, country } = req.body;
    if (!email || !username || !password) return res.status(400).json({ error: 'Missing required fields' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const { data: existing } = await supabase.from('users').select('id').or(`email.eq.${email},username.eq.${username}`).limit(1);
    if (existing?.length > 0) return res.status(400).json({ error: 'Email or username already exists' });

    const password_hash = await bcrypt.hash(password, 12);
    const { data: user, error } = await supabase.from('users').insert({
      email, username, password_hash, role: 'user', affiliation, country, is_verified: true
    }).select().single();
    if (error) throw error;

    const token = createToken({ id: user.id, email: user.email, username: user.username, role: user.role });
    res.json({ user: { id: user.id, email: user.email, username: user.username, role: user.role }, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.is_banned) return res.status(403).json({ error: 'Account is banned' });
    if (!(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Invalid credentials' });

    await supabase.from('users').update({ last_login: new Date().toISOString(), login_count: (user.login_count || 0) + 1 }).eq('id', user.id);

    const token = createToken({ id: user.id, email: user.email, username: user.username, role: user.role, teamId: user.team_id });
    res.json({ user: { id: user.id, email: user.email, username: user.username, role: user.role, teamId: user.team_id }, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const { data } = await supabase.from('users').select('id, email, username, role, team_id, avatar_url, country, affiliation, bio, website, github, twitter, discord, created_at').eq('id', req.user.id).single();
    const { data: solves } = await supabase.from('solves').select('points_awarded').eq('user_id', req.user.id);
    const score = (solves || []).reduce((sum, s) => sum + (s.points_awarded || 0), 0);
    res.json({ user: { ...data, score, solveCount: solves?.length || 0 } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/auth/profile', requireAuth, async (req, res) => {
  try {
    const allowed = ['affiliation', 'country', 'bio', 'website', 'github', 'twitter', 'discord', 'avatar_url'];
    const filtered = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)));
    const { data } = await supabase.from('users').update(filtered).eq('id', req.user.id).select().single();
    res.json({ user: data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== CHALLENGES ====================
app.get('/challenges', async (req, res) => {
  try {
    const user = getUser(req);
    const category = req.query.category;

    let query = supabase.from('challenges').select('id, title, description, category, difficulty, points, min_points, decay, scoring_type, connection_info, solve_count, first_blood_points, first_blood_user_id, first_blood_at, max_attempts, state').eq('is_visible', true);
    if (category) query = query.eq('category', category);

    const { data: challenges } = await query.order('category').order('points', { ascending: true });

    let solvedIds = [];
    let userAttempts = {};
    if (user?.id) {
      const { data: solves } = await supabase.from('solves').select('challenge_id').eq('user_id', user.id);
      solvedIds = (solves || []).map(s => s.challenge_id);
      const { data: submissions } = await supabase.from('submissions').select('challenge_id').eq('user_id', user.id).eq('is_correct', false);
      for (const sub of submissions || []) userAttempts[sub.challenge_id] = (userAttempts[sub.challenge_id] || 0) + 1;
    }

    const challengeIds = (challenges || []).map(c => c.id);
    const { data: hints } = await supabase.from('hints').select('challenge_id, id').in('challenge_id', challengeIds);
    const { data: files } = await supabase.from('challenge_files').select('challenge_id, id').in('challenge_id', challengeIds);

    const hintCount = {}, fileCount = {};
    for (const h of hints || []) hintCount[h.challenge_id] = (hintCount[h.challenge_id] || 0) + 1;
    for (const f of files || []) fileCount[f.challenge_id] = (fileCount[f.challenge_id] || 0) + 1;

    const result = (challenges || []).map(c => {
      const points = c.scoring_type === 'dynamic' ? calculateDynamicPoints(c.points, c.min_points || 100, c.decay || 50, c.solve_count || 0) : c.points;
      return { ...c, points, solved: solvedIds.includes(c.id), solveCount: c.solve_count || 0, hintCount: hintCount[c.id] || 0, fileCount: fileCount[c.id] || 0, attempts: userAttempts[c.id] || 0 };
    });

    res.json({ challenges: result });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/challenges/categories', async (req, res) => {
  try {
    const { data } = await supabase.from('challenges').select('category').eq('is_visible', true);
    const categories = [...new Set((data || []).map(c => c.category).filter(Boolean))].sort();
    res.json({ categories });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/challenges/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const user = getUser(req);

    const { data: challenge } = await supabase.from('challenges').select('*').eq('id', id).eq('is_visible', true).single();
    if (!challenge) return res.status(404).json({ error: 'Challenge not found' });

    const { data: hints } = await supabase.from('hints').select('id, penalty, order_index, content').eq('challenge_id', id).order('order_index');
    const { data: files } = await supabase.from('challenge_files').select('id, filename, file_size, file_path').eq('challenge_id', id);

    let unlockedHints = [], solved = false;
    if (user?.id) {
      const { data: unlocks } = await supabase.from('hint_unlocks').select('hint_id').eq('user_id', user.id);
      unlockedHints = (unlocks || []).map(u => u.hint_id);
      const { data: solve } = await supabase.from('solves').select('id').eq('user_id', user.id).eq('challenge_id', id).single();
      solved = !!solve;
    }

    let firstBlood = null;
    if (challenge.first_blood_user_id) {
      const { data: fbUser } = await supabase.from('users').select('username').eq('id', challenge.first_blood_user_id).single();
      firstBlood = { username: fbUser?.username, at: challenge.first_blood_at };
    }

    const points = challenge.scoring_type === 'dynamic' ? calculateDynamicPoints(challenge.points, challenge.min_points || 100, challenge.decay || 50, challenge.solve_count || 0) : challenge.points;

    const hintsWithContent = (hints || []).map(h => ({
      id: h.id, penalty: h.penalty, unlocked: unlockedHints.includes(h.id) || solved,
      content: (unlockedHints.includes(h.id) || solved) ? h.content : null
    }));

    res.json({
      id: challenge.id, title: challenge.title, description: challenge.description, category: challenge.category,
      difficulty: challenge.difficulty, points, originalPoints: challenge.points, scoringType: challenge.scoring_type,
      connectionInfo: challenge.connection_info, maxAttempts: challenge.max_attempts, solveCount: challenge.solve_count || 0,
      firstBlood, firstBloodPoints: challenge.first_blood_points, hints: hintsWithContent, files, solved
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

    const { data: existingSolve } = await supabase.from('solves').select('id').eq('user_id', req.user.id).eq('challenge_id', id).single();
    if (existingSolve) return res.status(400).json({ error: 'Already solved' });

    if (challenge.max_attempts > 0) {
      const { count } = await supabase.from('submissions').select('*', { count: 'exact', head: true }).eq('user_id', req.user.id).eq('challenge_id', id).eq('is_correct', false);
      if ((count || 0) >= challenge.max_attempts) return res.status(400).json({ error: 'Maximum attempts reached' });
    }

    let isCorrect = false;
    const flagType = challenge.flag_type || 'static';

    if (flagType === 'regex') {
      try { isCorrect = new RegExp(challenge.flag).test(flag.trim()); } catch { isCorrect = false; }
    } else {
      const parseFlag = (f) => { const m = f.match(/^([A-Za-z0-9_]+)\{(.+)\}$/); return m ? { prefix: m[1], value: m[2] } : { prefix: null, value: f.trim() }; };
      const submitted = parseFlag(flag.trim());
      const correct = parseFlag(challenge.flag);
      if (correct.prefix) {
        isCorrect = submitted.prefix !== null && (submitted.prefix === correct.prefix || FLAG_PREFIXES.includes(submitted.prefix)) && submitted.value === correct.value;
      } else {
        isCorrect = challenge.flag === flag.trim();
      }
    }

    const { count: solveCount } = await supabase.from('solves').select('*', { count: 'exact', head: true }).eq('challenge_id', id);
    const isFirstBlood = isCorrect && (solveCount || 0) === 0;

    const basePoints = challenge.scoring_type === 'dynamic' ? calculateDynamicPoints(challenge.points, challenge.min_points || 100, challenge.decay || 50, challenge.solve_count || 0) : challenge.points;
    let pointsAwarded = isCorrect ? basePoints : 0;
    let firstBloodBonus = 0;

    if (isFirstBlood && challenge.first_blood_points) {
      firstBloodBonus = challenge.first_blood_points;
      pointsAwarded += firstBloodBonus;
    }

    const { data: submission } = await supabase.from('submissions').insert({
      user_id: req.user.id, challenge_id: id, submitted_flag: flag.trim(), is_correct: isCorrect,
      points_awarded: pointsAwarded, team_id: req.user.teamId || null
    }).select().single();

    if (isCorrect) {
      await supabase.from('solves').insert({
        user_id: req.user.id, challenge_id: id, submission_id: submission.id,
        points_awarded: pointsAwarded, is_first_blood: isFirstBlood, team_id: req.user.teamId || null
      });

      const updates = { solve_count: (challenge.solve_count || 0) + 1 };
      if (isFirstBlood) { updates.first_blood_user_id = req.user.id; updates.first_blood_at = new Date().toISOString(); }
      await supabase.from('challenges').update(updates).eq('id', id);

      const { data: allSolves } = await supabase.from('solves').select('points_awarded').eq('user_id', req.user.id);
      const totalPoints = (allSolves || []).reduce((sum, s) => sum + (s.points_awarded || 0), 0);

      return res.json({ correct: true, points: pointsAwarded, basePoints, firstBloodBonus, isFirstBlood, totalScore: totalPoints, message: isFirstBlood ? 'First Blood! Bonus points!' : 'Correct! Challenge solved!' });
    }

    res.json({ correct: false, message: 'Incorrect flag. Try again!' });
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

    res.json({ hint: { id: hint.id, content: hint.content, penalty: hint.penalty }, unlocked: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== SCOREBOARD ====================
app.get('/scoreboard', async (req, res) => {
  try {
    const type = req.query.type || 'users';
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);

    if (type === 'teams') {
      const { data: solves } = await supabase.from('solves').select('team_id, points_awarded, solved_at').not('team_id', 'is', null).order('solved_at');
      const teamScores = {};
      for (const s of solves || []) {
        if (!teamScores[s.team_id]) teamScores[s.team_id] = { score: 0, solves: 0, lastSolve: s.solved_at };
        teamScores[s.team_id].score += s.points_awarded || 0;
        teamScores[s.team_id].solves++;
        if (s.solved_at > teamScores[s.team_id].lastSolve) teamScores[s.team_id].lastSolve = s.solved_at;
      }

      const teamIds = Object.keys(teamScores);
      const { data: teams } = await supabase.from('teams').select('id, name, avatar_url, country').in('id', teamIds);
      const teamMap = Object.fromEntries((teams || []).map(t => [t.id, t]));

      const leaderboard = Object.entries(teamScores)
        .map(([id, data]) => ({ teamId: id, name: teamMap[id]?.name || 'Unknown', avatar: teamMap[id]?.avatar_url, country: teamMap[id]?.country, ...data }))
        .sort((a, b) => b.score - a.score || new Date(a.lastSolve) - new Date(b.lastSolve))
        .slice(0, limit)
        .map((entry, i) => ({ rank: i + 1, ...entry }));

      return res.json({ leaderboard, type: 'teams' });
    }

    const { data: solves } = await supabase.from('solves').select('user_id, points_awarded, solved_at').order('solved_at');
    const { data: hintUnlocks } = await supabase.from('hint_unlocks').select('user_id, hints(penalty)');

    const userScores = {};
    for (const s of solves || []) {
      if (!userScores[s.user_id]) userScores[s.user_id] = { score: 0, solves: 0, lastSolve: s.solved_at, penalty: 0 };
      userScores[s.user_id].score += s.points_awarded || 0;
      userScores[s.user_id].solves++;
      if (s.solved_at > userScores[s.user_id].lastSolve) userScores[s.user_id].lastSolve = s.solved_at;
    }

    for (const h of hintUnlocks || []) {
      if (userScores[h.user_id]) userScores[h.user_id].penalty += h.hints?.penalty || 0;
    }

    const userIds = Object.keys(userScores);
    const { data: users } = await supabase.from('users').select('id, username, avatar_url, country, affiliation').in('id', userIds).eq('is_hidden', false);
    const userMap = Object.fromEntries((users || []).map(u => [u.id, u]));

    const leaderboard = Object.entries(userScores)
      .filter(([id]) => userMap[id])
      .map(([id, data]) => ({ userId: id, username: userMap[id]?.username || 'Unknown', avatar: userMap[id]?.avatar_url, country: userMap[id]?.country, affiliation: userMap[id]?.affiliation, score: data.score - data.penalty, solves: data.solves, lastSolve: data.lastSolve }))
      .sort((a, b) => b.score - a.score || new Date(a.lastSolve) - new Date(b.lastSolve))
      .slice(0, limit)
      .map((entry, i) => ({ rank: i + 1, ...entry }));

    res.json({ leaderboard, type: 'users' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== TEAMS ====================
app.get('/teams', async (req, res) => {
  try {
    const { data: teams } = await supabase.from('teams').select('id, name, description, avatar_url, country, affiliation, is_public, created_at').eq('is_public', true).order('created_at', { ascending: false });
    res.json({ teams: teams || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/teams', requireAuth, async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Team name is required' });

    const { data: currentUser } = await supabase.from('users').select('team_id').eq('id', req.user.id).single();
    if (currentUser?.team_id) return res.status(400).json({ error: 'You are already in a team' });

    const { data: team, error } = await supabase.from('teams').insert({ name, description, leader_id: req.user.id, is_public: true }).select().single();
    if (error) return res.status(400).json({ error: error.message });

    await supabase.from('users').update({ team_id: team.id }).eq('id', req.user.id);
    await supabase.from('team_members').insert({ team_id: team.id, user_id: req.user.id });

    res.json({ team });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/teams/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: team } = await supabase.from('teams').select('*').eq('id', id).single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    const { data: members } = await supabase.from('team_members').select('user_id, joined_at, users(id, username, avatar_url, country)').eq('team_id', id);
    const { data: solves } = await supabase.from('solves').select('points_awarded').eq('team_id', id);
    const score = (solves || []).reduce((sum, s) => sum + (s.points_awarded || 0), 0);

    res.json({ ...team, members: (members || []).map(m => ({ ...m.users, joinedAt: m.joined_at })), score, solveCount: solves?.length || 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/teams/:id/join', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { inviteCode } = req.body;

    const { data: team } = await supabase.from('teams').select('*').eq('id', id).single();
    if (!team) return res.status(404).json({ error: 'Team not found' });
    if (team.invite_code && team.invite_code !== inviteCode) return res.status(400).json({ error: 'Invalid invite code' });

    const { count } = await supabase.from('team_members').select('*', { count: 'exact', head: true }).eq('team_id', id);
    if ((count || 0) >= team.max_members) return res.status(400).json({ error: 'Team is full' });

    const { data: currentUser } = await supabase.from('users').select('team_id').eq('id', req.user.id).single();
    if (currentUser?.team_id) return res.status(400).json({ error: 'You are already in a team' });

    await supabase.from('users').update({ team_id: id }).eq('id', req.user.id);
    await supabase.from('team_members').insert({ team_id: id, user_id: req.user.id });

    res.json({ success: true, message: 'Joined team successfully' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/teams/:id/leave', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: team } = await supabase.from('teams').select('leader_id').eq('id', id).single();
    if (team?.leader_id === req.user.id) return res.status(400).json({ error: 'Team leader cannot leave' });

    await supabase.from('users').update({ team_id: null }).eq('id', req.user.id);
    await supabase.from('team_members').delete().eq('team_id', id).eq('user_id', req.user.id);

    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== STATS ====================
app.get('/stats', async (req, res) => {
  try {
    const { count: userCount } = await supabase.from('users').select('*', { count: 'exact', head: true });
    const { count: teamCount } = await supabase.from('teams').select('*', { count: 'exact', head: true });
    const { count: challengeCount } = await supabase.from('challenges').select('*', { count: 'exact', head: true }).eq('is_visible', true);
    const { count: solveCount } = await supabase.from('solves').select('*', { count: 'exact', head: true });

    const { data: categories } = await supabase.from('challenges').select('category').eq('is_visible', true);
    const catCount = {};
    for (const c of categories || []) catCount[c.category] = (catCount[c.category] || 0) + 1;

    res.json({ users: userCount || 0, teams: teamCount || 0, challenges: challengeCount || 0, solves: solveCount || 0, categories: catCount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ANNOUNCEMENTS ====================
app.get('/announcements', async (req, res) => {
  try {
    const { data } = await supabase.from('announcements').select('*').eq('is_active', true).lte('starts_at', new Date().toISOString()).order('created_at', { ascending: false });
    res.json({ announcements: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== NOTIFICATIONS ====================
app.get('/notifications', requireAuth, async (req, res) => {
  try {
    const { data } = await supabase.from('notifications').select('*').or(`user_id.eq.${req.user.id},user_id.is.null`).order('created_at', { ascending: false }).limit(50);
    res.json({ notifications: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/notifications/:id/read', requireAuth, async (req, res) => {
  try {
    await supabase.from('notifications').update({ is_read: true }).eq('id', req.params.id).eq('user_id', req.user.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== USERS ====================
app.get('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: profile } = await supabase.from('users').select('id, username, avatar_url, country, affiliation, bio, website, github, twitter, discord, created_at, team_id').eq('id', id).eq('is_hidden', false).single();
    if (!profile) return res.status(404).json({ error: 'User not found' });

    const { data: solves } = await supabase.from('solves').select('challenge_id, points_awarded, solved_at, is_first_blood, challenges(title, category)').eq('user_id', id).order('solved_at', { ascending: false });
    const score = (solves || []).reduce((sum, s) => sum + (s.points_awarded || 0), 0);

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

    const { data: achievements } = await supabase.from('user_achievements').select('*').eq('user_id', id);

    res.json({
      ...profile, score, rank: rank || null, solveCount: solves?.length || 0, team, achievements: achievements || [],
      recentSolves: (solves || []).slice(0, 10).map(s => ({ challengeId: s.challenge_id, title: s.challenges?.title, category: s.challenges?.category, points: s.points_awarded, firstBlood: s.is_first_blood, solvedAt: s.solved_at }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== WRITEUPS ====================
app.get('/writeups', async (req, res) => {
  try {
    const challengeId = req.query.challenge_id;
    let query = supabase.from('writeups').select('id, title, user_id, challenge_id, is_public, view_count, like_count, created_at, users(username, avatar_url), challenges(title, category)').eq('is_public', true).eq('is_approved', true);
    if (challengeId) query = query.eq('challenge_id', challengeId);
    const { data } = await query.order('like_count', { ascending: false }).limit(50);
    res.json({ writeups: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/writeups', requireAuth, async (req, res) => {
  try {
    const { challengeId, title, content } = req.body;
    const { data: solve } = await supabase.from('solves').select('id').eq('user_id', req.user.id).eq('challenge_id', challengeId).single();
    if (!solve) return res.status(400).json({ error: 'You must solve the challenge first' });

    const { data: writeup } = await supabase.from('writeups').insert({ user_id: req.user.id, challenge_id: challengeId, title, content, is_public: false, is_approved: false }).select().single();
    res.json({ writeup });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/writeups/:id', async (req, res) => {
  try {
    const { data: writeup } = await supabase.from('writeups').select('*, users(username, avatar_url), challenges(title, category)').eq('id', req.params.id).single();
    if (!writeup) return res.status(404).json({ error: 'Writeup not found' });
    if (!writeup.is_public || !writeup.is_approved) {
      const user = getUser(req);
      if (writeup.user_id !== user?.id) return res.status(404).json({ error: 'Writeup not found' });
    }
    await supabase.from('writeups').update({ view_count: (writeup.view_count || 0) + 1 }).eq('id', req.params.id);
    res.json(writeup);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/writeups/:id/like', requireAuth, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('writeup_likes').select('id').eq('writeup_id', req.params.id).eq('user_id', req.user.id).single();
    if (existing) return res.status(400).json({ error: 'Already liked' });

    await supabase.from('writeup_likes').insert({ writeup_id: req.params.id, user_id: req.user.id });
    const { data: writeup } = await supabase.from('writeups').select('like_count').eq('id', req.params.id).single();
    await supabase.from('writeups').update({ like_count: (writeup?.like_count || 0) + 1 }).eq('id', req.params.id);

    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ADMIN ====================
app.get('/admin/challenges', requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('challenges').select('*, hints(id, content, penalty), challenge_files(id, filename, file_size)').order('created_at', { ascending: false });
    res.json({ challenges: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/challenges', requireAdmin, async (req, res) => {
  try {
    const { title, description, category, difficulty, points, flag, flagType, minPoints, decay, scoringType, connectionInfo, maxAttempts, firstBloodPoints, isVisible, hints } = req.body;
    if (!title || !category || !flag || !points) return res.status(400).json({ error: 'Missing required fields' });

    let { data: comp } = await supabase.from('competitions').select('id').order('created_at', { ascending: false }).limit(1).single();
    if (!comp) {
      const { data: newComp } = await supabase.from('competitions').insert({ name: 'Default Competition', start_time: new Date().toISOString(), end_time: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), is_public: true }).select().single();
      comp = newComp;
    }

    const { data: challenge, error } = await supabase.from('challenges').insert({
      title, description, category, difficulty: difficulty || 'medium', points: Number(points), flag,
      flag_type: flagType || 'static', min_points: minPoints || 100, decay: decay || 50,
      scoring_type: scoringType || 'static', connection_info: connectionInfo,
      max_attempts: maxAttempts || 0, first_blood_points: firstBloodPoints || 0,
      is_visible: isVisible !== false, competition_id: comp.id
    }).select().single();

    if (error) return res.status(400).json({ error: error.message });

    if (hints && Array.isArray(hints)) {
      for (let i = 0; i < hints.length; i++) {
        await supabase.from('hints').insert({ challenge_id: challenge.id, content: hints[i].content, penalty: hints[i].penalty || 0, order_index: i });
      }
    }

    res.json({ challenge });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/admin/challenges/:id', requireAdmin, async (req, res) => {
  try {
    const allowed = ['title', 'description', 'category', 'difficulty', 'points', 'flag', 'flag_type', 'min_points', 'decay', 'scoring_type', 'connection_info', 'max_attempts', 'first_blood_points', 'is_visible'];
    const filtered = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)));
    const { data } = await supabase.from('challenges').update(filtered).eq('id', req.params.id).select().single();
    res.json({ challenge: data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/admin/challenges/:id', requireAdmin, async (req, res) => {
  try {
    await supabase.from('challenges').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('users').select('id, email, username, role, team_id, is_banned, is_hidden, created_at, last_login, login_count').order('created_at', { ascending: false });
    res.json({ users: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/admin/users/:id/role', requireAdmin, async (req, res) => {
  try {
    await supabase.from('users').update({ role: req.body.role }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/users/:id/ban', requireAdmin, async (req, res) => {
  try {
    await supabase.from('users').update({ is_banned: true, banned_at: new Date().toISOString(), banned_by: req.user.id, ban_reason: req.body.reason }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/users/:id/unban', requireAdmin, async (req, res) => {
  try {
    await supabase.from('users').update({ is_banned: false, banned_at: null, banned_by: null, ban_reason: null }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/announcements', requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('announcements').insert({ title: req.body.title, content: req.body.content, priority: req.body.priority || 'normal', created_by: req.user.id, is_active: true }).select().single();
    res.json({ announcement: data });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/writeups', requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('writeups').select('*, users(username), challenges(title)').order('created_at', { ascending: false });
    res.json({ writeups: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/writeups/:id/approve', requireAdmin, async (req, res) => {
  try {
    await supabase.from('writeups').update({ is_approved: true, is_public: true, approved_by: req.user.id }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== CONFIG ====================
app.get('/config', async (req, res) => {
  try {
    const { data } = await supabase.from('config').select('key, value');
    const config = {};
    for (const c of data || []) config[c.key] = c.value;
    res.json({ platformName: config.platform_name || 'CTF War', flagFormat: `${FLAG_PREFIXES[0]}{...}`, flagPrefix: FLAG_PREFIXES[0], registrationEnabled: config.registration_enabled !== 'false', teamMode: config.team_mode === 'true' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Start server
app.listen(PORT, () => console.log(`CTF War API running on port ${PORT}`));
