const { createClient } = require('@supabase/supabase-js');
const https = require('https');

const supabase = createClient(
  'https://vfhilobaycsxwbjojgjc.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZmaGlsb2JheWNzeHdiam9qZ2pjIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzUzMTAwOCwiZXhwIjoyMDc5MTA3MDA4fQ.cjZaPWBs_t_ScE-A9p_Ew0YOSA29GLvgiMK6JcDJBvc'
);

function apiCall(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method: opts.method || 'GET',
      headers: opts.headers || {}
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve({ raw: data }); }
      });
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function testAllFlags() {
  console.log('=== COMPREHENSIVE FLAG TEST ===\n');

  // Get all challenges with valid flags
  const { data: all } = await supabase.from('challenges').select('*');
  const validChallenges = all.filter(c => c.flag && c.flag.startsWith('WOW{'));

  console.log('Total challenges:', all.length);
  console.log('Challenges with valid WOW{ flags:', validChallenges.length);

  // Login
  const login = await apiCall('https://ctf-war-1.onrender.com/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'ctfplayer@test.com', password: 'test123' })
  });

  if (!login.token) {
    console.log('Login failed:', login);
    return;
  }

  console.log('\nLogged in as:', login.user.username, '(' + login.user.role + ')');
  console.log('\nTesting flag submissions for 15 random challenges...\n');

  // Pick 15 random challenges to test
  const shuffled = validChallenges.sort(() => Math.random() - 0.5);
  const testCases = shuffled.slice(0, 15);

  let passed = 0;
  let failed = 0;

  for (const c of testCases) {
    // Test correct flag
    const result = await apiCall(`https://ctf-war-1.onrender.com/challenges/${c.id}/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + login.token
      },
      body: JSON.stringify({ flag: c.flag })
    });

    const success = result.success || result.correct ||
                    (result.message && result.message.includes('orrect')) ||
                    (result.error && result.error.includes('already'));

    if (success) {
      console.log('✓', c.title, '(' + c.category + ')');
      passed++;
    } else {
      console.log('✗', c.title, '-', JSON.stringify(result));
      failed++;
    }
  }

  // Test wrong flag rejection
  console.log('\n--- Testing wrong flag rejection ---');
  const wrongResult = await apiCall(`https://ctf-war-1.onrender.com/challenges/${testCases[0].id}/submit`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + login.token
    },
    body: JSON.stringify({ flag: 'WOW{wrong_flag_test}' })
  });

  if (wrongResult.error || wrongResult.correct === false) {
    console.log('✓ Wrong flag correctly rejected');
  } else {
    console.log('✗ Wrong flag was accepted (BUG!):', wrongResult);
  }

  console.log('\n=== RESULTS ===');
  console.log('Passed:', passed);
  console.log('Failed:', failed);
  console.log('Success rate:', (passed / (passed + failed) * 100).toFixed(1) + '%');

  // Category breakdown
  console.log('\n=== CATEGORY SUMMARY ===');
  const cats = {};
  all.forEach(c => { cats[c.category] = (cats[c.category] || 0) + 1; });
  Object.entries(cats).sort((a,b) => b[1]-a[1]).forEach(([k,v]) => {
    console.log('  ' + k + ': ' + v + ' challenges');
  });
}

testAllFlags().catch(e => console.error('Error:', e.message));
