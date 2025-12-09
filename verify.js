const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(
  'https://vfhilobaycsxwbjojgjc.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZmaGlsb2JheWNzeHdiam9qZ2pjIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzUzMTAwOCwiZXhwIjoyMDc5MTA3MDA4fQ.cjZaPWBs_t_ScE-A9p_Ew0YOSA29GLvgiMK6JcDJBvc'
);

async function verify() {
  // Count total challenges
  const { data: all } = await supabase.from('challenges').select('*');
  console.log('=== CHALLENGE VERIFICATION ===\n');
  console.log('Total challenges:', all.length);

  // Count by category
  const cats = {};
  all.forEach(c => { cats[c.category] = (cats[c.category] || 0) + 1; });
  console.log('\nBy Category:');
  Object.entries(cats).sort((a,b) => b[1]-a[1]).forEach(([k,v]) => console.log('  ' + k + ': ' + v));

  // Check for challenges with missing flags
  const noFlag = all.filter(c => !c.flag);
  console.log('\nChallenges missing flags:', noFlag.length);
  if (noFlag.length > 0) {
    noFlag.slice(0,5).forEach(c => console.log('  -', c.title));
  }

  // Check for challenges with invalid flag format
  const badFlag = all.filter(c => c.flag && !c.flag.startsWith('WOW{'));
  console.log('Challenges with wrong flag format:', badFlag.length);
  if (badFlag.length > 0) {
    badFlag.slice(0,5).forEach(c => console.log('  -', c.title, ':', c.flag));
  }

  // Sample some flags
  console.log('\nSample challenges with valid flags:');
  const validFlags = all.filter(c => c.flag && c.flag.startsWith('WOW{'));
  validFlags.slice(0,10).forEach(c => {
    console.log('  ✓ ' + c.title + ' -> ' + c.flag);
  });

  console.log('\n=== FLAG SUBMISSION TEST ===');
  // Now test flag submission via API
  const testCases = validFlags.slice(0, 5);

  // Login first
  const https = require('https');

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

  console.log('Logged in as admin');

  // Test submitting flags
  for (const c of testCases) {
    // Submit correct flag
    const result = await apiCall(`https://ctf-war-1.onrender.com/challenges/${c.id}/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + login.token
      },
      body: JSON.stringify({ flag: c.flag })
    });

    if (result.success || result.correct || result.message?.includes('orrect') || result.error?.includes('already')) {
      console.log('  ✓', c.title, '- Flag accepted');
    } else {
      console.log('  ✗', c.title, '- FAILED:', JSON.stringify(result));
    }
  }

  console.log('\n=== ALL TESTS COMPLETE ===');
}

verify().catch(e => console.error('Error:', e.message));
