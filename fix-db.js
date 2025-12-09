const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  'https://vfhilobaycsxwbjojgjc.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZmaGlsb2JheWNzeHdiam9qZ2pjIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzUzMTAwOCwiZXhwIjoyMDc5MTA3MDA4fQ.cjZaPWBs_t_ScE-A9p_Ew0YOSA29GLvgiMK6JcDJBvc'
);

async function fixDB() {
  // Test connection by getting users
  const { data: users, error } = await supabase.from('users').select('id, username, email').limit(5);
  if (error) {
    console.log('Error:', error.message);
    return;
  }
  console.log('Existing users:', JSON.stringify(users, null, 2));
  
  // Create test user with bcrypt hash for "test123"
  const bcrypt = require('bcryptjs');
  const hashedPassword = await bcrypt.hash('test123', 12);
  const { v4: uuidv4 } = require('uuid');
  
  const { data: newUser, error: insertError } = await supabase.from('users').insert({
    id: uuidv4(),
    username: 'ctfplayer',
    email: 'ctfplayer@test.com',
    password: hashedPassword,
    role: 'user',
    score: 0,
    created_at: new Date().toISOString()
  }).select().single();
  
  if (insertError) {
    console.log('Insert error:', insertError.message);
  } else {
    console.log('Created user:', newUser.username);
  }
}

fixDB();
