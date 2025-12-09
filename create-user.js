const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const supabase = createClient(
  'https://vfhilobaycsxwbjojgjc.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZmaGlsb2JheWNzeHdiam9qZ2pjIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzUzMTAwOCwiZXhwIjoyMDc5MTA3MDA4fQ.cjZaPWBs_t_ScE-A9p_Ew0YOSA29GLvgiMK6JcDJBvc'
);

async function createUser() {
  const hashedPassword = await bcrypt.hash('test123', 12);
  
  const { data: user, error } = await supabase.from('users').insert({
    id: uuidv4(),
    username: 'ctfplayer',
    email: 'ctfplayer@test.com',
    password_hash: hashedPassword,
    role: 'user',
    created_at: new Date().toISOString()
  }).select().single();
  
  if (error) console.log('Error:', error.message);
  else console.log('Created user:', user.username, user.email);
  
  // Create admin
  const adminHash = await bcrypt.hash('admin123', 12);
  const { data: admin, error: adminErr } = await supabase.from('users').insert({
    id: uuidv4(),
    username: 'admin',
    email: 'admin@ctfwar.com',
    password_hash: adminHash,
    role: 'admin',
    created_at: new Date().toISOString()
  }).select().single();
  
  if (adminErr) console.log('Admin error:', adminErr.message);
  else console.log('Created admin:', admin.username);
}

createUser();
