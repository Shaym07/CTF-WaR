const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(
  'https://vfhilobaycsxwbjojgjc.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZmaGlsb2JheWNzeHdiam9qZ2pjIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzUzMTAwOCwiZXhwIjoyMDc5MTA3MDA4fQ.cjZaPWBs_t_ScE-A9p_Ew0YOSA29GLvgiMK6JcDJBvc'
);

async function checkSchema() {
  // Get one user with all columns
  const { data, error } = await supabase.from('users').select('*').limit(1);
  if (error) console.log('Error:', error);
  else console.log('User columns:', Object.keys(data[0] || {}));
  
  // Get one challenge with all columns
  const { data: ch, error: chErr } = await supabase.from('challenges').select('*').limit(1);
  if (chErr) console.log('Challenge Error:', chErr);
  else console.log('Challenge columns:', Object.keys(ch[0] || {}));
}
checkSchema();
