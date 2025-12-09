const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(
  'https://vfhilobaycsxwbjojgjc.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZmaGlsb2JheWNzeHdiam9qZ2pjIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzUzMTAwOCwiZXhwIjoyMDc5MTA3MDA4fQ.cjZaPWBs_t_ScE-A9p_Ew0YOSA29GLvgiMK6JcDJBvc'
);

async function updateRemaining() {
  const { data: all } = await supabase.from('challenges').select('*');

  const hasResources = (c) => {
    const d = c.description || '';
    return d.includes('Download:') ||
           d.includes('Connection:') ||
           d.includes('Target:') ||
           d.includes('nc ') ||
           d.includes('files.ctf-war.com') ||
           d.includes('**Given:**') ||
           d.includes('**Tool');
  };

  const needsUpdate = all.filter(c => !hasResources(c));

  console.log('Challenges needing updates:', needsUpdate.length);

  for (const c of needsUpdate) {
    let desc = c.description || c.title + ' challenge.';
    const port = 9000 + Math.floor(Math.random() * 100);

    if (c.category === 'crypto') {
      desc += `

**Tools:**
- [CyberChef](https://gchq.github.io/CyberChef/)
- [dcode.fr](https://www.dcode.fr/)
- Python with pycryptodome

**Download:** [challenge_files.zip](https://files.ctf-war.com/crypto/${c.title.replace(/\s+/g, '_').toLowerCase()}.zip)`;
    } else if (c.category === 'web') {
      desc += `

**Target:** [http://ctf-challenges.example.com/${c.title.replace(/\s+/g, '-').toLowerCase()}](http://ctf-challenges.example.com/${c.title.replace(/\s+/g, '-').toLowerCase()})

**Tools:**
- Browser DevTools (F12)
- Burp Suite
- curl/wget`;
    } else if (c.category === 'pwn') {
      desc += `

**Connection:**
\`\`\`bash
nc pwn.ctf-war.com ${port}
\`\`\`

**Download:** [${c.title.replace(/\s+/g, '_').toLowerCase()}](https://files.ctf-war.com/pwn/${c.title.replace(/\s+/g, '_').toLowerCase()})

**Tools:** pwntools, gdb, ghidra`;
    } else if (c.category === 'reverse') {
      desc += `

**Download:** [${c.title.replace(/\s+/g, '_').toLowerCase()}](https://files.ctf-war.com/reverse/${c.title.replace(/\s+/g, '_').toLowerCase()})

**Tools:**
- Ghidra / IDA Pro
- radare2 / rizin
- strings, objdump, gdb`;
    } else if (c.category === 'forensics') {
      desc += `

**Download:** [evidence.zip](https://files.ctf-war.com/forensics/${c.title.replace(/\s+/g, '_').toLowerCase()}.zip)

**Tools:**
- Autopsy / FTK Imager
- Volatility (memory)
- Wireshark (network)`;
    } else if (c.category === 'stego') {
      desc += `

**Download:** [challenge_file](https://files.ctf-war.com/stego/${c.title.replace(/\s+/g, '_').toLowerCase()})

**Tools:**
- steghide, zsteg, stegsolve
- binwalk, foremost
- Audacity (audio)`;
    } else if (c.category === 'misc') {
      desc += `

**Download:** [challenge.zip](https://files.ctf-war.com/misc/${c.title.replace(/\s+/g, '_').toLowerCase()}.zip)

**Hint:** Think outside the box!`;
    }

    await supabase.from('challenges').update({ description: desc }).eq('id', c.id);
    console.log('Updated:', c.title);
  }

  console.log('\nDone! Updated', needsUpdate.length, 'challenges');
}

updateRemaining();
