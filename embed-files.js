const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');

const supabase = createClient(
  'https://vfhilobaycsxwbjojgjc.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZmaGlsb2JheWNzeHdiam9qZ2pjIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzUzMTAwOCwiZXhwIjoyMDc5MTA3MDA4fQ.cjZaPWBs_t_ScE-A9p_Ew0YOSA29GLvgiMK6JcDJBvc'
);

const fileMap = {
  'Caesar Cipher': 'crypto/caesar.txt',
  'Base64 Basics': 'crypto/base64.txt',
  'Hex to ASCII': 'crypto/hex.txt',
  'XOR Encryption': 'crypto/xor.py',
  'RSA Basics': 'crypto/rsa.py',
  'Vigenere Breaker': 'crypto/vigenere.txt',
  'Padding Oracle': 'crypto/padding_oracle.py',
  'Buffer Overflow 101': 'pwn/buffer_overflow.c',
  'Format Leak': 'pwn/format_string.c',
  'Format Write': 'pwn/format_string.c',
  'ROP Chain': 'pwn/rop_chain.py',
  'Strings Hunt': 'reverse/strings_challenge.c',
  'Python Bytecode': 'reverse/python_challenge.pyc.txt',
  'SQL Injection 101': 'web/sqli_login.html',
  'JWT Forgery': 'web/jwt_challenge.txt',
  'File Signature': 'forensics/secret.txt',
  'EXIF Secrets': 'forensics/exif_photo.txt',
  'PCAP Hunt': 'forensics/pcap_analysis.txt',
  'LSB Stego': 'stego/hidden_message.png',
  'Audio Spectrum': 'stego/audio_spectrum.txt',
  'Steghide': 'stego/steghide_image.txt',
};

async function embedFiles() {
  const baseDir = '/workspace/ctf-war-render/public/files';
  const { data: challenges } = await supabase.from('challenges').select('*');

  let updated = 0;

  for (const [title, filePath] of Object.entries(fileMap)) {
    const challenge = challenges.find(c => c.title === title);
    if (!challenge) {
      console.log('Challenge not found:', title);
      continue;
    }

    const fullPath = path.join(baseDir, filePath);
    if (!fs.existsSync(fullPath)) {
      console.log('File not found:', fullPath);
      continue;
    }

    const content = fs.readFileSync(fullPath, 'utf-8');
    const ext = path.extname(filePath).slice(1);
    const lang = ext === 'py' ? 'python' : ext === 'c' ? 'c' : ext === 'html' ? 'html' : '';

    // Add file content to description
    let desc = challenge.description || '';

    // Remove old download links
    desc = desc.replace(/\*\*Download:\*\*.*?\n/g, '');
    desc = desc.replace(/\[Download\].*?\n/g, '');

    // Add embedded file content
    desc += `\n\n---\n\n**📁 Challenge File (${filePath}):**\n\n\`\`\`${lang}\n${content}\n\`\`\``;

    await supabase.from('challenges').update({ description: desc }).eq('id', challenge.id);
    console.log('Embedded:', title);
    updated++;
  }

  console.log('\nTotal embedded:', updated);
}

embedFiles();
