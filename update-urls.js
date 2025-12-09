const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(
  'https://vfhilobaycsxwbjojgjc.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZmaGlsb2JheWNzeHdiam9qZ2pjIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MzUzMTAwOCwiZXhwIjoyMDc5MTA3MDA4fQ.cjZaPWBs_t_ScE-A9p_Ew0YOSA29GLvgiMK6JcDJBvc'
);

const BASE_URL = 'https://ctf-war-1.onrender.com/files';

const challengeFiles = {
  'Caesar Cipher': `${BASE_URL}/crypto/caesar.txt`,
  'Base64 Basics': `${BASE_URL}/crypto/base64.txt`,
  'Hex to ASCII': `${BASE_URL}/crypto/hex.txt`,
  'XOR Encryption': `${BASE_URL}/crypto/xor.py`,
  'RSA Basics': `${BASE_URL}/crypto/rsa.py`,
  'Vigenere Breaker': `${BASE_URL}/crypto/vigenere.txt`,
  'Padding Oracle': `${BASE_URL}/crypto/padding_oracle.py`,
  'Buffer Overflow 101': `${BASE_URL}/pwn/buffer_overflow.c`,
  'Format Leak': `${BASE_URL}/pwn/format_string.c`,
  'Format Write': `${BASE_URL}/pwn/format_string.c`,
  'ROP Chain': `${BASE_URL}/pwn/rop_chain.py`,
  'Strings Hunt': `${BASE_URL}/reverse/strings_challenge.c`,
  'Python Bytecode': `${BASE_URL}/reverse/python_challenge.pyc.txt`,
  'SQL Injection 101': `${BASE_URL}/web/sqli_login.html`,
  'JWT Forgery': `${BASE_URL}/web/jwt_challenge.txt`,
  'File Signature': `${BASE_URL}/forensics/secret.txt`,
  'EXIF Secrets': `${BASE_URL}/forensics/exif_photo.txt`,
  'PCAP Hunt': `${BASE_URL}/forensics/pcap_analysis.txt`,
  'LSB Stego': `${BASE_URL}/stego/hidden_message.png`,
  'Audio Spectrum': `${BASE_URL}/stego/audio_spectrum.txt`,
  'Steghide': `${BASE_URL}/stego/steghide_image.txt`,
};

async function updateURLs() {
  const { data: all } = await supabase.from('challenges').select('*');

  let updated = 0;
  for (const [title, fileUrl] of Object.entries(challengeFiles)) {
    const challenge = all.find(c => c.title === title);
    if (!challenge) {
      console.log('Not found:', title);
      continue;
    }

    // Replace fake URLs with real ones
    let desc = challenge.description || '';

    // Replace various fake URL patterns
    desc = desc.replace(/https:\/\/files\.ctf-war\.com\/[^\s\)]+/g, fileUrl);
    desc = desc.replace(/\[.*?\]\(https:\/\/files\.ctf-war\.com\/[^\)]+\)/g, `[Download](${fileUrl})`);

    // If no URL was replaced, add download link
    if (!desc.includes(fileUrl) && !desc.includes('Download:')) {
      desc += `\n\n**Download:** [Challenge File](${fileUrl})`;
    }

    await supabase.from('challenges').update({ description: desc }).eq('id', challenge.id);
    console.log('Updated:', title);
    updated++;
  }

  console.log('\nTotal updated:', updated);
}

updateURLs();
