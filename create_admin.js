require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha256').toString('hex');
  return `${salt}:${hash}`;
}

async function createAdmin() {
  const email = 'admin@frame.com';
  const username = 'Inioluwa';
  const password = 'frameadmin';

  // Check if exists
  const { data: existing } = await supabase.from('users').select('*').eq('email', email);
  if (existing && existing.length > 0) {
    // Delete existing to recreate cleanly
    await supabase.from('users').delete().eq('email', email);
  }

  const { error } = await supabase.from('users').insert({
    id: uuidv4(),
    email,
    username,
    password: hashPassword(password),
    "isAdmin": true,
    "isVerified": true,
    "verifyToken": null
  });

  if (error) {
    console.error("Error creating admin:", error);
  } else {
    console.log(`✅ Admin created successfully! Email: ${email} | Password: ${password}`);
  }
}

createAdmin();
