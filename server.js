require('dotenv').config();
const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'Inioluwa';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// ── MAILER ───────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

async function sendMail(to, subject, html) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS || process.env.EMAIL_USER.includes('your_gmail')) {
    console.log('\n--- EMAIL CONFIG MISSING: MOCKING EMAIL ---');
    console.log(`To: ${to}\nSubject: ${subject}\nBody: ${html}`);
    console.log('-------------------------------------------\n');
    return;
  }
  return transporter.sendMail({ from: `"FRAME" <${process.env.EMAIL_USER}>`, to, subject, html });
}

// ── AUTH ─────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha256').toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored) return false;
  const parts = stored.split(':');
  if(parts.length !== 2) return false;
  const [salt, hash] = parts;
  return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha256').toString('hex') === hash;
}

async function createSession(userId, username, isAdmin) {
  const token = crypto.randomBytes(32).toString('hex');
  const exp = Date.now() + 7 * 24 * 60 * 60 * 1000;
  await supabase.from('sessions').insert({ token, userId, username, isAdmin, exp });
  return token;
}

async function getSession(token) {
  if (!token) return null;
  const { data: s } = await supabase.from('sessions').select('*').eq('token', token).single();
  if (!s) return null;
  if (Date.now() > s.exp) { 
    await supabase.from('sessions').delete().eq('token', token);
    return null; 
  }
  return s;
}

async function authMiddleware(req, res, next) {
  const s = await getSession(req.headers['x-auth-token']);
  if (!s) return res.status(401).json({ error: 'Not authenticated' });
  req.user = s; next();
}

// ── STORAGE ───────────────────────────────────────
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'thumbnail') return cb(null, true);
    const allowed = /mp4|mov|avi|mkv|webm|m4v/i;
    if (allowed.test(path.extname(file.originalname))) return cb(null, true);
    cb(new Error('Only video files are allowed'));
  }
});

// ── MIDDLEWARE ────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH ROUTES ───────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password) return res.status(400).json({ error: 'Email, username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  
  const { data: existingUser } = await supabase.from('users').select('id, email, username').or(`email.ilike.${email},username.ilike.${username}`);
  if (existingUser && existingUser.length > 0) {
    if (existingUser.some(u => u.email.toLowerCase() === email.toLowerCase())) return res.status(400).json({ error: 'Email already registered' });
    return res.status(400).json({ error: 'Username already taken' });
  }
  
  const isAdmin = username.toLowerCase() === ADMIN_USERNAME.toLowerCase();
  const verifyToken = crypto.randomBytes(20).toString('hex');
  
  await supabase.from('users').insert({ 
    id: uuidv4(), email, username, password: hashPassword(password), 
    isAdmin, isVerified: isAdmin, verifyToken: isAdmin ? null : verifyToken
  });
  
  if (!isAdmin) {
    const host = req.get('host') || `localhost:${PORT}`;
    const protocol = req.get('x-forwarded-proto') || req.protocol || 'http';
    const verifyUrl = `${protocol}://${host}/verify?token=${verifyToken}`;
    await sendMail(email, 'Verify your FRAME account', `<p>Click <a href="${verifyUrl}">here</a> to verify your account.</p>`);
    res.json({ success: true, message: 'Account created! Please check your email to verify before logging in.' });
  } else {
    res.json({ success: true, message: 'Admin account created successfully! You can now log in.' });
  }
});

app.get('/verify', async (req, res) => {
  const { token } = req.query;
  const { data: user } = await supabase.from('users').select('*').eq('verifyToken', token).single();
  if (!user) return res.status(400).send('Invalid or expired verification link.');
  
  await supabase.from('users').update({ isVerified: true, verifyToken: null }).eq('id', user.id);
  res.send('<div style="font-family:monospace;text-align:center;margin-top:50px">Account verified! You can now close this window and log in on the main site.</div>');
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  
  const { data: user } = await supabase.from('users').select('*').or(`email.ilike.${email},username.ilike.${email}`).single();
  if (!user || !verifyPassword(password, user.password)) return res.status(401).json({ error: 'Invalid email or password' });
  if (user.email && !user.isVerified) return res.status(403).json({ error: 'Please verify your email before logging in.' });
  
  const token = await createSession(user.id, user.username, user.isAdmin);
  res.json({ token, username: user.username, userId: user.id, isAdmin: user.isAdmin });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const { data: user } = await supabase.from('users').select('*').ilike('email', email).single();
  if (user) {
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExp = Date.now() + 3600000;
    await supabase.from('users').update({ resetToken, resetTokenExp }).eq('id', user.id);
    
    const host = req.get('host') || `localhost:${PORT}`;
    const protocol = req.protocol || 'http';
    const resetUrl = `${protocol}://${host}/?reset=${resetToken}`;
    await sendMail(email, 'FRAME Password Reset', `<p>Click <a href="${resetUrl}">here</a> to reset your password.</p>`);
  }
  res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  
  const { data: user } = await supabase.from('users').select('*').eq('resetToken', token).single();
  if (!user || Date.now() > user.resetTokenExp) return res.status(400).json({ error: 'Invalid or expired reset link' });
  
  await supabase.from('users').update({ password: hashPassword(password), resetToken: null, resetTokenExp: null }).eq('id', user.id);
  res.json({ success: true, message: 'Password has been reset. You can now login.' });
});

app.post('/api/auth/logout', async (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) await supabase.from('sessions').delete().eq('token', token);
  res.json({ success: true });
});

app.get('/api/auth/me', async (req, res) => {
  const s = await getSession(req.headers['x-auth-token']);
  if (!s) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ username: s.username, userId: s.userId, isAdmin: s.isAdmin });
});

// ── VIDEO ROUTES ──────────────────────────────────

app.get('/api/portfolio', async (req, res) => {
  let query = supabase.from('videos').select('*').eq('isPortfolio', true).order('created_at', { ascending: false });
  if (req.query.category && req.query.category !== 'all') query = query.eq('category', req.query.category);
  
  const { data: videos } = await query;
  res.json(videos || []);
});

app.get('/api/storage', authMiddleware, async (req, res) => {
  let query = supabase.from('videos').select('*').eq('userId', req.user.userId).eq('isPortfolio', false).order('created_at', { ascending: false });
  if (req.query.category && req.query.category !== 'all') query = query.eq('category', req.query.category);
  
  const { data: videos } = await query;
  res.json(videos || []);
});

app.get('/api/share/:shareId', async (req, res) => {
  const { data: video } = await supabase.from('videos').select('*').eq('shareId', req.params.shareId).eq('isPortfolio', true).single();
  if (!video) return res.status(404).json({ error: 'Not found' });
  res.json(video);
});

app.post('/api/videos', authMiddleware, upload.fields([{ name: 'video', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), async (req, res) => {
  const videoFile = req.files?.video?.[0];
  const thumbFile = req.files?.thumbnail?.[0];
  if (!videoFile) return res.status(400).json({ error: 'No video file provided' });
  
  const { title, category, description } = req.body;
  if (!title || !category) return res.status(400).json({ error: 'Title and category required' });
  
  const id = uuidv4();
  const shareId = uuidv4().replace(/-/g, '').substring(0, 12);
  
  const videoExt = path.extname(videoFile.originalname).toLowerCase() || '.mp4';
  const videoFilename = `${id}${videoExt}`;
  
  // Upload Video to Supabase Storage
  const { error: vidError } = await supabase.storage.from('media').upload(videoFilename, videoFile.buffer, {
    contentType: videoFile.mimetype,
    upsert: true
  });
  if (vidError) return res.status(500).json({ error: 'Error uploading video to storage' });
  
  let thumbFilename = null;
  if (thumbFile) {
    const thumbExt = path.extname(thumbFile.originalname).toLowerCase() || '.jpg';
    thumbFilename = `${id}_thumb${thumbExt}`;
    await supabase.storage.from('media').upload(thumbFilename, thumbFile.buffer, {
      contentType: thumbFile.mimetype,
      upsert: true
    });
  }
  
  const entry = {
    id, shareId, title, category,
    description: description || '',
    filename: videoFilename,
    thumbnail: thumbFilename,
    size: videoFile.size,
    userId: req.user.userId,
    username: req.user.username,
    isPortfolio: req.user.isAdmin,
    created_at: new Date().toISOString()
  };
  
  const { error: dbError } = await supabase.from('videos').insert(entry);
  if (dbError) return res.status(500).json({ error: 'Error saving video metadata' });
  
  res.json(entry);
});

app.delete('/api/videos/:id', authMiddleware, async (req, res) => {
  const { data: video } = await supabase.from('videos').select('*').eq('id', req.params.id).single();
  if (!video) return res.status(404).json({ error: 'Not found' });
  if (video.userId !== req.user.userId) return res.status(403).json({ error: 'Not your video' });
  
  // Delete from Storage
  const filesToDelete = [video.filename];
  if (video.thumbnail) filesToDelete.push(video.thumbnail);
  await supabase.storage.from('media').remove(filesToDelete);
  
  // Delete from DB
  await supabase.from('videos').delete().eq('id', req.params.id);
  
  res.json({ success: true });
});

app.post('/api/videos/batch-delete', authMiddleware, async (req, res) => {
  const { ids } = req.body;
  if (!ids || !Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'Invalid payload' });
  
  // Fetch videos to verify ownership
  const { data: videos } = await supabase.from('videos').select('*').in('id', ids);
  if (!videos) return res.status(404).json({ error: 'Not found' });
  
  // Filter only videos owned by the user (or if admin, they own everything in portfolio)
  // Wait, if admin, they can delete anything. If user, they can only delete their own.
  const toDelete = req.user.isAdmin ? videos : videos.filter(v => v.userId === req.user.userId);
  const finalIds = toDelete.map(v => v.id);
  if (finalIds.length === 0) return res.json({ success: true, deleted: 0 });
  
  // Delete from Storage
  const filesToDelete = [];
  toDelete.forEach(v => {
    filesToDelete.push(v.filename);
    if (v.thumbnail) filesToDelete.push(v.thumbnail);
  });
  if (filesToDelete.length > 0) {
    await supabase.storage.from('media').remove(filesToDelete);
  }
  
  // Delete from DB
  await supabase.from('videos').delete().in('id', finalIds);
  
  res.json({ success: true, deleted: finalIds.length });
});

app.get('/video/:filename', async (req, res) => {
  const token = req.headers['x-auth-token'] || req.query.token;
  const session = await getSession(token);
  
  const { data: video } = await supabase.from('videos').select('*').eq('filename', req.params.filename).single();
  if (!video && !req.params.filename.includes('_thumb')) return res.status(404).send('Not found');
  
  if (video && !video.isPortfolio) {
    if (!session) return res.status(401).send('Unauthorized');
    if (video.userId !== session.userId) return res.status(403).send('Forbidden');
  }
  
  // Redirect to Supabase Storage public URL
  const { data: publicUrlData } = supabase.storage.from('media').getPublicUrl(req.params.filename);
  res.redirect(publicUrlData.publicUrl);
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`🎬 FRAME running at http://localhost:${PORT}`));