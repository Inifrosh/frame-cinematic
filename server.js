require('dotenv').config();
const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '1NI';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// ── AUTH ─────────────────────────────────────────

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

// Google OAuth — frontend sends Supabase access token, we create a server session
app.post('/api/auth/google', async (req, res) => {
  const { accessToken } = req.body;
  if (!accessToken) return res.status(400).json({ error: 'Access token required' });

  // Verify the Supabase JWT and get the user
  const { data: { user }, error } = await supabase.auth.getUser(accessToken);
  if (error || !user) return res.status(401).json({ error: 'Invalid or expired Google token' });

  const email = user.email;
  const displayName = user.user_metadata?.full_name || user.user_metadata?.name || '';

  // Look up existing user in our DB
  let { data: dbUser } = await supabase.from('users').select('*').ilike('email', email).maybeSingle();

  if (!dbUser) {
    // Build a clean username from display name or email
    let base = displayName
      ? displayName.replace(/[^a-zA-Z0-9_]/g, '').substring(0, 20)
      : email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '').substring(0, 20);
    if (!base) base = 'user';

    const adminEmail = (process.env.ADMIN_EMAIL || '').toLowerCase();
    const isAdmin = email.toLowerCase() === adminEmail;

    // Force admin username for admin email; otherwise use derived name
    let username = isAdmin ? ADMIN_USERNAME : base;
    if (!isAdmin) {
      const { data: taken } = await supabase.from('users').select('id').ilike('username', base).maybeSingle();
      if (taken) username = base + '_' + Math.floor(Math.random() * 9000 + 1000);
    }

    const { data: newUser, error: insertError } = await supabase.from('users').insert({
      id: uuidv4(), email, username,
      password: null, isAdmin, isVerified: true, verifyToken: null
    }).select().single();

    if (insertError) {
      console.error('User insert error:', insertError);
      return res.status(500).json({ error: 'Failed to create user account' });
    }
    dbUser = newUser;
  }

  const token = await createSession(dbUser.id, dbUser.username, dbUser.isAdmin);
  res.json({ token, username: dbUser.username, userId: dbUser.id, isAdmin: dbUser.isAdmin });
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

app.listen(PORT, () => {
  console.log(`🎬 FRAME running at http://localhost:${PORT}`);

  // ── KEEP-ALIVE: Ping self every 14 min to prevent Render free-tier sleep ──
  const RENDER_URL = 'https://frame-cinematic.onrender.com';
  setInterval(async () => {
    try {
      const res = await fetch(RENDER_URL);
      console.log(`[keep-alive] pinged ${RENDER_URL} — ${res.status}`);
    } catch (err) {
      console.error('[keep-alive] ping failed:', err.message);
    }
  }, 14 * 60 * 1000); // every 14 minutes
});