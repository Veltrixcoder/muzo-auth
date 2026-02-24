import express from 'express';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';
import { OAuth2Client } from 'google-auth-library'; // Added

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// ==========================================
// CONFIGURATION
// ==========================================

// Your provided Web Client ID
const GOOGLE_CLIENT_ID = '1023316916513-0ceeamcb82h4c5j27p7pnrbq0fl9udhd.apps.googleusercontent.com';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

const dbConfig = {
  host: process.env.DB_HOST || 'gateway01.ap-southeast-1.prod.aws.tidbcloud.com',
  port: parseInt(process.env.DB_PORT || '4000'),
  user: process.env.DB_USER || '4WX16yxhR4aVTvZ.root',
  password: process.env.DB_PASSWORD || 'WUuvAEq1GNA2F4nV',
  database: 'test',
  ssl: {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true
  },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// ==========================================
// IN-MEMORY CACHE LAYER
// ==========================================

const GlobalCache = {
  users: new Map(),
  history: new Map(),
  favorites: new Map(),
  subscriptions: new Map(),
  playlists: new Map(),
  
  initUser(userId) {
    if (!this.history.has(userId)) this.history.set(userId, []);
    if (!this.favorites.has(userId)) this.favorites.set(userId, []);
    if (!this.subscriptions.has(userId)) this.subscriptions.set(userId, []);
    if (!this.playlists.has(userId)) this.playlists.set(userId, new Map());
  }
};

// ==========================================
// DATABASE & CACHE INITIALIZATION
// ==========================================

let pool;

async function initSystem() {
  try {
    pool = mysql.createPool(dbConfig);
    console.log('🔌 Database connected');

    const connection = await pool.getConnection();
    try {
      // Basic table creation - ensure you ran the ALTER TABLE SQL provided separately!
      await connection.query(`
        CREATE TABLE IF NOT EXISTS users (
          id INT AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(50) UNIQUE NOT NULL,
          email VARCHAR(100) UNIQUE NOT NULL,
          password VARCHAR(255) NULL, 
          google_id VARCHAR(255) UNIQUE DEFAULT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      await createAllTables(connection);
    } finally {
      connection.release();
    }

    console.log('🔥 Warming up cache...');
    await loadDataToCache();
    console.log('✅ Cache fully loaded. Server ready.');

  } catch (err) {
    console.error('❌ Initialization failed:', err);
    process.exit(1);
  }
}

async function createAllTables(conn) {
    await conn.query(`CREATE TABLE IF NOT EXISTS history (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, song_data JSON, added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await conn.query(`CREATE TABLE IF NOT EXISTS favorites (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, song_data JSON, added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await conn.query(`CREATE TABLE IF NOT EXISTS subscriptions (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, channel_data JSON, added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await conn.query(`CREATE TABLE IF NOT EXISTS playlists (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, playlist_name VARCHAR(100), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await conn.query(`CREATE TABLE IF NOT EXISTS playlist_songs (id INT AUTO_INCREMENT PRIMARY KEY, playlist_id INT, song_data JSON, added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
}

async function loadDataToCache() {
  const [users] = await pool.query('SELECT * FROM users');
  users.forEach(u => GlobalCache.users.set(u.id, u));

  const [history] = await pool.query('SELECT * FROM history ORDER BY added_at DESC');
  history.forEach(h => {
    GlobalCache.initUser(h.user_id);
    GlobalCache.history.get(h.user_id).push({ ...h.song_data, added_at: h.added_at, db_id: h.id });
  });

  const [favorites] = await pool.query('SELECT * FROM favorites ORDER BY added_at DESC');
  favorites.forEach(f => {
    GlobalCache.initUser(f.user_id);
    GlobalCache.favorites.get(f.user_id).push({ ...f.song_data, added_at: f.added_at, db_id: f.id });
  });

  const [subs] = await pool.query('SELECT * FROM subscriptions ORDER BY added_at DESC');
  subs.forEach(s => {
    GlobalCache.initUser(s.user_id);
    GlobalCache.subscriptions.get(s.user_id).push({ ...s.channel_data, added_at: s.added_at, db_id: s.id });
  });

  const [playlists] = await pool.query('SELECT * FROM playlists');
  const [playlistSongs] = await pool.query('SELECT * FROM playlist_songs ORDER BY added_at ASC');

  playlists.forEach(p => {
    GlobalCache.initUser(p.user_id);
    const pObj = { ...p, songs: [] };
    GlobalCache.playlists.get(p.user_id).set(p.id, pObj);
  });

  playlistSongs.forEach(ps => {
    for (let [userId, userPlaylists] of GlobalCache.playlists) {
      if (userPlaylists.has(ps.playlist_id)) {
        userPlaylists.get(ps.playlist_id).songs.push({ ...ps.song_data, added_at: ps.added_at, db_id: ps.id });
        break;
      }
    }
  });
}

const backgroundSync = (promise, context) => {
  promise.catch(err => {
    console.error(`⚠️ Background Sync Failed [${context}]:`, err);
  });
};

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    GlobalCache.initUser(user.userId);
    next();
  });
}

// ==========================================
// AUTH ROUTES
// ==========================================

// --- NEW GOOGLE AUTH ROUTE ---
app.post('/api/auth/google', async (req, res) => {
  const { idToken } = req.body;

  try {
    // 1. Verify Token
    const ticket = await client.verifyIdToken({
      idToken: idToken,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, sub: googleId, name } = payload;

    // 2. Check Cache
    let user = null;
    for (let [id, u] of GlobalCache.users) {
      if (u.email === email) {
        user = u;
        break;
      }
    }

    // 3. Check DB if not in cache
    if (!user) {
      const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      if (rows.length > 0) user = rows[0];
    }

    // 4. Register or Link
    if (!user) {
      // NEW USER
      const username = name.replace(/\s+/g, '') + Math.floor(Math.random() * 1000);
      const [result] = await pool.query(
        'INSERT INTO users (username, email, google_id) VALUES (?, ?, ?)',
        [username, email, googleId]
      );
      
      user = { id: result.insertId, username, email, google_id: googleId, created_at: new Date() };
      
      // Update Cache
      GlobalCache.users.set(user.id, user);
      GlobalCache.initUser(user.id);
    } else if (!user.google_id) {
      // EXISTING USER (Link Google ID)
      await pool.query('UPDATE users SET google_id = ? WHERE id = ?', [googleId, user.id]);
      user.google_id = googleId;
      GlobalCache.users.set(user.id, user); // Update cache entry
    }

    // 5. Generate Token
    const token = jwt.sign(
      { userId: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '7000000000d' }
    );

    res.json({
      message: 'Google Login successful',
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });

  } catch (error) {
    console.error('Google Auth Error:', error);
    res.status(401).json({ error: 'Invalid Google Token' });
  }
});

// --- STANDARD LOGIN ---
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  let user = null;
  for (let [id, u] of GlobalCache.users) {
    if (u.email === email) {
      user = u;
      break;
    }
  }

  if (!user) {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length > 0) user = rows[0];
  }

  // Check if user exists AND has a password (google users might not have one)
  if (!user || !user.password || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7000000000d' });
  res.json({ message: 'Login successful', token, user: { id: user.id, username: user.username, email: user.email } });
});

app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);
    const newUser = { id: result.insertId, username, email, password: hashedPassword, created_at: new Date() };

    GlobalCache.users.set(newUser.id, newUser);
    GlobalCache.initUser(newUser.id);

    const token = jwt.sign({ userId: newUser.id, username, email }, JWT_SECRET, { expiresIn: '70000000000000d' });
    res.status(201).json({ message: 'User created', token, user: { id: newUser.id, username, email } });
  } catch (error) {
    res.status(500).json({ error: 'Creation failed' });
  }
});

// ==========================================
// DATA ROUTES
// ==========================================

app.get('/api/user/data', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const history = GlobalCache.history.get(userId) || [];
  const favorites = GlobalCache.favorites.get(userId) || [];
  const subscriptions = GlobalCache.subscriptions.get(userId) || [];
  const playlistsMap = GlobalCache.playlists.get(userId) || new Map();
  
  const playlists = Array.from(playlistsMap.values()).map(p => ({
    id: p.id,
    name: p.playlist_name,
    created_at: p.created_at,
    songs: p.songs,
    song_count: p.songs.length
  }));

  res.json({
    source: 'cache',
    user: { id: userId, username: req.user.username, email: req.user.email },
    stats: { history_count: history.length, favorites_count: favorites.length, playlists_count: playlists.length },
    history, favorites, subscriptions, playlists
  });
});

app.post('/api/history', authenticateToken, (req, res) => {
  const songData = req.body;
  const userId = req.user.userId;
  const addedAt = new Date();

  const historyItem = { ...songData, added_at: addedAt, db_id: 'temp_' + Date.now() };
  GlobalCache.history.get(userId).unshift(historyItem);
  res.status(201).json({ message: 'Added to history' });

  backgroundSync(
    pool.query('INSERT INTO history (user_id, song_data, added_at) VALUES (?, ?, ?)', [userId, JSON.stringify(songData), addedAt]),
    'AddToHistory'
  );
});

app.delete('/api/history/:videoId', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const videoId = req.params.videoId;

  const historyList = GlobalCache.history.get(userId);
  const initialLength = historyList.length;
  const filtered = historyList.filter(item => item.videoId !== videoId);
  GlobalCache.history.set(userId, filtered);

  if (filtered.length === initialLength) return res.status(404).json({ error: 'Not found' });
  res.json({ message: 'Removed from history' });

  backgroundSync(
    pool.query('DELETE FROM history WHERE user_id = ? AND JSON_EXTRACT(song_data, "$.videoId") = ?', [userId, videoId]),
    'DeleteHistory'
  );
});

app.post('/api/favorites', authenticateToken, (req, res) => {
  const songData = req.body;
  const userId = req.user.userId;
  const addedAt = new Date();

  GlobalCache.favorites.get(userId).unshift({ ...songData, added_at: addedAt });
  res.status(201).json({ message: 'Added to favorites' });

  backgroundSync(
    pool.query('INSERT INTO favorites (user_id, song_data, added_at) VALUES (?, ?, ?)', [userId, JSON.stringify(songData), addedAt]),
    'AddFavorite'
  );
});

app.delete('/api/favorites/:videoId', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const videoId = req.params.videoId;

  const list = GlobalCache.favorites.get(userId);
  GlobalCache.favorites.set(userId, list.filter(item => item.videoId !== videoId));
  res.json({ message: 'Removed from favorites' });

  backgroundSync(
    pool.query('DELETE FROM favorites WHERE user_id = ? AND JSON_EXTRACT(song_data, "$.videoId") = ?', [userId, videoId]),
    'DeleteFavorite'
  );
});

app.post('/api/playlists/:name', authenticateToken, async (req, res) => {
  const songData = req.body;
  const playlistName = req.params.name;
  const userId = req.user.userId;

  try {
    let playlistId;
    let userPlaylists = GlobalCache.playlists.get(userId);
    let cachedPlaylist = Array.from(userPlaylists.values()).find(p => p.playlist_name === playlistName);

    if (!cachedPlaylist) {
        const [result] = await pool.query('INSERT INTO playlists (user_id, playlist_name) VALUES (?, ?)', [userId, playlistName]);
        playlistId = result.insertId;
        cachedPlaylist = { id: playlistId, user_id: userId, playlist_name: playlistName, created_at: new Date(), songs: [] };
        userPlaylists.set(playlistId, cachedPlaylist);
    } else {
        playlistId = cachedPlaylist.id;
    }

    cachedPlaylist.songs.push({ ...songData, added_at: new Date() });
    res.status(201).json({ message: 'Added to playlist' });

    backgroundSync(
        pool.query('INSERT INTO playlist_songs (playlist_id, song_data) VALUES (?, ?)', [playlistId, JSON.stringify(songData)]),
        'AddPlaylistSong'
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error processing request' });
  }
});

initSystem().then(() => {
  app.listen(7860, () => {
    console.log('🚀 Server running on port 7860 (Google Auth Enabled)');
  });
});
