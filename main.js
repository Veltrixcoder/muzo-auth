import express from 'express';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// ==========================================
// CONFIGURATION
// ==========================================

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
  // Connection pool settings to handle background tasks
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// ==========================================
// IN-MEMORY CACHE LAYER
// ==========================================

/**
 * The GlobalCache stores all DB data in memory for instant access.
 * Structure:
 * {
 * users: { [id]: { ...userObj } },
 * history: { [userId]: [ ...songs ] },
 * favorites: { [userId]: [ ...songs ] },
 * subscriptions: { [userId]: [ ...channels ] },
 * playlists: { [userId]: { [playlistId]: { ...data, songs: [] } } }
 * }
 */
const GlobalCache = {
  users: new Map(),
  history: new Map(),
  favorites: new Map(),
  subscriptions: new Map(),
  playlists: new Map(),
  
  // Helper to ensure user buckets exist
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
    // 1. Connect to DB
    pool = mysql.createPool(dbConfig);
    console.log('🔌 Database connected');

    // 2. Initialize Tables (if not exist)
    const connection = await pool.getConnection();
    try {
      await connection.query(`
        CREATE TABLE IF NOT EXISTS users (
          id INT AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(50) UNIQUE NOT NULL,
          email VARCHAR(100) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      // ... (Rest of tables: history, playlists, etc. - simplified for brevity but assume same schema)
      // Ensure all your CREATE TABLE statements from the original code are here
      await createAllTables(connection);
    } finally {
      connection.release();
    }

    // 3. WARM UP CACHE (Load EVERYTHING from DB)
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
  // Load Users
  const [users] = await pool.query('SELECT * FROM users');
  users.forEach(u => GlobalCache.users.set(u.id, u));

  // Load History
  const [history] = await pool.query('SELECT * FROM history ORDER BY added_at DESC');
  history.forEach(h => {
    GlobalCache.initUser(h.user_id);
    GlobalCache.history.get(h.user_id).push({ ...h.song_data, added_at: h.added_at, db_id: h.id });
  });

  // Load Favorites
  const [favorites] = await pool.query('SELECT * FROM favorites ORDER BY added_at DESC');
  favorites.forEach(f => {
    GlobalCache.initUser(f.user_id);
    GlobalCache.favorites.get(f.user_id).push({ ...f.song_data, added_at: f.added_at, db_id: f.id });
  });

  // Load Subscriptions
  const [subs] = await pool.query('SELECT * FROM subscriptions ORDER BY added_at DESC');
  subs.forEach(s => {
    GlobalCache.initUser(s.user_id);
    GlobalCache.subscriptions.get(s.user_id).push({ ...s.channel_data, added_at: s.added_at, db_id: s.id });
  });

  // Load Playlists
  const [playlists] = await pool.query('SELECT * FROM playlists');
  const [playlistSongs] = await pool.query('SELECT * FROM playlist_songs ORDER BY added_at ASC');

  playlists.forEach(p => {
    GlobalCache.initUser(p.user_id);
    const pObj = { ...p, songs: [] };
    GlobalCache.playlists.get(p.user_id).set(p.id, pObj);
  });

  playlistSongs.forEach(ps => {
    // Find which user owns this playlist
    for (let [userId, userPlaylists] of GlobalCache.playlists) {
      if (userPlaylists.has(ps.playlist_id)) {
        userPlaylists.get(ps.playlist_id).songs.push({ ...ps.song_data, added_at: ps.added_at, db_id: ps.id });
        break;
      }
    }
  });
}

// ==========================================
// BACKGROUND SYNC HELPER
// ==========================================

/**
 * Executes a DB operation asynchronously WITHOUT blocking the HTTP response.
 * If DB fails, it logs error (in production, you'd want a retry queue or rollback mechanism).
 */
const backgroundSync = (promise, context) => {
  promise.catch(err => {
    console.error(`⚠️ Background Sync Failed [${context}]:`, err);
    // TODO: Implement rollback logic here if strict consistency is needed
  });
};

// ==========================================
// MIDDLEWARE
// ==========================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    // Ensure cache bucket exists for this user
    GlobalCache.initUser(user.userId);
    next();
  });
}

// ==========================================
// ROUTES
// ==========================================

// --- Auth (Direct DB access required for consistency) ---

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  // 1. Try Cache First for User Lookup (Super fast login)
  let user = null;
  for (let [id, u] of GlobalCache.users) {
    if (u.email === email) {
      user = u;
      break;
    }
  }

  // Fallback to DB if not in cache (edge case: newly created)
  if (!user) {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length > 0) user = rows[0];
  }

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7000000000d' });
  
  res.json({ message: 'Login successful', token, user: { id: user.id, username: user.username, email: user.email } });
});

app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password } = req.body;
  
  // Validation checks... (omitted for brevity)

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // DB INSERT (Must wait for this to get ID)
    const [result] = await pool.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);
    const newUser = { id: result.insertId, username, email, password: hashedPassword, created_at: new Date() };

    // Update Cache
    GlobalCache.users.set(newUser.id, newUser);
    GlobalCache.initUser(newUser.id);

    const token = jwt.sign({ userId: newUser.id, username, email }, JWT_SECRET, { expiresIn: '70000000000000d' });
    res.status(201).json({ message: 'User created', token, user: { id: newUser.id, username, email } });
  } catch (error) {
    res.status(500).json({ error: 'Creation failed' });
  }
});

// --- User Data (Served entirely from Cache) ---

app.get('/api/user/data', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  
  // INSTANT RESPONSE FROM MEMORY
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
    source: 'cache', // Debug flag to prove it's cached
    user: { id: userId, username: req.user.username, email: req.user.email },
    stats: {
        history_count: history.length,
        favorites_count: favorites.length,
        playlists_count: playlists.length
    },
    history,
    favorites,
    subscriptions,
    playlists
  });
});

// --- History (Write-Behind) ---

app.post('/api/history', authenticateToken, (req, res) => {
  const songData = req.body;
  const userId = req.user.userId;
  const addedAt = new Date();

  // 1. UPDATE CACHE IMMEDIATELY
  const historyItem = { ...songData, added_at: addedAt, db_id: 'temp_' + Date.now() }; // Temp ID until DB sync
  GlobalCache.history.get(userId).unshift(historyItem); // Add to top

  // 2. SEND RESPONSE IMMEDIATELY
  res.status(201).json({ message: 'Added to history' });

  // 3. UPDATE DB IN BACKGROUND
  backgroundSync(
    pool.query('INSERT INTO history (user_id, song_data, added_at) VALUES (?, ?, ?)', [userId, JSON.stringify(songData), addedAt]),
    'AddToHistory'
  );
});

app.delete('/api/history/:videoId', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const videoId = req.params.videoId;

  // 1. UPDATE CACHE
  const historyList = GlobalCache.history.get(userId);
  const initialLength = historyList.length;
  const filtered = historyList.filter(item => item.videoId !== videoId);
  GlobalCache.history.set(userId, filtered);

  if (filtered.length === initialLength) return res.status(404).json({ error: 'Not found' });

  // 2. RESPOND
  res.json({ message: 'Removed from history' });

  // 3. BACKGROUND DB
  backgroundSync(
    pool.query('DELETE FROM history WHERE user_id = ? AND JSON_EXTRACT(song_data, "$.videoId") = ?', [userId, videoId]),
    'DeleteHistory'
  );
});

// --- Favorites (Write-Behind) ---

app.post('/api/favorites', authenticateToken, (req, res) => {
  const songData = req.body;
  const userId = req.user.userId;
  const addedAt = new Date();

  // 1. Cache
  GlobalCache.favorites.get(userId).unshift({ ...songData, added_at: addedAt });
  
  // 2. Respond
  res.status(201).json({ message: 'Added to favorites' });

  // 3. DB
  backgroundSync(
    pool.query('INSERT INTO favorites (user_id, song_data, added_at) VALUES (?, ?, ?)', [userId, JSON.stringify(songData), addedAt]),
    'AddFavorite'
  );
});

app.delete('/api/favorites/:videoId', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const videoId = req.params.videoId;

  // 1. Cache
  const list = GlobalCache.favorites.get(userId);
  GlobalCache.favorites.set(userId, list.filter(item => item.videoId !== videoId));

  // 2. Respond
  res.json({ message: 'Removed from favorites' });

  // 3. DB
  backgroundSync(
    pool.query('DELETE FROM favorites WHERE user_id = ? AND JSON_EXTRACT(song_data, "$.videoId") = ?', [userId, videoId]),
    'DeleteFavorite'
  );
});

// --- Playlists (Write-Behind) ---

app.post('/api/playlists/:name', authenticateToken, async (req, res) => {
  // NOTE: Creating a playlist needs an ID for relationships, so we might need to await DB creation 
  // OR we generate a temporary ID. For simplicity, we will await Playlist creation but Write-Behind the song addition.
  
  const songData = req.body;
  const playlistName = req.params.name;
  const userId = req.user.userId;

  try {
    let playlistId;
    let userPlaylists = GlobalCache.playlists.get(userId);
    
    // Check Cache for Playlist
    let cachedPlaylist = Array.from(userPlaylists.values()).find(p => p.playlist_name === playlistName);

    if (!cachedPlaylist) {
        // Create Playlist (Must await DB to get ID for foreign keys)
        const [result] = await pool.query('INSERT INTO playlists (user_id, playlist_name) VALUES (?, ?)', [userId, playlistName]);
        playlistId = result.insertId;
        
        // Update Cache
        cachedPlaylist = { id: playlistId, user_id: userId, playlist_name: playlistName, created_at: new Date(), songs: [] };
        userPlaylists.set(playlistId, cachedPlaylist);
    } else {
        playlistId = cachedPlaylist.id;
    }

    // Write-Behind Song Addition
    // 1. Cache Song
    cachedPlaylist.songs.push({ ...songData, added_at: new Date() });

    // 2. Respond
    res.status(201).json({ message: 'Added to playlist' });

    // 3. DB Insert Song
    backgroundSync(
        pool.query('INSERT INTO playlist_songs (playlist_id, song_data) VALUES (?, ?)', [playlistId, JSON.stringify(songData)]),
        'AddPlaylistSong'
    );

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error processing request' });
  }
});

// ==========================================
// START SERVER
// ==========================================

initSystem().then(() => {
  app.listen(7860, () => {
    console.log('🚀 Server running on port 8000 (Pure Express + Cache Layer)');
  });
});
