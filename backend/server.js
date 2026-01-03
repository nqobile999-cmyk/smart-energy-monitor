require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/energy_monitor'
});

// Create users table
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        settings JSONB DEFAULT '{}'
      )
    `);
    
    // Create energy readings table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS energy_readings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        power_w DECIMAL(10,2),
        energy_wh DECIMAL(10,2),
        cost DECIMAL(10,4),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('✅ Database tables created');
  } catch (err) {
    console.error('Database error:', err);
  }
}

// Register user
app.post('/api/register', async (req, res) => {
  try {
    const { email, firstName, lastName, password } = req.body;
    
    // Validate input
    if (!email || !firstName || !lastName || !password) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Save to database
    const result = await pool.query(
      'INSERT INTO users (email, first_name, last_name, password) VALUES ($1, $2, $3, $4) RETURNING id, email, first_name, last_name, created_at',
      [email, firstName, lastName, hashedPassword]
    );
    
    // Generate JWT token
    const token = jwt.sign(
      { id: result.rows[0].id, email },
      process.env.JWT_SECRET || 'energy-monitor-secret-key-2024',
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      message: 'Registration successful',
      user: result.rows[0],
      token
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.detail || 'Registration failed'
    });
  }
});

// Login user
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    const user = result.rows[0];
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    // Update last login
    await pool.query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || 'energy-monitor-secret-key-2024',
      { expiresIn: '7d' }
    );
    
    // Remove password from response
    delete user.password;
    
    res.json({
      success: true,
      message: 'Login successful',
      user,
      token
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
});

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, first_name, last_name, created_at, last_login, settings FROM users WHERE id = $1',
      [req.user.id]
    );
    
    res.json({
      success: true,
      user: result.rows[0]
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile'
    });
  }
});

// Submit energy reading
app.post('/api/readings', authenticateToken, async (req, res) => {
  try {
    const { power, energy, cost } = req.body;
    
    await pool.query(
      'INSERT INTO energy_readings (user_id, power_w, energy_wh, cost) VALUES ($1, $2, $3, $4)',
      [req.user.id, power, energy, cost]
    );
    
    res.json({
      success: true,
      message: 'Reading saved'
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Failed to save reading'
    });
  }
});

// Get user readings
app.get('/api/readings', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM energy_readings WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 100',
      [req.user.id]
    );
    
    res.json({
      success: true,
      readings: result.rows
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch readings'
    });
  }
});

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }
  
  jwt.verify(token, process.env.JWT_SECRET || 'energy-monitor-secret-key-2024', (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
}

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    service: 'Energy Monitor API',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Smart Energy Monitor API',
    endpoints: {
      register: 'POST /api/register',
      login: 'POST /api/login',
      profile: 'GET /api/profile',
      readings: 'GET /api/readings',
      submit: 'POST /api/readings',
      health: 'GET /health'
    }
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Backend running on http://localhost:${PORT}`);
  console.log(`📊 API Documentation: http://localhost:${PORT}`);
  console.log(`❤️  Health check: http://localhost:${PORT}/health`);
  initDB();
});
