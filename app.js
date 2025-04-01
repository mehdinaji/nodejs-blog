require('dotenv').config(); // Load environment variables

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const app = express();
const moment = require('moment-jalaali');
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) {
    console.log('Database connection failed:', err);
    return;
  }
  console.log('Connected to database');
});

app.use(express.json());

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access Denied' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid Token' });

    req.user = user;
    next();
  });
};

// Create a new post
app.post('/posts', authenticateToken, (req, res) => {
  const { title, content } = req.body;
  const username = req.user.username;

  const query = 'INSERT INTO posts (username, title, content) VALUES (?, ?, ?)';
  db.query(query, [username, title, content], (err, result) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.status(201).json({ message: 'Post created successfully!' });
  });
});

// Get all posts
app.get('/posts', (req, res) => {
  const query = 'SELECT * FROM posts ORDER BY created_at DESC';
  db.query(query, (err, results) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(results);
  });
});

// Get user-specific posts
app.get('/myposts', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM posts WHERE username = ?';
  db.query(query, [req.user.username], (err, results) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: 'Database error' });
    }

    // Convert created_at to Jalali date
    const formattedResults = results.map(post => ({
      ...post,
      created_at: moment(post.created_at).format('jYYYY/jMM/jDD HH:mm')
    }));

    res.json(formattedResults);
  });
});

// User login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], async (err, result) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (result.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
