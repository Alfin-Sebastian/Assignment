const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const JWT_SECRET = 'your_cms_super_secret_key';
const users = []; 

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, userPayload) => {
    if (err) return res.sendStatus(403);
    req.user = userPayload; 
    next();
  });
};

const requireRole = (role) => {
  return (req, res, next) => {
 
    if (req.user.role !== role) {
      return res.status(403).json({ message: `Access forbidden. ${role} role required.` });
    }
    next();
  };
};

app.post('/register', async (req, res) => {
  try {
    const { username, password, role = 'user' } = req.body;
    if (users.find(user => user.username === username)) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = { username, password: hashedPassword, role };
    users.push(newUser);

    res.status(201).json({ message: `User (${role}) created successfully` });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = users.find(user => user.username === username);

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

       const token = jwt.sign(
      { username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ message: 'Login successful!', token: token, user: { username, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: 'Login error', error: error.message });
  }
});

app.get('/api/articles', (req, res) => {
  res.json({ message: 'List of public articles' });
});

app.put('/api/profile', authenticateToken, (req, res) => {
   res.json({ message: 'Profile updated successfully', user: req.user.username });
});

app.post('/api/articles', authenticateToken, requireRole('editor'), (req, res) => {
    res.json({ message: 'Draft article created successfully' });
});

app.delete('/api/articles/:id', authenticateToken, requireRole('admin'), (req, res) => {
  res.json({ message: `Article ${req.params.id} deleted by admin` });
});

app.get('/api/admin/dashboard', authenticateToken, requireRole('admin'), (req, res) => {
  res.json({
    message: 'Welcome to the Admin Dashboard',
    stats: { totalUsers: users.length, totalArticles: 147 },
    recentActivity: users.map(u => ({ username: u.username, role: u.role }))
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CMS Auth Server running on port ${PORT}`));