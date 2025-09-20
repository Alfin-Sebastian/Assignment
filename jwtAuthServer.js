const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const JWT_SECRET = 'your_super_secret_jwt_key_here';
const users = [];

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
   
        if (users.find(user => user.username === username)) {
            return res.status(400).json({ message: 'Username already exists' });
        }


        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

   
        const newUser = { username, password: hashedPassword };
        users.push(newUser);

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error creating user', error: error.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = users.find(user => user.username === username);
        if (!user) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

     
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }


        const token = jwt.sign(
            { username: user.username },
            JWT_SECRET,
            { expiresIn: '1h' }
        );


        res.json({
            message: 'Login successful!',
            token: token,
        });
    } catch (error) {
        res.status(500).json({ message: 'Login error', error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth Server running on port ${PORT}`));