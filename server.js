const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken'); // 👈 JWT added for login token

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT;
const mongoURI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// Connect MongoDB
mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('DB connection error:', err));

// Schema
const userSchema = new mongoose.Schema({
  name: { type : String, required: true },
  email: { type : String, required: true, unique: true },
  password: { type : String, required: true },
  bloodGroup: { type : String, required: true }
});

const User = mongoose.model('User', userSchema);

//
// 🔹 Registration Route
//
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, bloodGroup } = req.body;

    if (!name || !email || !password || !bloodGroup) {
      return res.status(400).json({ error: 'Please fill all fields including blood group' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      bloodGroup
    });

    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

//
// 🔹 Login Route
//
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Generate JWT token (optional)
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        bloodGroup: user.bloodGroup
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/', (req, res) => {
  res.send('Backend is running! 👌');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


