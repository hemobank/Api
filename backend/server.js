const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT;

const mongoURI = process.env.MONGO_URI;


mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('DB connection error:', err));

// User schema with bloodGroup field
const userSchema = new mongoose.Schema({
  name: { type : String, required: true },
  email: { type : String, required: true, unique: true },
  password: { type : String, required: true },
  bloodGroup: { type : String, required: true }
});

const User = mongoose.model('User', userSchema);

// Registration endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, bloodGroup } = req.body;

    // Validate all fields
    if (!name || !email || !password || !bloodGroup) {
      return res.status(400).json({ error: 'Please fill all fields including blood group' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user document
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

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
