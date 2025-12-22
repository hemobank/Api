const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();


const allowedOrigins = ['https://hemo-bank.vercel.app'];
app.use(cors({
  origin: function(origin, callback){
    // Allow requests with no origin (like Postman)
    if(!origin) return callback(null, true);
    if(allowedOrigins.indexOf(origin) === -1){
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true
}));

app.use(express.json());

const PORT = process.env.PORT || 5000;
const mongoURI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// MongoDB connection
mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('DB connection error:', err));

// User schema & model
const userSchema = new mongoose.Schema({
  name: { type : String, required: true },
  email: { type : String, required: true, unique: true },
  password: { type : String, required: true },
  bloodGroup: { type : String, required: true },

  resetToken: String,
  resetTokenExpiry: Date
});

const User = mongoose.model('User', userSchema);

// 🔹 Registration Route
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

// 🔹 Login Route
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

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


// 🔹 FORGOT PASSWORD ROUTE ✅
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const token = crypto.randomBytes(32).toString('hex');

    user.resetToken = token;
    user.resetTokenExpiry = Date.now() + 15 * 60 * 1000;

    await user.save();

    const resetLink = `https://hemo-bank.vercel.app/reset-password.html?token=${token}`;
    console.log('Reset link:', resetLink);

    res.json({ message: 'Password reset link sent' });
  } catch (err) {
    console.error("Forgot password route error:", err);
    res.status(500).json({ error: 'Server error' });
  }
});


// 🔹 RESET PASSWORD ROUTE ✅
app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;

    await user.save();

    res.json({ message: 'Password reset successful' });

  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 🔹 Default Route
app.get('/', (req, res) => {
  res.send('Backend is running! 👌');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


