const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const sgMail = require('@sendgrid/mail');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

dotenv.config();
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Failed to connect to MongoDB', err));

// User Schema and Model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  mobile: String,
  password: String,
  verified: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);

// Registration Endpoint
app.post('/api/auth/register', async (req, res) => {
  const { name, email, mobile, password } = req.body;

  if (!name || !email || !mobile || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  // Check if the user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: 'User with this email already exists.' });
  }

  // Hash the password for security
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create a new user
  const verificationLink = `https://sendgrid-sigma.vercel.app/login?email=${email}`; 
  const user = new User({ name, email, mobile, password: hashedPassword });

  try {
    // Save user to the database
    await user.save();

    // Send Verification Email via SendGrid
    const msg = {
      to: email,
      from: 'pritam.kamble@linkcode.in',
      subject: 'Please Verify Your Email',
      html: `<p>Hi ${name},</p><p>Click the link below to verify your email address:</p><a href="${verificationLink}">Verify Email</a>`,
    };

    await sgMail.send(msg);
    res.status(200).json({ message: 'Registration successful! Please check your email to Login' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to send verification email. Please try again later.' });
  }
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(401).json({ message: 'User not found.' });
  }

  if (!user.verified) {
    return res.status(401).json({ message: 'Please verify your email to log in.' });
  }

  // Compare the entered password with the hashed password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid password.' });
  }

  res.status(200).json({ message: 'Login successful.' });
});

// Email Verification Endpoint
app.get('/api/auth/verify', async (req, res) => {
  const { email } = req.query;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ message: 'User not found.' });
  }

  user.verified = true;
  await user.save();
  res.status(200).json({ message: 'Email verified successfully. You can now log in.' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
