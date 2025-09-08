import express from 'express';
import bcrypt from 'bcryptjs';
import { body, validationResult } from 'express-validator';
import { executeQuery } from '../config/database.js';
import { generateToken, authenticateToken } from '../middleware/auth.js';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const router = express.Router();
const SALT_ROUNDS = 12;

// Nodemailer setup
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false, // true for 465
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ===== Validation rules =====
const registerValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters long'),
];

const loginValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required'),
];

// ===== Helper functions =====
async function findUserByEmail(email) {
  if (!email) return [];
  const users = await executeQuery('SELECT * FROM users WHERE email = ?', [email]);
  return users;
}
// ===== Register =====
router.post('/register', registerValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });

    const { email, password, name } = req.body;
    const existingUser = await findUserByEmail(email);
    if (existingUser.length > 0) return res.status(409).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await executeQuery(
      'INSERT INTO users (email, password, name, is_verified) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, name, false]
    );

    const newUser = await executeQuery('SELECT id, email, name, is_verified, created_at FROM users WHERE id = ?', [result.insertId]);
    const token = generateToken(newUser[0].id);

    res.status(201).json({ message: 'User registered successfully', user: newUser[0], token });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed', message: 'Internal server error' });
  }
});

// ===== Login =====
router.post('/login', loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });

    const { email, password } = req.body;
    const users = await findUserByEmail(email);
    if (users.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

    const user = users[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ error: 'Invalid email or password' });

    const token = generateToken(user.id);
    const { password: _, ...userWithoutPassword } = user;

    res.json({ message: 'Login successful', user: userWithoutPassword, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed', message: 'Internal server error' });
  }
});

// ===== Profile =====
router.get('/profile', authenticateToken, async (req, res) => {
  res.json({ user: req.user });
});

router.put('/profile', authenticateToken, [
  body('name').optional().trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters long'),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });

    const { name } = req.body;
    const userId = req.user.id;

    if (!name) return res.status(400).json({ error: 'No valid fields to update' });

    await executeQuery('UPDATE users SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [name, userId]);

    const updatedUser = await executeQuery('SELECT id, email, name, is_verified, created_at, updated_at FROM users WHERE id = ?', [userId]);
    res.json({ message: 'Profile updated successfully', user: updatedUser[0] });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ error: 'Profile update failed', message: 'Internal server error' });
  }
});

// ===== Change Password =====
router.put('/change-password', authenticateToken, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters long'),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });

    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    const users = await executeQuery('SELECT password FROM users WHERE id = ?', [userId]);
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });

    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, users[0].password);
    if (!isCurrentPasswordValid) return res.status(401).json({ error: 'Current password is incorrect' });

    const hashedNewPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await executeQuery('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [hashedNewPassword, userId]);

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ error: 'Password change failed', message: 'Internal server error' });
  }
});

// ===== Verify JWT =====
router.get('/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// ===== Forgot Password / OTP (Email only) =====
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const users = await findUserByEmail(email);
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });

    const otp = crypto.randomInt(100000, 999999).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await executeQuery('INSERT INTO otp_codes (email, otp, expires_at) VALUES (?, ?, ?)', [email, otp, expiresAt]);

    await transporter.sendMail({
      from: `"MyApp" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP code is: ${otp}`,
      html: `<p>Your OTP code is: <b>${otp}</b></p>`,
    });

    res.json({ message: 'OTP sent successfully', email });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Something went wrong', details: err.message });
  }
});

// ===== Verify OTP =====
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });

    const otpRecords = await executeQuery(
      'SELECT * FROM otp_codes WHERE email = ? AND otp = ? ORDER BY created_at DESC LIMIT 1',
      [email, otp]
    );

    if (otpRecords.length === 0) return res.status(400).json({ error: 'Invalid OTP' });

    const record = otpRecords[0];
    if (new Date() > new Date(record.expires_at)) return res.status(400).json({ error: 'OTP expired' });

    // Mark OTP as used
    await executeQuery('DELETE FROM otp_codes WHERE id = ?', [record.id]);

    res.json({ message: 'OTP verified', email });
  } catch (err) {
    console.error('Verify OTP error:', err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// ===== Reset Password =====
router.put('/reset-password', [
  body('password').isLength({ min: 6 }),
  body('confirmPassword').custom((value, { req }) => value === req.body.password)
], async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const users = await findUserByEmail(email);
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    await executeQuery('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?', [hashedPassword, email]);

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

export default router;
