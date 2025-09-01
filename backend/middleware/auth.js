import jwt from 'jsonwebtoken';
import { executeQuery } from '../config/database.js';

// Verify JWT token
export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'No token provided'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database
    const query = 'SELECT id, email, name, phone, is_verified, created_at FROM users WHERE id = ?';
    const users = await executeQuery(query, [decoded.userId]);
    
    if (users.length === 0) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'Invalid token - user not found'
      });
    }
    
    // Add user to request object
    req.user = users[0];
    next();
    
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Access denied',
        message: 'Invalid token'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Access denied',
        message: 'Token expired'
      });
    }
    
    console.error('Auth middleware error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      message: 'Authentication failed'
    });
  }
};

// Optional authentication (for routes that work with both authenticated and guest users)
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      req.user = null;
      return next();
    }
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database
    const query = 'SELECT id, email, name, phone, is_verified, created_at FROM users WHERE id = ?';
    const users = await executeQuery(query, [decoded.userId]);
    
    if (users.length > 0) {
      req.user = users[0];
    } else {
      req.user = null;
    }
    
    next();
    
  } catch (error) {
    // If token is invalid, continue as guest
    req.user = null;
    next();
  }
};

// Generate JWT token
export const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

// Verify user ownership (for accessing own resources)
export const verifyOwnership = (req, res, next) => {
  const userId = req.params.userId || req.body.userId;
  
  if (req.user.id !== userId) {
    return res.status(403).json({
      error: 'Access denied',
      message: 'You can only access your own resources'
    });
  }
  
  next();
};

export default {
  authenticateToken,
  optionalAuth,
  generateToken,
  verifyOwnership
};