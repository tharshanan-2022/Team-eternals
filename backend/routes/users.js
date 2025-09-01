import express from 'express';
import { body, validationResult } from 'express-validator';
import { executeQuery } from '../config/database.js';
import { authenticateToken, verifyOwnership } from '../middleware/auth.js';

const router = express.Router();

// Get user dashboard data
router.get('/:userId/dashboard', authenticateToken, verifyOwnership, async (req, res) => {
  try {
    const userId = req.params.userId;

    // Get user's booking statistics
    const bookingStats = await executeQuery(`
      SELECT 
        COUNT(*) as total_bookings,
        COUNT(CASE WHEN status = 'confirmed' THEN 1 END) as confirmed_bookings,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_bookings,
        COUNT(CASE WHEN status = 'cancelled' THEN 1 END) as cancelled_bookings,
        COALESCE(SUM(total_fare), 0) as total_spent
      FROM bookings 
      WHERE user_id = ?
    `, [userId]);

    // Get recent bookings (last 5)
    const recentBookings = await executeQuery(`
      SELECT 
        b.id,
        b.trip_id,
        b.rental_type,
        b.from_date,
        b.to_date,
        b.pickup_location,
        b.dropoff_location,
        b.total_fare,
        b.status,
        b.created_at,
        v.name as vehicle_name,
        v.type as vehicle_type,
        v.image as vehicle_image
      FROM bookings b
      JOIN vehicles v ON b.vehicle_id = v.id
      WHERE b.user_id = ?
      ORDER BY b.created_at DESC
      LIMIT 5
    `, [userId]);

    // Get upcoming bookings
    const upcomingBookings = await executeQuery(`
      SELECT 
        b.id,
        b.trip_id,
        b.rental_type,
        b.from_date,
        b.to_date,
        b.pickup_location,
        b.dropoff_location,
        b.total_fare,
        b.status,
        v.name as vehicle_name,
        v.type as vehicle_type,
        v.image as vehicle_image
      FROM bookings b
      JOIN vehicles v ON b.vehicle_id = v.id
      WHERE b.user_id = ? AND b.from_date > NOW() AND b.status = 'confirmed'
      ORDER BY b.from_date ASC
    `, [userId]);

    // Get monthly booking trend (last 6 months)
    const monthlyTrend = await executeQuery(`
      SELECT 
        DATE_FORMAT(created_at, '%Y-%m') as month,
        COUNT(*) as bookings,
        COALESCE(SUM(total_fare), 0) as revenue
      FROM bookings 
      WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
      GROUP BY DATE_FORMAT(created_at, '%Y-%m')
      ORDER BY month DESC
    `, [userId]);

    res.json({
      user: req.user,
      stats: bookingStats[0],
      recentBookings,
      upcomingBookings,
      monthlyTrend
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({
      error: 'Failed to load dashboard',
      message: 'Internal server error'
    });
  }
});

// Get user's all bookings with pagination
router.get('/:userId/bookings', authenticateToken, verifyOwnership, async (req, res) => {
  try {
    const userId = req.params.userId;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const status = req.query.status;
    const offset = (page - 1) * limit;

    // Build WHERE clause
    let whereClause = 'WHERE b.user_id = ?';
    const queryParams = [userId];

    if (status && ['confirmed', 'completed', 'cancelled'].includes(status)) {
      whereClause += ' AND b.status = ?';
      queryParams.push(status);
    }

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM bookings b
      ${whereClause}
    `;
    const totalResult = await executeQuery(countQuery, queryParams);
    const total = totalResult[0].total;

    // Get bookings with pagination
    const bookingsQuery = `
      SELECT 
        b.id,
        b.trip_id,
        b.rental_type,
        b.from_date,
        b.to_date,
        b.pickup_location,
        b.dropoff_location,
        b.hours,
        b.days,
        b.total_fare,
        b.payment_method,
        b.status,
        b.created_at,
        v.name as vehicle_name,
        v.type as vehicle_type,
        v.image as vehicle_image
      FROM bookings b
      JOIN vehicles v ON b.vehicle_id = v.id
      ${whereClause}
      ORDER BY b.created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `;

    const bookings = await executeQuery(bookingsQuery, queryParams);

    res.json({
      bookings,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    });

  } catch (error) {
    console.error('Get bookings error:', error);
    res.status(500).json({
      error: 'Failed to get bookings',
      message: 'Internal server error'
    });
  }
});

// Get specific booking details
router.get('/:userId/bookings/:bookingId', authenticateToken, verifyOwnership, async (req, res) => {
  try {
    const { userId, bookingId } = req.params;

    const booking = await executeQuery(`
      SELECT 
        b.*,
        v.name as vehicle_name,
        v.type as vehicle_type,
        v.description as vehicle_description,
        v.image as vehicle_image,
        v.features as vehicle_features
      FROM bookings b
      JOIN vehicles v ON b.vehicle_id = v.id
      WHERE b.id = ? AND b.user_id = ?
    `, [bookingId, userId]);

    if (booking.length === 0) {
      return res.status(404).json({
        error: 'Booking not found'
      });
    }

    res.json({
      booking: booking[0]
    });

  } catch (error) {
    console.error('Get booking details error:', error);
    res.status(500).json({
      error: 'Failed to get booking details',
      message: 'Internal server error'
    });
  }
});

// Cancel a booking
router.put('/:userId/bookings/:bookingId/cancel', authenticateToken, verifyOwnership, async (req, res) => {
  try {
    const { userId, bookingId } = req.params;

    // Check if booking exists and belongs to user
    const booking = await executeQuery(`
      SELECT id, status, from_date
      FROM bookings 
      WHERE id = ? AND user_id = ?
    `, [bookingId, userId]);

    if (booking.length === 0) {
      return res.status(404).json({
        error: 'Booking not found'
      });
    }

    const bookingData = booking[0];

    // Check if booking can be cancelled
    if (bookingData.status === 'cancelled') {
      return res.status(400).json({
        error: 'Booking already cancelled'
      });
    }

    if (bookingData.status === 'completed') {
      return res.status(400).json({
        error: 'Cannot cancel completed booking'
      });
    }

    // Check if booking is in the past
    const now = new Date();
    const fromDate = new Date(bookingData.from_date);
    if (fromDate < now) {
      return res.status(400).json({
        error: 'Cannot cancel past bookings'
      });
    }

    // Update booking status
    await executeQuery(`
      UPDATE bookings 
      SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `, [bookingId]);

    res.json({
      message: 'Booking cancelled successfully'
    });

  } catch (error) {
    console.error('Cancel booking error:', error);
    res.status(500).json({
      error: 'Failed to cancel booking',
      message: 'Internal server error'
    });
  }
});

// Get user profile
router.get('/:userId/profile', authenticateToken, verifyOwnership, async (req, res) => {
  try {
    res.json({
      user: req.user
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      error: 'Failed to get profile',
      message: 'Internal server error'
    });
  }
});

// Update user profile
router.put('/:userId/profile', authenticateToken, verifyOwnership, [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2 })
    .withMessage('Name must be at least 2 characters long'),
  body('phone')
    .optional()
    .isMobilePhone()
    .withMessage('Please provide a valid phone number')
], async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { name, phone } = req.body;
    const userId = req.params.userId;

    // Build update query dynamically
    const updates = [];
    const values = [];

    if (name) {
      updates.push('name = ?');
      values.push(name);
    }

    if (phone) {
      updates.push('phone = ?');
      values.push(phone);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        error: 'Update failed',
        message: 'No valid fields to update'
      });
    }

    values.push(userId);

    const updateQuery = `UPDATE users SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
    await executeQuery(updateQuery, values);

    // Get updated user
    const updatedUser = await executeQuery(
      'SELECT id, email, name, phone, is_verified, created_at, updated_at FROM users WHERE id = ?',
      [userId]
    );

    res.json({
      message: 'Profile updated successfully',
      user: updatedUser[0]
    });

  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({
      error: 'Profile update failed',
      message: 'Internal server error'
    });
  }
});

export default router;