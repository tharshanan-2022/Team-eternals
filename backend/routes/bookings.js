import express from 'express';
import { body, validationResult } from 'express-validator';
import { executeQuery } from '../config/database.js';
import { optionalAuth, authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Generate trip ID
const generateTripId = () => {
  const prefix = 'TB';
  const timestamp = Date.now().toString().slice(-6);
  const random = Math.random().toString(36).substring(2, 6).toUpperCase();
  return `${prefix}${timestamp}${random}`;
};

// Validation rules for booking creation
const bookingValidation = [
  body('vehicleId')
    .notEmpty()
    .withMessage('Vehicle ID is required'),
  body('rentalType')
    .isIn(['location', 'hourly', 'daily'])
    .withMessage('Invalid rental type'),
  body('fromDate')
    .isISO8601()
    .withMessage('Invalid from date'),
  body('toDate')
    .isISO8601()
    .withMessage('Invalid to date'),
  body('totalFare')
    .isFloat({ min: 0 })
    .withMessage('Total fare must be a positive number'),
  body('paymentMethod')
    .isIn(['cash', 'card', 'wallet'])
    .withMessage('Invalid payment method'),
  body('customerName')
    .trim()
    .isLength({ min: 2 })
    .withMessage('Customer name must be at least 2 characters'),
  body('customerEmail')
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email address'),
  body('customerPhone')
    .isMobilePhone()
    .withMessage('Invalid phone number')
];

// Create new booking
router.post('/', optionalAuth, bookingValidation, async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const {
      vehicleId,
      rentalType,
      fromDate,
      toDate,
      pickupLocation,
      dropoffLocation,
      hours,
      days,
      totalFare,
      paymentMethod,
      customerName,
      customerEmail,
      customerPhone
    } = req.body;

    // Check if vehicle exists and is available
    const vehicle = await executeQuery(
      'SELECT id, available FROM vehicles WHERE id = ?',
      [vehicleId]
    );

    if (vehicle.length === 0) {
      return res.status(404).json({
        error: 'Vehicle not found'
      });
    }

    if (!vehicle[0].available) {
      return res.status(400).json({
        error: 'Vehicle not available'
      });
    }

    // Validate dates
    const from = new Date(fromDate);
    const to = new Date(toDate);
    const now = new Date();
    
    // Compare dates at start of day to avoid timezone issues
    const fromDateOnly = new Date(from.getFullYear(), from.getMonth(), from.getDate());
    const nowDateOnly = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    if (fromDateOnly < nowDateOnly) {
      return res.status(400).json({
        error: 'From date cannot be in the past'
      });
    }

    if (to <= from) {
      return res.status(400).json({
        error: 'To date must be after from date'
      });
    }

    // Convert ISO datetime strings to MySQL format
    const formatDateForMySQL = (isoString) => {
      return new Date(isoString).toISOString().slice(0, 19).replace('T', ' ');
    };

    const formattedFromDate = formatDateForMySQL(fromDate);
    const formattedToDate = formatDateForMySQL(toDate);

    // Check for conflicting bookings
    const conflictingBookings = await executeQuery(`
      SELECT id FROM bookings 
      WHERE vehicle_id = ? 
        AND status IN ('confirmed', 'completed')
        AND (
          (from_date <= ? AND to_date > ?) OR
          (from_date < ? AND to_date >= ?) OR
          (from_date >= ? AND to_date <= ?)
        )
    `, [vehicleId, formattedFromDate, formattedFromDate, formattedToDate, formattedToDate, formattedFromDate, formattedToDate]);

    if (conflictingBookings.length > 0) {
      return res.status(409).json({
        error: 'Vehicle is not available for the selected time period'
      });
    }

    // Generate trip ID
    const tripId = generateTripId();
    console.log('Generated Trip ID:', tripId);

    // Determine if user is guest or authenticated
    const userId = req.user ? req.user.id : null;
    const isGuest = !req.user;

    // Insert booking
    const insertQuery = `
      INSERT INTO bookings (
        trip_id, user_id, vehicle_id, rental_type, from_date, to_date,
        pickup_location, dropoff_location, hours, days, total_fare,
        payment_method, customer_name, customer_email, customer_phone,
        is_guest, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'confirmed')
    `;

    const result = await executeQuery(insertQuery, [
      tripId,
      userId,
      vehicleId,
      rentalType,
      formattedFromDate,
      formattedToDate,
      pickupLocation || null,
      dropoffLocation || null,
      hours || null,
      days || null,
      totalFare,
      paymentMethod,
      customerName,
      customerEmail,
      customerPhone,
      isGuest
    ]);
    console.log('Insert result ID:', result.insertId);

    // Get the created booking with vehicle details using trip_id to ensure we get the correct booking
    const booking = await executeQuery(`
      SELECT 
        b.*,
        v.name as vehicle_name,
        v.type as vehicle_type,
        v.image as vehicle_image
      FROM bookings b
      JOIN vehicles v ON b.vehicle_id = v.id
      WHERE b.trip_id = ?
    `, [tripId]);
    console.log('Retrieved booking Trip ID:', booking[0]?.trip_id);

    console.log('Returning booking with Trip ID:', booking[0].trip_id);
    res.status(201).json({
      message: 'Booking created successfully',
      booking: booking[0]
    });

  } catch (error) {
    console.error('Booking creation error:', error);
    res.status(500).json({
      error: 'Booking creation failed',
      message: 'Internal server error'
    });
  }
});

// Get booking by trip ID (for trip lookup)
router.get('/trip/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;

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
      WHERE b.trip_id = ?
    `, [tripId]);

    if (booking.length === 0) {
      return res.status(404).json({
        error: 'Booking not found',
        message: 'No booking found with this trip ID'
      });
    }

    res.json({
      booking: booking[0]
    });

  } catch (error) {
    console.error('Get booking by trip ID error:', error);
    res.status(500).json({
      error: 'Failed to get booking',
      message: 'Internal server error'
    });
  }
});

// Cancel booking by trip ID (for trip lookup)
router.put('/trip/:tripId/cancel', async (req, res) => {
  try {
    const { tripId } = req.params;

    // Check if booking exists
    const booking = await executeQuery(`
      SELECT id, status, from_date, customer_email
      FROM bookings 
      WHERE trip_id = ?
    `, [tripId]);

    if (booking.length === 0) {
      return res.status(404).json({
        error: 'Booking not found',
        message: 'No booking found with this trip ID'
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
      WHERE trip_id = ?
    `, [tripId]);

    res.json({
      message: 'Booking cancelled successfully'
    });

  } catch (error) {
    console.error('Cancel booking by trip ID error:', error);
    res.status(500).json({
      error: 'Failed to cancel booking',
      message: 'Internal server error'
    });
  }
});

// Get all bookings (admin/authenticated users)
router.get('/', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const status = req.query.status;
    const vehicleType = req.query.vehicleType;
    const offset = (page - 1) * limit;

    // Build WHERE clause
    let whereClause = 'WHERE 1=1';
    const queryParams = [];

    // Filter by user's own bookings
    whereClause += ' AND b.user_id = ?';
    queryParams.push(req.user.id);

    if (status && ['confirmed', 'completed', 'cancelled'].includes(status)) {
      whereClause += ' AND b.status = ?';
      queryParams.push(status);
    }

    if (vehicleType && ['bike', 'threewheel', 'car', 'van', 'lorry'].includes(vehicleType)) {
      whereClause += ' AND v.type = ?';
      queryParams.push(vehicleType);
    }

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM bookings b
      JOIN vehicles v ON b.vehicle_id = v.id
      ${whereClause}
    `;
    const totalResult = await executeQuery(countQuery, queryParams);
    const total = totalResult[0].total;

    // Get bookings with pagination
    const bookingsQuery = `
      SELECT 
        b.*,
        v.name as vehicle_name,
        v.type as vehicle_type,
        v.image as vehicle_image
      FROM bookings b
      JOIN vehicles v ON b.vehicle_id = v.id
      ${whereClause}
      ORDER BY b.created_at DESC
      LIMIT ? OFFSET ?
    `;

    queryParams.push(limit, offset);
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

// Get specific booking by ID
router.get('/:bookingId', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

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
    `, [bookingId, req.user.id]);

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

// Update booking status
router.put('/:bookingId/status', authenticateToken, [
  body('status')
    .isIn(['confirmed', 'completed', 'cancelled'])
    .withMessage('Invalid status')
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

    const { bookingId } = req.params;
    const { status } = req.body;

    // Check if booking exists and belongs to user
    const booking = await executeQuery(`
      SELECT id, status as current_status, from_date
      FROM bookings 
      WHERE id = ? AND user_id = ?
    `, [bookingId, req.user.id]);

    if (booking.length === 0) {
      return res.status(404).json({
        error: 'Booking not found'
      });
    }

    const bookingData = booking[0];

    // Validate status transition
    if (status === 'cancelled' && bookingData.current_status === 'completed') {
      return res.status(400).json({
        error: 'Cannot cancel completed booking'
      });
    }

    if (status === 'cancelled') {
      const now = new Date();
      const fromDate = new Date(bookingData.from_date);
      if (fromDate < now) {
        return res.status(400).json({
          error: 'Cannot cancel past bookings'
        });
      }
    }

    // Update booking status
    await executeQuery(`
      UPDATE bookings 
      SET status = ?, updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `, [status, bookingId]);

    res.json({
      message: `Booking ${status} successfully`
    });

  } catch (error) {
    console.error('Update booking status error:', error);
    res.status(500).json({
      error: 'Failed to update booking status',
      message: 'Internal server error'
    });
  }
});

// Get booking statistics
router.get('/stats/overview', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // Get overall statistics
    const stats = await executeQuery(`
      SELECT 
        COUNT(*) as total_bookings,
        COUNT(CASE WHEN status = 'confirmed' THEN 1 END) as confirmed_bookings,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_bookings,
        COUNT(CASE WHEN status = 'cancelled' THEN 1 END) as cancelled_bookings,
        COALESCE(SUM(total_fare), 0) as total_spent,
        COALESCE(AVG(total_fare), 0) as average_fare
      FROM bookings 
      WHERE user_id = ?
    `, [userId]);

    // Get monthly trend (last 12 months)
    const monthlyTrend = await executeQuery(`
      SELECT 
        DATE_FORMAT(created_at, '%Y-%m') as month,
        COUNT(*) as bookings,
        COALESCE(SUM(total_fare), 0) as spent
      FROM bookings 
      WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
      GROUP BY DATE_FORMAT(created_at, '%Y-%m')
      ORDER BY month ASC
    `, [userId]);

    // Get vehicle type distribution
    const vehicleTypeStats = await executeQuery(`
      SELECT 
        v.type,
        COUNT(*) as bookings,
        COALESCE(SUM(b.total_fare), 0) as spent
      FROM bookings b
      JOIN vehicles v ON b.vehicle_id = v.id
      WHERE b.user_id = ?
      GROUP BY v.type
      ORDER BY bookings DESC
    `, [userId]);

    res.json({
      overview: stats[0],
      monthlyTrend,
      vehicleTypeStats
    });

  } catch (error) {
    console.error('Get booking statistics error:', error);
    res.status(500).json({
      error: 'Failed to get booking statistics',
      message: 'Internal server error'
    });
  }
});

export default router;