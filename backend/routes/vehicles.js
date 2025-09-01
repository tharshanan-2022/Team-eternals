import express from 'express';
import { body, validationResult } from 'express-validator';
import { executeQuery } from '../config/database.js';
import { authenticateToken, optionalAuth } from '../middleware/auth.js';

const router = express.Router();

// Get all vehicles
router.get('/', async (req, res) => {
  try {
    const type = req.query.type;
    const available = req.query.available;
    
    let whereClause = 'WHERE 1=1';
    const queryParams = [];
    
    if (type && ['bike', 'threewheel', 'car', 'van', 'lorry'].includes(type)) {
      whereClause += ' AND type = ?';
      queryParams.push(type);
    }
    
    if (available !== undefined) {
      whereClause += ' AND available = ?';
      queryParams.push(available === 'true');
    }
    
    const query = `
      SELECT 
        id,
        type,
        name,
        description,
        image,
        base_price,
        hourly_rate,
        daily_rate,
        features,
        available,
        created_at
      FROM vehicles 
      ${whereClause}
      ORDER BY type, name
    `;
    
    const vehicles = await executeQuery(query, queryParams);
    
    // Parse JSON features and transform to camelCase for each vehicle
    const vehiclesWithFeatures = (vehicles || []).map(vehicle => {
      if (!vehicle) return null;
      return {
        id: vehicle.id,
        type: vehicle.type,
        name: vehicle.name,
        description: vehicle.description,
        image: vehicle.image,
        basePrice: vehicle.base_price,
        hourlyRate: vehicle.hourly_rate,
        dailyRate: vehicle.daily_rate,
        features: (() => {
          try {
            return vehicle.features ? JSON.parse(vehicle.features) : [];
          } catch (e) {
            console.warn(`Invalid JSON in features for vehicle ${vehicle.id}:`, vehicle.features);
            return [];
          }
        })(),
        available: vehicle.available,
        createdAt: vehicle.created_at
      };
    }).filter(Boolean);
    
    res.json({
      vehicles: vehiclesWithFeatures
    });
    
  } catch (error) {
    console.error('Get vehicles error:', error);
    res.status(500).json({
      error: 'Failed to get vehicles',
      message: 'Internal server error'
    });
  }
});

// Get vehicle by ID
router.get('/:vehicleId', async (req, res) => {
  try {
    const { vehicleId } = req.params;
    
    const vehicles = await executeQuery(`
      SELECT 
        id,
        type,
        name,
        description,
        image,
        base_price,
        hourly_rate,
        daily_rate,
        features,
        available,
        created_at
      FROM vehicles 
      WHERE id = ?
    `, [vehicleId]);
    
    if (vehicles.length === 0) {
      return res.status(404).json({
        error: 'Vehicle not found'
      });
    }
    
    const vehicle = {
      id: vehicles[0].id,
      type: vehicles[0].type,
      name: vehicles[0].name,
      description: vehicles[0].description,
      image: vehicles[0].image,
      basePrice: vehicles[0].base_price,
      hourlyRate: vehicles[0].hourly_rate,
      dailyRate: vehicles[0].daily_rate,
      features: (() => {
        try {
          return vehicles[0].features ? JSON.parse(vehicles[0].features) : [];
        } catch (e) {
          console.warn(`Invalid JSON in features for vehicle ${vehicles[0].id}:`, vehicles[0].features);
          return [];
        }
      })(),
      available: vehicles[0].available,
      createdAt: vehicles[0].created_at
    };
    
    res.json({
      vehicle
    });
    
  } catch (error) {
    console.error('Get vehicle error:', error);
    res.status(500).json({
      error: 'Failed to get vehicle',
      message: 'Internal server error'
    });
  }
});

// Check vehicle availability for specific dates
router.post('/:vehicleId/availability', [
  body('fromDate')
    .isISO8601()
    .withMessage('Invalid from date'),
  body('toDate')
    .isISO8601()
    .withMessage('Invalid to date')
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
    
    const { vehicleId } = req.params;
    const { fromDate, toDate } = req.body;
    
    // Check if vehicle exists
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
      return res.json({
        available: false,
        reason: 'Vehicle is not available'
      });
    }
    
    // Validate dates
    const from = new Date(fromDate);
    const to = new Date(toDate);
    const now = new Date();
    
    if (from < now) {
      return res.status(400).json({
        error: 'From date cannot be in the past'
      });
    }
    
    if (to <= from) {
      return res.status(400).json({
        error: 'To date must be after from date'
      });
    }
    
    // Check for conflicting bookings
    const conflictingBookings = await executeQuery(`
      SELECT id, trip_id, from_date, to_date 
      FROM bookings 
      WHERE vehicle_id = ? 
        AND status IN ('confirmed', 'completed')
        AND (
          (from_date <= ? AND to_date > ?) OR
          (from_date < ? AND to_date >= ?) OR
          (from_date >= ? AND to_date <= ?)
        )
    `, [vehicleId, fromDate, fromDate, toDate, toDate, fromDate, toDate]);
    
    const isAvailable = conflictingBookings.length === 0;
    
    res.json({
      available: isAvailable,
      ...(conflictingBookings.length > 0 && {
        reason: 'Vehicle is booked for the selected time period',
        conflictingBookings: conflictingBookings.map(booking => ({
          tripId: booking.trip_id,
          fromDate: booking.from_date,
          toDate: booking.to_date
        }))
      })
    });
    
  } catch (error) {
    console.error('Check availability error:', error);
    res.status(500).json({
      error: 'Failed to check availability',
      message: 'Internal server error'
    });
  }
});

// Get vehicle types with counts
router.get('/types/summary', async (req, res) => {
  try {
    const summary = await executeQuery(`
      SELECT 
        type,
        COUNT(*) as total_vehicles,
        COUNT(CASE WHEN available = true THEN 1 END) as available_vehicles,
        MIN(base_price) as min_base_price,
        MAX(base_price) as max_base_price,
        AVG(base_price) as avg_base_price
      FROM vehicles 
      GROUP BY type
      ORDER BY 
        CASE type
          WHEN 'bike' THEN 1
          WHEN 'threewheel' THEN 2
          WHEN 'car' THEN 3
          WHEN 'van' THEN 4
          WHEN 'lorry' THEN 5
        END
    `);
    
    res.json({
      summary
    });
    
  } catch (error) {
    console.error('Get vehicle types summary error:', error);
    res.status(500).json({
      error: 'Failed to get vehicle types summary',
      message: 'Internal server error'
    });
  }
});

// Get popular vehicles (most booked)
router.get('/popular/ranking', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 5;
    
    const popularVehicles = await executeQuery(`
      SELECT 
        v.id,
        v.type,
        v.name,
        v.description,
        v.image,
        v.base_price,
        v.hourly_rate,
        v.daily_rate,
        v.features,
        v.available,
        COUNT(b.id) as booking_count,
        COALESCE(SUM(b.total_fare), 0) as total_revenue
      FROM vehicles v
      LEFT JOIN bookings b ON v.id = b.vehicle_id AND b.status IN ('confirmed', 'completed')
      GROUP BY v.id
      ORDER BY booking_count DESC, total_revenue DESC
      LIMIT ?
    `, [limit]);
    
    // Parse JSON features for each vehicle
    const vehiclesWithFeatures = popularVehicles.map(vehicle => ({
      ...vehicle,
      features: vehicle.features ? JSON.parse(vehicle.features) : [],
      booking_count: parseInt(vehicle.booking_count),
      total_revenue: parseFloat(vehicle.total_revenue)
    }));
    
    res.json({
      popularVehicles: vehiclesWithFeatures
    });
    
  } catch (error) {
    console.error('Get popular vehicles error:', error);
    res.status(500).json({
      error: 'Failed to get popular vehicles',
      message: 'Internal server error'
    });
  }
});

// Search vehicles
router.get('/search/query', async (req, res) => {
  try {
    const { q, type, minPrice, maxPrice, available } = req.query;
    
    let whereClause = 'WHERE 1=1';
    const queryParams = [];
    
    if (q) {
      whereClause += ' AND (name LIKE ? OR description LIKE ?)';
      const searchTerm = `%${q}%`;
      queryParams.push(searchTerm, searchTerm);
    }
    
    if (type && ['bike', 'threewheel', 'car', 'van', 'lorry'].includes(type)) {
      whereClause += ' AND type = ?';
      queryParams.push(type);
    }
    
    if (minPrice) {
      whereClause += ' AND base_price >= ?';
      queryParams.push(parseFloat(minPrice));
    }
    
    if (maxPrice) {
      whereClause += ' AND base_price <= ?';
      queryParams.push(parseFloat(maxPrice));
    }
    
    if (available !== undefined) {
      whereClause += ' AND available = ?';
      queryParams.push(available === 'true');
    }
    
    const query = `
      SELECT 
        id,
        type,
        name,
        description,
        image,
        base_price,
        hourly_rate,
        daily_rate,
        features,
        available,
        created_at
      FROM vehicles 
      ${whereClause}
      ORDER BY 
        CASE type
          WHEN 'bike' THEN 1
          WHEN 'threewheel' THEN 2
          WHEN 'car' THEN 3
          WHEN 'van' THEN 4
          WHEN 'lorry' THEN 5
        END,
        base_price ASC
    `;
    
    const vehicles = await executeQuery(query, queryParams);
    
    // Parse JSON features for each vehicle
    const vehiclesWithFeatures = vehicles.map(vehicle => ({
      ...vehicle,
      features: vehicle.features ? JSON.parse(vehicle.features) : []
    }));
    
    res.json({
      vehicles: vehiclesWithFeatures,
      count: vehicles.length
    });
    
  } catch (error) {
    console.error('Search vehicles error:', error);
    res.status(500).json({
      error: 'Failed to search vehicles',
      message: 'Internal server error'
    });
  }
});

export default router;