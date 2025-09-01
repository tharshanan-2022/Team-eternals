import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

let connection = null;

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'root',
  database: process.env.DB_NAME || 'taxi_booking',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
};

// Create connection pool
const pool = mysql.createPool(dbConfig);

// Connect to database
export const connectDB = async () => {
  try {
    // Test the connection
    connection = await pool.getConnection();
    console.log('🔗 MySQL Connected successfully');
    
    // Release the test connection
    connection.release();
    
    // Create database if it doesn't exist
    await createDatabase();
    
    // Initialize database tables
    await initializeTables();
    
    return pool;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    throw error;
  }
};

// Get database connection
export const getDB = () => {
  return pool;
};

// Create database if it doesn't exist
const createDatabase = async () => {
  try {
    const tempConfig = { ...dbConfig };
    delete tempConfig.database;
    const tempPool = mysql.createPool(tempConfig);
    
    await tempPool.execute(`CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\``);
    console.log(`Database '${dbConfig.database}' created or already exists`);
    
    await tempPool.end();
  } catch (error) {
    console.error('Error creating database:', error);
    throw error;
  }
};

// Execute query with error handling
export const executeQuery = async (query, params = []) => {
  try {
    const [rows] = await pool.execute(query, params);
    return rows;
  } catch (error) {
    console.error('Database query error:', error.message);
    throw error;
  }
};

// Execute transaction
export const executeTransaction = async (queries) => {
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    
    const results = [];
    for (const query of queries) {
      if (typeof query === 'string') {
        const result = await connection.execute(query);
        results.push(result);
      } else {
        const result = await connection.execute(query.sql, query.params || []);
        results.push(result);
      }
    }
    
    await connection.commit();
    console.log('Transaction completed successfully');
    return results;
  } catch (error) {
    await connection.rollback();
    console.error('Transaction failed, rolled back:', error);
    throw error;
  } finally {
    connection.release();
  }
};

// Close database connection
export const closeDB = async () => {
  try {
    await pool.end();
    console.log('🔒 Database connection pool closed');
  } catch (error) {
    console.error('Error closing database connection:', error.message);
  }
};

// Initialize database tables
const initializeTables = async () => {
  try {
    // Create users table
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(32) PRIMARY KEY DEFAULT (LOWER(HEX(RANDOM_BYTES(16)))),
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Create vehicles table
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS vehicles (
        id VARCHAR(32) PRIMARY KEY,
        type ENUM('bike', 'threewheel', 'car', 'van', 'lorry') NOT NULL,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        image VARCHAR(500),
        base_price DECIMAL(10,2) NOT NULL,
        hourly_rate DECIMAL(10,2) NOT NULL,
        daily_rate DECIMAL(10,2) NOT NULL,
        features JSON,
        available BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Create bookings table
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS bookings (
        id VARCHAR(32) PRIMARY KEY DEFAULT (LOWER(HEX(RANDOM_BYTES(16)))),
        trip_id VARCHAR(50) UNIQUE NOT NULL,
        user_id VARCHAR(32),
        vehicle_id VARCHAR(32) NOT NULL,
        rental_type ENUM('location', 'hourly', 'daily') NOT NULL,
        from_date DATETIME NOT NULL,
        to_date DATETIME NOT NULL,
        pickup_location TEXT,
        dropoff_location TEXT,
        hours INT,
        days INT,
        total_fare DECIMAL(10,2) NOT NULL,
        payment_method ENUM('cash', 'card') NOT NULL,
        customer_name VARCHAR(255) NOT NULL,
        customer_email VARCHAR(255) NOT NULL,
        customer_phone VARCHAR(20) NOT NULL,
        is_guest BOOLEAN DEFAULT TRUE,
        status ENUM('confirmed', 'completed', 'cancelled') DEFAULT 'confirmed',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
      )
    `);

    // Add gamification tables
    await initializeGamificationTables();

    // Insert sample data if tables are empty
    const [vehicleCount] = await pool.execute('SELECT COUNT(*) as count FROM vehicles');
    if (vehicleCount[0].count === 0) {
      await insertSampleData();
    }

    console.log('📋 Database tables initialized successfully');
  } catch (error) {
    console.error('Error initializing tables:', error);
    throw error;
  }
};

// Initialize gamification tables
const initializeGamificationTables = async () => {
  try {
    // Check if points column exists, if not add it
    const [columns] = await pool.execute(`
      SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'users' AND COLUMN_NAME = 'points'
    `, [process.env.DB_NAME || 'taxi_booking']);
    
    if (columns.length === 0) {
      await pool.execute(`
        ALTER TABLE users 
        ADD COLUMN points INT DEFAULT 0,
        ADD COLUMN total_points_earned INT DEFAULT 0,
        ADD COLUMN rewards_enabled BOOLEAN DEFAULT TRUE
      `);
    }

    // Create games table
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS games (
        id VARCHAR(32) PRIMARY KEY DEFAULT (LOWER(HEX(RANDOM_BYTES(16)))),
        name VARCHAR(255) NOT NULL,
        description TEXT,
        max_points INT NOT NULL,
        difficulty ENUM('easy', 'medium', 'hard') DEFAULT 'medium',
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Create game_sessions table
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS game_sessions (
        id VARCHAR(32) PRIMARY KEY DEFAULT (LOWER(HEX(RANDOM_BYTES(16)))),
        user_id VARCHAR(32) NOT NULL,
        game_id VARCHAR(32) NOT NULL,
        score INT NOT NULL DEFAULT 0,
        points_earned INT NOT NULL DEFAULT 0,
        duration_seconds INT,
        completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (game_id) REFERENCES games(id) ON DELETE CASCADE
      )
    `);

    // Create rewards table
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS rewards (
        id VARCHAR(32) PRIMARY KEY DEFAULT (LOWER(HEX(RANDOM_BYTES(16)))),
        name VARCHAR(255) NOT NULL,
        description TEXT,
        points_required INT NOT NULL,
        discount_percentage DECIMAL(5,2) NOT NULL,
        max_discount_amount DECIMAL(10,2),
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Create user_rewards table
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS user_rewards (
        id VARCHAR(32) PRIMARY KEY DEFAULT (LOWER(HEX(RANDOM_BYTES(16)))),
        user_id VARCHAR(32) NOT NULL,
        reward_id VARCHAR(32) NOT NULL,
        booking_id VARCHAR(32),
        points_used INT NOT NULL,
        discount_amount DECIMAL(10,2) NOT NULL,
        redeemed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (reward_id) REFERENCES rewards(id) ON DELETE CASCADE,
        FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE SET NULL
      )
    `);

    // Insert sample games if table is empty
    const [gameCount] = await pool.execute('SELECT COUNT(*) as count FROM games');
    if (gameCount[0].count === 0) {
      await insertGamificationData();
    }

    console.log('🎮 Gamification tables initialized successfully');
  } catch (error) {
    console.error('Error initializing gamification tables:', error);
    // Don't throw error to prevent breaking main initialization
  }
};

// Insert sample data
const insertSampleData = async () => {
  try {
    // Insert sample vehicles
    const vehicles = [
      ['bike-1', 'bike', 'Standard Bike', 'Perfect for quick city rides and short distances', '/src/assets/realistic-bike.svg', 50.00, 25.00, 200.00, JSON.stringify(["Helmet included", "Fuel efficient", "Easy parking"])],
      ['bike-2', 'bike', 'Sports Bike', 'High-performance bike for enthusiasts', '/src/assets/realistic-bike.svg', 80.00, 40.00, 320.00, JSON.stringify(["High performance", "Sports design", "Advanced features"])],
      ['threewheel-1', 'threewheel', 'Standard Three Wheeler', 'Comfortable 3-wheeler for city travel', '/src/assets/realistic-threewheel.svg', 80.00, 40.00, 320.00, JSON.stringify(["AC available", "3 passengers", "City specialist"])],
        ['threewheel-2', 'threewheel', 'Shared Three Wheeler', 'Economical shared three wheeler', '/src/assets/realistic-threewheel.svg', 60.00, 30.00, 240.00, JSON.stringify(["Shared ride", "Economical", "Fixed routes"])],
      ['car-1', 'car', 'Sedan Car', 'Comfortable sedan for family trips', '/src/assets/realistic-car.svg', 150.00, 75.00, 600.00, JSON.stringify(["AC", "4 passengers", "Comfortable seats", "Music system"])],
      ['car-2', 'car', 'SUV', 'Spacious SUV for group travel', '/src/assets/realistic-car.svg', 200.00, 100.00, 800.00, JSON.stringify(["7 passengers", "AC", "Large luggage space", "Premium comfort"])],
      ['car-3', 'car', 'Hatchback', 'Compact car for city driving', '/src/assets/realistic-car.svg', 120.00, 60.00, 480.00, JSON.stringify(["Fuel efficient", "Easy parking", "AC", "4 passengers"])],
      ['van-1', 'van', 'Mini Van', 'Perfect for group travel and luggage', '/src/assets/realistic-van.svg', 250.00, 125.00, 1000.00, JSON.stringify(["8 passengers", "Large luggage space", "AC", "Comfortable seating"])],
      ['van-2', 'van', 'Tempo Traveller', 'Ideal for group outings and tours', '/src/assets/realistic-van.svg', 350.00, 175.00, 1400.00, JSON.stringify(["12 passengers", "Reclining seats", "AC", "Entertainment system"])],
      ['lorry-1', 'lorry', 'Small Truck', 'For moving and cargo transport', '/src/assets/realistic-lorry.svg', 300.00, 150.00, 1200.00, JSON.stringify(["1 ton capacity", "Covered", "Loading assistance", "City permits"])],
      ['lorry-2', 'lorry', 'Large Truck', 'Heavy cargo and long distance transport', '/src/assets/realistic-lorry.svg', 500.00, 250.00, 2000.00, JSON.stringify(["5 ton capacity", "Long distance", "GPS tracking", "Professional driver"])]
    ];

    for (const vehicle of vehicles) {
      await pool.execute(
        'INSERT INTO vehicles (id, type, name, description, image, base_price, hourly_rate, daily_rate, features) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        vehicle
      );
    }

    // Insert demo user (password: demo123 - hashed)
    await pool.execute(
      'INSERT INTO users (id, email, password, name, phone, is_verified) VALUES (?, ?, ?, ?, ?, ?)',
      ['demo-user-1', 'demo@taxibooking.com', '$2b$10$rOzJqQqQqQqQqQqQqQqQqOzJqQqQqQqQqQqQqQqQqOzJqQqQqQqQqQ', 'Demo User', '+91 98765 43210', true]
    );

    // Insert sample bookings
    const bookings = [
      ['TB001DEMO', 'demo-user-1', 'car-1', 'location', '2024-01-20 10:00:00', '2024-01-20 12:00:00', 'Mumbai Central', 'Bandra West', null, null, 300.00, 'card', 'Demo User', 'demo@taxibooking.com', '+91 98765 43210', false, 'completed'],
      ['TB002DEMO', 'demo-user-1', 'threewheel-1', 'hourly', '2024-01-22 14:00:00', '2024-01-22 17:00:00', 'Andheri East', 'Powai', 3, null, 240.00, 'cash', 'Demo User', 'demo@taxibooking.com', '+91 98765 43210', false, 'completed'],
      ['TB003DEMO', 'demo-user-1', 'car-2', 'daily', '2024-01-25 09:00:00', '2024-01-27 09:00:00', 'Mumbai Airport', 'Goa', null, 2, 1600.00, 'card', 'Demo User', 'demo@taxibooking.com', '+91 98765 43210', false, 'confirmed']
    ];

    for (const booking of bookings) {
      await pool.execute(
        'INSERT INTO bookings (trip_id, user_id, vehicle_id, rental_type, from_date, to_date, pickup_location, dropoff_location, hours, days, total_fare, payment_method, customer_name, customer_email, customer_phone, is_guest, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        booking
      );
    }

    console.log('📦 Sample data inserted successfully');
  } catch (error) {
    console.error('Error inserting sample data:', error);
  }
};

// Insert gamification sample data
const insertGamificationData = async () => {
  try {
    // Insert sample games
    await pool.execute(`
      INSERT INTO games (name, description, max_points, difficulty) VALUES
      ('Number Memory', 'Remember and repeat the sequence of numbers', 1000, 'easy'),
      ('Color Match', 'Match the colors in the correct sequence', 1500, 'medium'),
      ('Speed Click', 'Click the targets as fast as possible', 2000, 'hard'),
      ('Pattern Recognition', 'Identify and complete the pattern', 1800, 'medium'),
      ('Math Challenge', 'Solve math problems quickly', 2500, 'hard')
    `);

    // Insert reward tiers
    await pool.execute(`
      INSERT INTO rewards (name, description, points_required, discount_percentage, max_discount_amount) VALUES
      ('Bronze Saver', 'Get 1% off your next booking', 1000, 1.00, 50.00),
      ('Silver Saver', 'Get 3% off your next booking', 3000, 3.00, 150.00),
      ('Gold Saver', 'Get 5% off your next booking', 5000, 5.00, 250.00),
      ('Platinum Saver', 'Get 8% off your next booking', 8000, 8.00, 400.00),
      ('Diamond Saver', 'Get 10% off your next booking', 10000, 10.00, 500.00),
      ('Elite Saver', 'Get 15% off your next booking', 15000, 15.00, 750.00),
      ('Champion Saver', 'Get 20% off your next booking', 20000, 20.00, 1000.00)
    `);

    console.log('🎮 Gamification sample data inserted successfully');
   } catch (error) {
     console.error('Error inserting gamification data:', error);
   }
 };
 
 export default pool;