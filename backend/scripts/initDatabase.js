import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';

dotenv.config();

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || ''
};

const DATABASE_NAME = process.env.DB_NAME || 'taxi_booking';

const createDatabase = async () => {
  let connection;
  
  try {
    // Connect to MySQL server (without specifying database)
    connection = await mysql.createConnection(dbConfig);
    console.log('🔗 Connected to MySQL server');
    
    // Create database if it doesn't exist
    await connection.execute(`CREATE DATABASE IF NOT EXISTS ${DATABASE_NAME}`);
    console.log(`✅ Database '${DATABASE_NAME}' created or already exists`);
    
    // Use the database
    await connection.execute(`USE ${DATABASE_NAME}`);
    
    // Create users table
    const createUsersTable = `
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_phone (phone)
      )
    `;
    
    await connection.execute(createUsersTable);
    console.log('✅ Users table created');
    
    // Create vehicles table
    const createVehiclesTable = `
      CREATE TABLE IF NOT EXISTS vehicles (
        id VARCHAR(36) PRIMARY KEY,
        type ENUM('bike', 'threewheel', 'car', 'van', 'lorry') NOT NULL,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        image VARCHAR(500),
        base_price DECIMAL(10, 2) NOT NULL,
        hourly_rate DECIMAL(10, 2) NOT NULL,
        daily_rate DECIMAL(10, 2) NOT NULL,
        features JSON,
        available BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_type (type),
        INDEX idx_available (available)
      )
    `;
    
    await connection.execute(createVehiclesTable);
    console.log('✅ Vehicles table created');
    
    // Create bookings table
    const createBookingsTable = `
      CREATE TABLE IF NOT EXISTS bookings (
        id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
        trip_id VARCHAR(20) UNIQUE NOT NULL,
        user_id VARCHAR(36),
        vehicle_id VARCHAR(36) NOT NULL,
        rental_type ENUM('location', 'hourly', 'daily') NOT NULL,
        from_date DATETIME NOT NULL,
        to_date DATETIME NOT NULL,
        pickup_location VARCHAR(500),
        dropoff_location VARCHAR(500),
        hours INT,
        days INT,
        total_fare DECIMAL(10, 2) NOT NULL,
        payment_method ENUM('cash', 'card') NOT NULL,
        customer_name VARCHAR(255) NOT NULL,
        customer_email VARCHAR(255) NOT NULL,
        customer_phone VARCHAR(20) NOT NULL,
        is_guest BOOLEAN DEFAULT TRUE,
        status ENUM('confirmed', 'completed', 'cancelled') DEFAULT 'confirmed',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id),
        INDEX idx_vehicle_id (vehicle_id),
        INDEX idx_trip_id (trip_id),
        INDEX idx_status (status),
        INDEX idx_created_at (created_at)
      )
    `;
    
    await connection.execute(createBookingsTable);
    console.log('✅ Bookings table created');
    
    // Insert sample vehicles
    const sampleVehicles = [
      {
        id: 'bike-1',
        type: 'bike',
        name: 'Standard Bike',
        description: 'Perfect for quick city rides and short distances',
        image: '/images/bike.jpg',
        base_price: 50.00,
        hourly_rate: 25.00,
        daily_rate: 200.00,
        features: JSON.stringify(['Fuel Efficient', 'Easy Parking', 'Quick Navigation'])
      },
      {
        id: 'threewheel-1',
        type: 'threewheel',
        name: 'Three Wheeler',
        description: 'Three-wheeler for city travel',
        image: '/src/assets/realistic-threewheel.svg',
        base_price: 80.00,
        hourly_rate: 40.00,
        daily_rate: 350.00,
        features: JSON.stringify(['Weather Protection', 'Affordable', 'City Specialist'])
      },
      {
        id: 'car-1',
        type: 'car',
        name: 'Sedan Car',
        description: 'Comfortable sedan for family trips',
        image: '/images/car.jpg',
        base_price: 150.00,
        hourly_rate: 75.00,
        daily_rate: 600.00,
        features: JSON.stringify(['Air Conditioning', 'Comfortable Seating', 'Safe Travel'])
      },
      {
        id: 'van-1',
        type: 'van',
        name: 'Mini Van',
        description: 'Spacious van for group travel',
        image: '/images/van.jpg',
        base_price: 250.00,
        hourly_rate: 125.00,
        daily_rate: 1000.00,
        features: JSON.stringify(['Large Capacity', 'Group Travel', 'Luggage Space'])
      },
      {
        id: 'lorry-1',
        type: 'lorry',
        name: 'Goods Lorry',
        description: 'Heavy-duty vehicle for cargo transport',
        image: '/images/lorry.jpg',
        base_price: 400.00,
        hourly_rate: 200.00,
        daily_rate: 1500.00,
        features: JSON.stringify(['Heavy Load', 'Cargo Transport', 'Professional Driver'])
      }
    ];
    
    for (const vehicle of sampleVehicles) {
      const insertVehicle = `
        INSERT IGNORE INTO vehicles (id, type, name, description, image, base_price, hourly_rate, daily_rate, features)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      
      await connection.execute(insertVehicle, [
        vehicle.id,
        vehicle.type,
        vehicle.name,
        vehicle.description,
        vehicle.image,
        vehicle.base_price,
        vehicle.hourly_rate,
        vehicle.daily_rate,
        vehicle.features
      ]);
    }
    
    console.log('✅ Sample vehicles inserted');
    
    // Create a demo user
    const hashedPassword = await bcrypt.hash('demo123', 12);
    const insertDemoUser = `
      INSERT IGNORE INTO users (email, password, name, phone, is_verified)
      VALUES (?, ?, ?, ?, ?)
    `;
    
    await connection.execute(insertDemoUser, [
      'demo@taxibooking.com',
      hashedPassword,
      'Demo User',
      '+1234567890',
      true
    ]);
    
    console.log('✅ Demo user created (email: demo@taxibooking.com, password: demo123)');
    
    console.log('\n🎉 Database initialization completed successfully!');
    console.log('\n📋 Summary:');
    console.log('   - Database created: ' + DATABASE_NAME);
    console.log('   - Tables created: users, vehicles, bookings');
    console.log('   - Sample data inserted: 5 vehicles, 1 demo user');
    console.log('\n🔐 Demo Login Credentials:');
    console.log('   Email: demo@taxibooking.com');
    console.log('   Password: demo123');
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    throw error;
  } finally {
    if (connection) {
      await connection.end();
    }
  }
};

// Run the initialization
if (import.meta.url === `file://${process.argv[1]}`) {
  createDatabase()
    .then(() => {
      console.log('\n✅ Database setup completed');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Database setup failed:', error);
      process.exit(1);
    });
}

export default createDatabase;