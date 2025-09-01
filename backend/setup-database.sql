-- Create database
CREATE DATABASE IF NOT EXISTS taxi_booking;
USE taxi_booking;

-- Create users table
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
  INDEX idx_created_at (created_at)
);

-- Create vehicles table
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
);

-- Create bookings table
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
  INDEX idx_trip_id (trip_id),
  INDEX idx_user_id (user_id),
  INDEX idx_vehicle_id (vehicle_id),
  INDEX idx_status (status),
  INDEX idx_from_date (from_date),
  INDEX idx_created_at (created_at)
);

-- Insert sample vehicles
INSERT INTO vehicles (id, type, name, description, image, base_price, hourly_rate, daily_rate, features) VALUES
('bike-1', 'bike', 'Standard Bike', 'Perfect for quick city rides and short distances', '/src/assets/realistic-bike.svg', 50.00, 25.00, 200.00, '["Helmet included", "Fuel efficient", "Easy parking"]'),
('bike-2', 'bike', 'Sports Bike', 'High-performance bike for enthusiasts', '/src/assets/realistic-bike.svg', 80.00, 40.00, 320.00, '["High performance", "Sports design", "Advanced features"]'),
('threewheel-1', 'threewheel', 'Standard Three Wheeler', 'Comfortable 3-wheeler for city travel', '/src/assets/realistic-threewheel.svg', 80.00, 40.00, 320.00, '["AC available", "3 passengers", "City specialist"]'),
('threewheel-2', 'threewheel', 'Shared Three Wheeler', 'Economical shared three wheeler', '/src/assets/realistic-threewheel.svg', 60.00, 30.00, 240.00, '["Shared ride", "Economical", "Fixed routes"]'),
('car-1', 'car', 'Sedan Car', 'Comfortable sedan for family trips', '/src/assets/realistic-car.svg', 150.00, 75.00, 600.00, '["AC", "4 passengers", "Comfortable seats", "Music system"]'),
('car-2', 'car', 'SUV', 'Spacious SUV for group travel', '/src/assets/realistic-car.svg', 200.00, 100.00, 800.00, '["7 passengers", "AC", "Large luggage space", "Premium comfort"]'),
('car-3', 'car', 'Hatchback', 'Compact car for city driving', '/src/assets/realistic-car.svg', 120.00, 60.00, 480.00, '["Fuel efficient", "Easy parking", "AC", "4 passengers"]'),
('van-1', 'van', 'Mini Van', 'Perfect for group travel and luggage', '/src/assets/realistic-van.svg', 250.00, 125.00, 1000.00, '["8 passengers", "Large luggage space", "AC", "Comfortable seating"]'),
('van-2', 'van', 'Tempo Traveller', 'Ideal for group outings and tours', '/src/assets/realistic-van.svg', 350.00, 175.00, 1400.00, '["12 passengers", "Reclining seats", "AC", "Entertainment system"]'),
('lorry-1', 'lorry', 'Small Truck', 'For moving and cargo transport', '/src/assets/realistic-lorry.svg', 300.00, 150.00, 1200.00, '["1 ton capacity", "Covered", "Loading assistance", "City permits"]'),
('lorry-2', 'lorry', 'Large Truck', 'Heavy cargo and long distance transport', '/src/assets/realistic-lorry.svg', 500.00, 250.00, 2000.00, '["5 ton capacity", "Long distance", "GPS tracking", "Professional driver"]');

-- Insert demo user (password: demo123)
INSERT INTO users (id, email, password, name, phone, is_verified) VALUES
('demo-user-1', 'demo@taxibooking.com', '$2b$10$rOzJqQqQqQqQqQqQqQqQqOzJqQqQqQqQqQqQqQqQqOzJqQqQqQqQqQ', 'Demo User', '+91 98765 43210', TRUE);

-- Insert sample bookings
INSERT INTO bookings (trip_id, user_id, vehicle_id, rental_type, from_date, to_date, pickup_location, dropoff_location, total_fare, payment_method, customer_name, customer_email, customer_phone, is_guest, status) VALUES
('TB001DEMO', 'demo-user-1', 'car-1', 'location', '2024-01-20 10:00:00', '2024-01-20 12:00:00', 'Mumbai Central', 'Bandra West', 300.00, 'card', 'Demo User', 'demo@taxibooking.com', '+91 98765 43210', FALSE, 'completed'),
('TB002DEMO', 'demo-user-1', 'threewheel-1', 'hourly', '2024-01-22 14:00:00', '2024-01-22 17:00:00', 'Andheri East', 'Powai', 240.00, 'cash', 'Demo User', 'demo@taxibooking.com', '+91 98765 43210', FALSE, 'completed'),
('TB003DEMO', 'demo-user-1', 'car-2', 'daily', '2024-01-25 09:00:00', '2024-01-27 09:00:00', 'Mumbai Airport', 'Goa', 1600.00, 'card', 'Demo User', 'demo@taxibooking.com', '+91 98765 43210', FALSE, 'confirmed');

SELECT 'Database setup completed successfully!' as message;