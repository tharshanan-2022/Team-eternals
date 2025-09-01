-- Gamification System Database Schema
USE taxi_booking;

-- Add points column to users table
ALTER TABLE users 
ADD COLUMN points INT DEFAULT 0,
ADD COLUMN total_points_earned INT DEFAULT 0,
ADD COLUMN rewards_enabled BOOLEAN DEFAULT TRUE;

-- Create games table
CREATE TABLE IF NOT EXISTS games (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  max_points INT NOT NULL,
  difficulty ENUM('easy', 'medium', 'hard') DEFAULT 'medium',
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_is_active (is_active)
);

-- Create game_sessions table
CREATE TABLE IF NOT EXISTS game_sessions (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  user_id VARCHAR(36) NOT NULL,
  game_id VARCHAR(36) NOT NULL,
  score INT NOT NULL DEFAULT 0,
  points_earned INT NOT NULL DEFAULT 0,
  duration_seconds INT,
  completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (game_id) REFERENCES games(id) ON DELETE CASCADE,
  INDEX idx_user_id (user_id),
  INDEX idx_game_id (game_id),
  INDEX idx_completed_at (completed_at)
);

-- Create rewards table
CREATE TABLE IF NOT EXISTS rewards (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  points_required INT NOT NULL,
  discount_percentage DECIMAL(5,2) NOT NULL,
  max_discount_amount DECIMAL(10,2),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_points_required (points_required),
  INDEX idx_is_active (is_active)
);

-- Create user_rewards table (for tracking redeemed rewards)
CREATE TABLE IF NOT EXISTS user_rewards (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  user_id VARCHAR(36) NOT NULL,
  reward_id VARCHAR(36) NOT NULL,
  booking_id VARCHAR(36),
  points_used INT NOT NULL,
  discount_amount DECIMAL(10,2) NOT NULL,
  voucher_code VARCHAR(50),
  status ENUM('redeemed', 'used', 'expired') DEFAULT 'redeemed',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  redeemed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  used_at TIMESTAMP NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (reward_id) REFERENCES rewards(id) ON DELETE CASCADE,
  FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE SET NULL,
  INDEX idx_user_id (user_id),
  INDEX idx_booking_id (booking_id),
  INDEX idx_redeemed_at (redeemed_at),
  INDEX idx_voucher_code (voucher_code),
  INDEX idx_status (status)
);

-- Insert sample games
INSERT INTO games (id, name, description, max_points, difficulty) VALUES
('game-1', 'Number Memory', 'Remember and repeat the sequence of numbers', 1000, 'easy'),
('game-2', 'Color Match', 'Match the colors in the correct sequence', 1500, 'medium'),
('game-3', 'Speed Click', 'Click the targets as fast as possible', 2000, 'hard'),
('game-4', 'Pattern Recognition', 'Identify and complete the pattern', 1800, 'medium'),
('game-5', 'Math Challenge', 'Solve math problems quickly', 2500, 'hard');

-- Insert reward tiers
INSERT INTO rewards (id, name, description, points_required, discount_percentage, max_discount_amount) VALUES
('reward-1', 'Bronze Saver', 'Get 1% off your next booking', 1000, 1.00, 50.00),
('reward-2', 'Silver Saver', 'Get 3% off your next booking', 3000, 3.00, 150.00),
('reward-3', 'Gold Saver', 'Get 5% off your next booking', 5000, 5.00, 250.00),
('reward-4', 'Platinum Saver', 'Get 8% off your next booking', 8000, 8.00, 400.00),
('reward-5', 'Diamond Saver', 'Get 10% off your next booking', 10000, 10.00, 500.00),
('reward-6', 'Elite Saver', 'Get 15% off your next booking', 15000, 15.00, 750.00),
('reward-7', 'Champion Saver', 'Get 20% off your next booking', 20000, 20.00, 1000.00);

-- Update demo user with some points
UPDATE users SET points = 5500, total_points_earned = 12000 WHERE id = 'demo-user-1';

-- Insert some sample game sessions for demo user
INSERT INTO game_sessions (user_id, game_id, score, points_earned, duration_seconds) VALUES
('demo-user-1', 'game-1', 850, 850, 120),
('demo-user-1', 'game-2', 1200, 1200, 180),
('demo-user-1', 'game-3', 1800, 1800, 90),
('demo-user-1', 'game-1', 950, 950, 110),
('demo-user-1', 'game-4', 1600, 1600, 200);

SELECT 'Gamification system setup completed successfully!' as message;