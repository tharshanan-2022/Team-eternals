-- Digital Wallet System Database Schema
USE taxi_booking;

-- Add wallet balance to users table
ALTER TABLE users 
ADD COLUMN wallet_balance DECIMAL(10,2) DEFAULT 0.00,
ADD COLUMN wallet_enabled BOOLEAN DEFAULT TRUE;

-- Create wallet_transactions table for tracking all wallet activities
CREATE TABLE IF NOT EXISTS wallet_transactions (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  user_id VARCHAR(36) NOT NULL,
  transaction_type ENUM('credit', 'debit', 'reward_conversion', 'booking_payment', 'refund') NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  balance_before DECIMAL(10,2) NOT NULL,
  balance_after DECIMAL(10,2) NOT NULL,
  description TEXT,
  reference_id VARCHAR(36), -- booking_id, reward_id, etc.
  reference_type ENUM('booking', 'reward', 'topup', 'refund', 'admin') DEFAULT 'topup',
  status ENUM('pending', 'completed', 'failed', 'cancelled') DEFAULT 'completed',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_id (user_id),
  INDEX idx_transaction_type (transaction_type),
  INDEX idx_status (status),
  INDEX idx_created_at (created_at)
);

-- Create wallet_topup_methods table for payment methods
CREATE TABLE IF NOT EXISTS wallet_topup_methods (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  name VARCHAR(255) NOT NULL,
  type ENUM('credit_card', 'debit_card', 'bank_transfer', 'paypal', 'stripe', 'razorpay') NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  min_amount DECIMAL(10,2) DEFAULT 10.00,
  max_amount DECIMAL(10,2) DEFAULT 10000.00,
  processing_fee_percentage DECIMAL(5,2) DEFAULT 0.00,
  processing_fee_fixed DECIMAL(10,2) DEFAULT 0.00,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_is_active (is_active)
);

-- Create reward_conversions table for points to money conversion
CREATE TABLE IF NOT EXISTS reward_conversions (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  user_id VARCHAR(36) NOT NULL,
  points_used INT NOT NULL,
  money_earned DECIMAL(10,2) NOT NULL,
  conversion_rate DECIMAL(10,4) NOT NULL, -- points per dollar
  transaction_id VARCHAR(36),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (transaction_id) REFERENCES wallet_transactions(id) ON DELETE SET NULL,
  INDEX idx_user_id (user_id),
  INDEX idx_created_at (created_at)
);

-- Create wallet_settings table for system configuration
CREATE TABLE IF NOT EXISTS wallet_settings (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  setting_key VARCHAR(255) UNIQUE NOT NULL,
  setting_value TEXT NOT NULL,
  description TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default wallet settings
INSERT INTO wallet_settings (setting_key, setting_value, description) VALUES
('points_to_money_rate', '100', 'Points required to earn 1 dollar (100 points = $1)'),
('min_conversion_points', '500', 'Minimum points required for conversion to money'),
('max_daily_conversion', '50.00', 'Maximum money that can be earned per day from points'),
('wallet_max_balance', '5000.00', 'Maximum wallet balance allowed'),
('min_topup_amount', '10.00', 'Minimum amount for wallet top-up'),
('max_topup_amount', '1000.00', 'Maximum amount for single wallet top-up');

-- Insert default top-up methods
INSERT INTO wallet_topup_methods (name, type, min_amount, max_amount, processing_fee_percentage) VALUES
('Credit Card', 'credit_card', 10.00, 1000.00, 2.9),
('Debit Card', 'debit_card', 10.00, 1000.00, 1.5),
('Bank Transfer', 'bank_transfer', 25.00, 5000.00, 0.0),
('PayPal', 'paypal', 10.00, 2000.00, 3.4),
('Stripe', 'stripe', 5.00, 1000.00, 2.9);

-- Update demo user with wallet balance
UPDATE users SET wallet_balance = 25.50 WHERE id = 'demo-user-1';

-- Insert sample wallet transactions for demo user
INSERT INTO wallet_transactions (user_id, transaction_type, amount, balance_before, balance_after, description, reference_type) VALUES
('demo-user-1', 'credit', 50.00, 0.00, 50.00, 'Initial wallet top-up via Credit Card', 'topup'),
('demo-user-1', 'reward_conversion', 15.00, 50.00, 65.00, 'Converted 1500 points to wallet money', 'reward'),
('demo-user-1', 'debit', 25.50, 65.00, 39.50, 'Payment for booking #TXI-001', 'booking'),
('demo-user-1', 'credit', 10.00, 39.50, 49.50, 'Refund for cancelled booking', 'refund'),
('demo-user-1', 'debit', 24.00, 49.50, 25.50, 'Payment for booking #TXI-002', 'booking');

-- Insert sample reward conversion for demo user
INSERT INTO reward_conversions (user_id, points_used, money_earned, conversion_rate) VALUES
('demo-user-1', 1500, 15.00, 100.0000);

SELECT 'Digital Wallet system setup completed successfully!' as message;