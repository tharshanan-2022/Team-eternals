import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'taxi_booking'
};

const addWalletColumns = async () => {
  let connection;
  
  try {
    connection = await mysql.createConnection(dbConfig);
    console.log('🔗 Connected to database');
    
    // Add wallet columns to users table
    try {
      await connection.execute(`
        ALTER TABLE users 
        ADD COLUMN wallet_balance DECIMAL(10,2) DEFAULT 0.00,
        ADD COLUMN wallet_enabled BOOLEAN DEFAULT TRUE
      `);
      console.log('✅ Added wallet_balance and wallet_enabled columns to users table');
    } catch (error) {
      if (error.code === 'ER_DUP_FIELDNAME') {
        console.log('ℹ️ Wallet columns already exist in users table');
      } else {
        console.error('❌ Error adding wallet columns:', error.message);
      }
    }
    
    // Create wallet_transactions table
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS wallet_transactions (
          id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
          user_id VARCHAR(36) NOT NULL,
          transaction_type ENUM('credit', 'debit', 'reward_conversion', 'booking_payment', 'refund') NOT NULL,
          amount DECIMAL(10,2) NOT NULL,
          balance_before DECIMAL(10,2) NOT NULL,
          balance_after DECIMAL(10,2) NOT NULL,
          description TEXT,
          reference_id VARCHAR(36),
          reference_type ENUM('booking', 'reward', 'topup', 'refund', 'admin') DEFAULT 'topup',
          status ENUM('pending', 'completed', 'failed', 'cancelled') DEFAULT 'completed',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          INDEX idx_user_id (user_id),
          INDEX idx_transaction_type (transaction_type),
          INDEX idx_status (status),
          INDEX idx_created_at (created_at)
        )
      `);
      console.log('✅ Created wallet_transactions table');
    } catch (error) {
      console.error('❌ Error creating wallet_transactions table:', error.message);
    }
    
    // Create wallet_topup_methods table
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS wallet_topup_methods (
          id INT AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(100) NOT NULL,
          type ENUM('credit_card', 'debit_card', 'bank_transfer', 'digital_wallet') NOT NULL,
          min_amount DECIMAL(10,2) DEFAULT 10.00,
          max_amount DECIMAL(10,2) DEFAULT 1000.00,
          processing_fee_percentage DECIMAL(5,2) DEFAULT 0.00,
          is_active BOOLEAN DEFAULT TRUE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Created wallet_topup_methods table');
    } catch (error) {
      console.error('❌ Error creating wallet_topup_methods table:', error.message);
    }
    
    // Create wallet_settings table
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS wallet_settings (
          id INT AUTO_INCREMENT PRIMARY KEY,
          setting_key VARCHAR(100) NOT NULL UNIQUE,
          setting_value TEXT NOT NULL,
          description TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Created wallet_settings table');
    } catch (error) {
      console.error('❌ Error creating wallet_settings table:', error.message);
    }
    
    // Create reward_conversions table for points to money conversion
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS reward_conversions (
          id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
          user_id VARCHAR(36) NOT NULL,
          points_used INT NOT NULL,
          money_earned DECIMAL(10,2) NOT NULL,
          conversion_rate DECIMAL(10,4) NOT NULL,
          transaction_id VARCHAR(36),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY (transaction_id) REFERENCES wallet_transactions(id) ON DELETE SET NULL,
          INDEX idx_user_id (user_id),
          INDEX idx_created_at (created_at)
        )
      `);
      console.log('✅ Created reward_conversions table');
    } catch (error) {
      console.error('❌ Error creating reward_conversions table:', error.message);
    }
    
    // Insert default top-up methods
    try {
      await connection.execute(`
        INSERT IGNORE INTO wallet_topup_methods (name, type, min_amount, max_amount, processing_fee_percentage) VALUES
        ('Credit Card', 'credit_card', 10.00, 1000.00, 2.50),
        ('Debit Card', 'debit_card', 10.00, 500.00, 1.50),
        ('Bank Transfer', 'bank_transfer', 50.00, 2000.00, 0.00),
        ('Digital Wallet', 'digital_wallet', 5.00, 500.00, 1.00)
      `);
      console.log('✅ Inserted default top-up methods');
    } catch (error) {
      console.error('❌ Error inserting top-up methods:', error.message);
    }
    
    // Insert default wallet settings
    try {
      await connection.execute(`
        INSERT IGNORE INTO wallet_settings (setting_key, setting_value, description) VALUES
        ('min_balance', '0.00', 'Minimum wallet balance allowed'),
        ('max_balance', '10000.00', 'Maximum wallet balance allowed'),
        ('daily_topup_limit', '2000.00', 'Daily top-up limit per user'),
        ('monthly_topup_limit', '10000.00', 'Monthly top-up limit per user'),
        ('wallet_enabled', 'true', 'Global wallet system enable/disable')
      `);
      console.log('✅ Inserted default wallet settings');
    } catch (error) {
      console.error('❌ Error inserting wallet settings:', error.message);
    }
    
    console.log('🎉 Wallet setup completed successfully!');
    
  } catch (error) {
    console.error('❌ Database connection error:', error.message);
  } finally {
    if (connection) {
      await connection.end();
      console.log('🔌 Database connection closed');
    }
  }
};

addWalletColumns().catch(console.error);