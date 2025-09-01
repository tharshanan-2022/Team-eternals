import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'taxi_booking'
};

const initializeWalletTables = async () => {
  let connection;
  
  try {
    // Connect to database
    connection = await mysql.createConnection(dbConfig);
    console.log('🔗 Connected to database');
    
    // Add wallet_balance and wallet_enabled columns to users table if they don't exist
    const addWalletColumnsToUsers = `
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS wallet_balance DECIMAL(10,2) DEFAULT 0.00,
      ADD COLUMN IF NOT EXISTS wallet_enabled BOOLEAN DEFAULT TRUE
    `;
    
    try {
      await connection.execute(addWalletColumnsToUsers);
      console.log('✅ Added wallet columns to users table');
    } catch (error) {
      if (error.code === 'ER_DUP_FIELDNAME') {
        console.log('ℹ️ Wallet columns already exist in users table');
      } else {
        throw error;
      }
    }
    
    // Create wallet_transactions table
    const createWalletTransactionsTable = `
      CREATE TABLE IF NOT EXISTS wallet_transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        transaction_type ENUM('credit', 'debit', 'reward_conversion') NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        balance_before DECIMAL(10,2) NOT NULL,
        balance_after DECIMAL(10,2) NOT NULL,
        description TEXT,
        reference_id VARCHAR(255),
        reference_type ENUM('topup', 'booking', 'reward', 'refund') NOT NULL,
        status ENUM('pending', 'completed', 'failed', 'cancelled') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id),
        INDEX idx_transaction_type (transaction_type),
        INDEX idx_reference_type (reference_type),
        INDEX idx_status (status),
        INDEX idx_created_at (created_at)
      )
    `;
    
    await connection.execute(createWalletTransactionsTable);
    console.log('✅ Wallet transactions table created');
    
    // Create wallet_topup_methods table
    const createWalletTopupMethodsTable = `
      CREATE TABLE IF NOT EXISTS wallet_topup_methods (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        type ENUM('credit_card', 'debit_card', 'paypal', 'bank_transfer', 'mobile_payment', 'digital_wallet') NOT NULL,
        description TEXT,
        min_amount DECIMAL(10,2) DEFAULT 1.00,
        max_amount DECIMAL(10,2) DEFAULT 1000.00,
        processing_fee_percentage DECIMAL(5,2) DEFAULT 0.00,
        processing_fee_fixed DECIMAL(10,2) DEFAULT 0.00,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_type (type),
        INDEX idx_is_active (is_active)
      )
    `;
    
    await connection.execute(createWalletTopupMethodsTable);
    console.log('✅ Wallet top-up methods table created');
    
    // Create reward_conversions table
    const createRewardConversionsTable = `
      CREATE TABLE IF NOT EXISTS reward_conversions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        points_used INT NOT NULL,
        money_earned DECIMAL(10,2) NOT NULL,
        conversion_rate INT NOT NULL COMMENT 'Points needed for 1 dollar',
        transaction_id INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (transaction_id) REFERENCES wallet_transactions(id) ON DELETE SET NULL,
        INDEX idx_user_id (user_id),
        INDEX idx_created_at (created_at)
      )
    `;
    
    await connection.execute(createRewardConversionsTable);
    console.log('✅ Reward conversions table created');
    
    // Create wallet_settings table
    const createWalletSettingsTable = `
      CREATE TABLE IF NOT EXISTS wallet_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        setting_key VARCHAR(100) UNIQUE NOT NULL,
        setting_value TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_setting_key (setting_key)
      )
    `;
    
    await connection.execute(createWalletSettingsTable);
    console.log('✅ Wallet settings table created');
    
    // Insert default wallet settings
    const defaultSettings = [
      ['points_to_money_rate', '100', 'Points needed to earn 1 dollar (100 points = $1)'],
      ['min_conversion_points', '500', 'Minimum points required for conversion'],
      ['max_daily_conversion', '50.00', 'Maximum dollars that can be earned per day from point conversion'],
      ['wallet_max_balance', '5000.00', 'Maximum wallet balance allowed'],
      ['wallet_enabled_by_default', 'true', 'Whether wallet is enabled for new users']
    ];
    
    for (const [key, value, description] of defaultSettings) {
      await connection.execute(
        'INSERT IGNORE INTO wallet_settings (setting_key, setting_value, description) VALUES (?, ?, ?)',
        [key, value, description]
      );
    }
    console.log('✅ Default wallet settings inserted');
    
    // Insert default top-up methods
    const defaultTopupMethods = [
      ['Credit Card', 'credit_card', 'Pay with your credit card', 5.00, 1000.00, 2.9, 0.30],
      ['Debit Card', 'debit_card', 'Pay with your debit card', 5.00, 500.00, 1.5, 0.25],
      ['PayPal', 'paypal', 'Pay with your PayPal account', 1.00, 2000.00, 3.5, 0.00],
      ['Bank Transfer', 'bank_transfer', 'Direct bank transfer', 10.00, 5000.00, 0.0, 1.00],
      ['Mobile Payment', 'mobile_payment', 'Pay with mobile wallet apps', 1.00, 1000.00, 2.0, 0.00],
      ['Digital Wallet', 'digital_wallet', 'Pay with digital wallet providers like PayPal, Apple Pay, Google Pay', 1.00, 2000.00, 2.5, 0.00]
    ];
    
    for (const [name, type, description, minAmount, maxAmount, feePercentage, feeFixed] of defaultTopupMethods) {
      await connection.execute(
        `INSERT IGNORE INTO wallet_topup_methods 
         (name, type, description, min_amount, max_amount, processing_fee_percentage, processing_fee_fixed) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [name, type, description, minAmount, maxAmount, feePercentage, feeFixed]
      );
    }
    console.log('✅ Default top-up methods inserted');
    
    // Update demo user with wallet balance if exists
    const demoUserResult = await connection.execute(
      'SELECT id FROM users WHERE email = "demo@example.com"'
    );
    
    if (demoUserResult[0].length > 0) {
      const demoUserId = demoUserResult[0][0].id;
      
      // Set demo user wallet balance
      await connection.execute(
        'UPDATE users SET wallet_balance = 25.50, wallet_enabled = TRUE WHERE id = ?',
        [demoUserId]
      );
      
      // Add sample wallet transaction for demo user
      await connection.execute(
        `INSERT IGNORE INTO wallet_transactions 
         (user_id, transaction_type, amount, balance_before, balance_after, description, reference_type, status) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [demoUserId, 'credit', 25.50, 0.00, 25.50, 'Welcome bonus - Initial wallet credit', 'topup', 'completed']
      );
      
      console.log('✅ Demo user wallet data initialized');
    }
    
    console.log('🎉 Wallet system initialization completed successfully!');
    
  } catch (error) {
    console.error('❌ Error initializing wallet system:', error);
    throw error;
  } finally {
    if (connection) {
      await connection.end();
    }
  }
};

// Run initialization if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  initializeWalletTables()
    .then(() => {
      console.log('✅ Wallet initialization completed');
      process.exit(0);
    })
    .catch((error) => {
      console.error('❌ Wallet initialization failed:', error);
      process.exit(1);
    });
}

export { initializeWalletTables };