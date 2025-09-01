import { executeQuery } from '../config/database.js';

async function updateUserRewardsTable() {
  try {
    console.log('Starting user_rewards table update...');
    
    // Add voucher_code column
    try {
      await executeQuery(`
        ALTER TABLE user_rewards 
        ADD COLUMN voucher_code VARCHAR(50)
      `);
      console.log('✅ Added voucher_code column');
    } catch (error) {
      if (error.code === 'ER_DUP_FIELDNAME') {
        console.log('ℹ️ voucher_code column already exists');
      } else {
        throw error;
      }
    }
    
    // Add status column
    try {
      await executeQuery(`
        ALTER TABLE user_rewards 
        ADD COLUMN status ENUM('redeemed', 'used', 'expired') DEFAULT 'redeemed'
      `);
      console.log('✅ Added status column');
    } catch (error) {
      if (error.code === 'ER_DUP_FIELDNAME') {
        console.log('ℹ️ status column already exists');
      } else {
        throw error;
      }
    }
    
    // Add created_at column
    try {
      await executeQuery(`
        ALTER TABLE user_rewards 
        ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      `);
      console.log('✅ Added created_at column');
    } catch (error) {
      if (error.code === 'ER_DUP_FIELDNAME') {
        console.log('ℹ️ created_at column already exists');
      } else {
        throw error;
      }
    }
    
    // Add used_at column
    try {
      await executeQuery(`
        ALTER TABLE user_rewards 
        ADD COLUMN used_at TIMESTAMP NULL
      `);
      console.log('✅ Added used_at column');
    } catch (error) {
      if (error.code === 'ER_DUP_FIELDNAME') {
        console.log('ℹ️ used_at column already exists');
      } else {
        throw error;
      }
    }
    
    // Add indexes
    try {
      await executeQuery(`
        ALTER TABLE user_rewards 
        ADD INDEX idx_voucher_code (voucher_code)
      `);
      console.log('✅ Added voucher_code index');
    } catch (error) {
      if (error.code === 'ER_DUP_KEYNAME') {
        console.log('ℹ️ voucher_code index already exists');
      } else {
        throw error;
      }
    }
    
    try {
      await executeQuery(`
        ALTER TABLE user_rewards 
        ADD INDEX idx_status (status)
      `);
      console.log('✅ Added status index');
    } catch (error) {
      if (error.code === 'ER_DUP_KEYNAME') {
        console.log('ℹ️ status index already exists');
      } else {
        throw error;
      }
    }
    
    console.log('🎉 user_rewards table update completed successfully!');
    
  } catch (error) {
    console.error('❌ Error updating user_rewards table:', error);
    process.exit(1);
  }
}

updateUserRewardsTable();