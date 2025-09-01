import mysql from 'mysql2/promise';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '..', '.env') });

async function fixWalletNullValues() {
  let connection;
  
  try {
    // Create connection
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'taxi_booking'
    });
    
    console.log('Connected to MySQL database');
    
    // Check for NULL wallet_balance values
    const [nullBalances] = await connection.execute(
      'SELECT id, email, wallet_balance FROM users WHERE wallet_balance IS NULL'
    );
    
    if (nullBalances.length > 0) {
      console.log('\n=== Users with NULL wallet_balance ===');
      nullBalances.forEach(user => {
        console.log(`User ID: ${user.id}, Email: ${user.email}, Balance: ${user.wallet_balance}`);
      });
      
      // Fix NULL values by setting them to 0.00
      const [result] = await connection.execute(
        'UPDATE users SET wallet_balance = 0.00 WHERE wallet_balance IS NULL'
      );
      
      console.log(`\n✅ Fixed ${result.affectedRows} NULL wallet_balance values`);
    } else {
      console.log('\n✅ No NULL wallet_balance values found');
    }
    
    // Check for users with wallet_enabled = NULL
    const [nullEnabled] = await connection.execute(
      'SELECT id, email, wallet_enabled FROM users WHERE wallet_enabled IS NULL'
    );
    
    if (nullEnabled.length > 0) {
      console.log('\n=== Users with NULL wallet_enabled ===');
      nullEnabled.forEach(user => {
        console.log(`User ID: ${user.id}, Email: ${user.email}, Enabled: ${user.wallet_enabled}`);
      });
      
      // Fix NULL values by setting them to TRUE
      const [result] = await connection.execute(
        'UPDATE users SET wallet_enabled = TRUE WHERE wallet_enabled IS NULL'
      );
      
      console.log(`\n✅ Fixed ${result.affectedRows} NULL wallet_enabled values`);
    } else {
      console.log('\n✅ No NULL wallet_enabled values found');
    }
    
    // Check for any string or invalid values in wallet_balance
    const [invalidBalances] = await connection.execute(
      "SELECT id, email, wallet_balance FROM users WHERE wallet_balance REGEXP '[^0-9.-]'"
    );
    
    if (invalidBalances.length > 0) {
      console.log('\n=== Users with invalid wallet_balance values ===');
      invalidBalances.forEach(user => {
        console.log(`User ID: ${user.id}, Email: ${user.email}, Balance: ${user.wallet_balance}`);
      });
    } else {
      console.log('\n✅ No invalid wallet_balance values found');
    }
    
    // Show final state
    const [finalState] = await connection.execute(
      'SELECT COUNT(*) as total, MIN(wallet_balance) as min_balance, MAX(wallet_balance) as max_balance, AVG(wallet_balance) as avg_balance FROM users WHERE wallet_balance IS NOT NULL'
    );
    
    console.log('\n=== Final Wallet State ===');
    console.log(`Total users: ${finalState[0].total}`);
    console.log(`Min balance: ${finalState[0].min_balance}`);
    console.log(`Max balance: ${finalState[0].max_balance}`);
    console.log(`Avg balance: ${parseFloat(finalState[0].avg_balance).toFixed(2)}`);
    
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    if (connection) {
      await connection.end();
      console.log('\nDatabase connection closed');
    }
  }
}

fixWalletNullValues();