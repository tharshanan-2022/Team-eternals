import mysql from 'mysql2/promise';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '..', '.env') });

async function checkWalletSchema() {
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
    
    // Check users table schema for wallet_balance column
    const [columns] = await connection.execute(
      "SHOW COLUMNS FROM users LIKE 'wallet_balance'"
    );
    
    if (columns.length > 0) {
      console.log('\n=== wallet_balance Column Schema ===');
      console.log('Field:', columns[0].Field);
      console.log('Type:', columns[0].Type);
      console.log('Null:', columns[0].Null);
      console.log('Default:', columns[0].Default);
    } else {
      console.log('❌ wallet_balance column not found in users table');
    }
    
    // Check current wallet balances
    const [balances] = await connection.execute(
      'SELECT id, wallet_balance FROM users WHERE wallet_balance IS NOT NULL ORDER BY wallet_balance DESC LIMIT 10'
    );
    
    console.log('\n=== Current Wallet Balances (Top 10) ===');
    balances.forEach(user => {
      console.log(`User ID: ${user.id}, Balance: ${user.wallet_balance}`);
    });
    
    // Check for any extremely large or problematic values
    const [extremeValues] = await connection.execute(
      'SELECT id, wallet_balance FROM users WHERE wallet_balance > 10000 OR wallet_balance < -1000'
    );
    
    if (extremeValues.length > 0) {
      console.log('\n=== Extreme Wallet Balance Values ===');
      extremeValues.forEach(user => {
        console.log(`User ID: ${user.id}, Balance: ${user.wallet_balance}`);
      });
    } else {
      console.log('\n✅ No extreme wallet balance values found');
    }
    
    // Check wallet_transactions table schema
    const [transactionColumns] = await connection.execute(
      "SHOW COLUMNS FROM wallet_transactions WHERE Field IN ('amount', 'balance_before', 'balance_after')"
    );
    
    console.log('\n=== wallet_transactions Table Schema ===');
    transactionColumns.forEach(col => {
      console.log(`${col.Field}: ${col.Type}`);
    });
    
    // Check for any problematic transaction amounts
    const [largeTransactions] = await connection.execute(
      'SELECT id, user_id, amount, balance_before, balance_after FROM wallet_transactions WHERE ABS(amount) > 10000 OR ABS(balance_after) > 10000 LIMIT 5'
    );
    
    if (largeTransactions.length > 0) {
      console.log('\n=== Large Transaction Values ===');
      largeTransactions.forEach(tx => {
        console.log(`TX ID: ${tx.id}, User: ${tx.user_id}, Amount: ${tx.amount}, Balance After: ${tx.balance_after}`);
      });
    } else {
      console.log('\n✅ No extremely large transaction values found');
    }
    
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    if (connection) {
      await connection.end();
      console.log('\nDatabase connection closed');
    }
  }
}

checkWalletSchema();