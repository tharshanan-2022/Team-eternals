import mysql from 'mysql2/promise';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '..', '.env') });

async function removeDuplicateTopupMethods() {
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
    
    // Get all topup methods before cleanup
    const [beforeRows] = await connection.execute(
      'SELECT COUNT(*) as total FROM wallet_topup_methods'
    );
    console.log(`Total topup methods before cleanup: ${beforeRows[0].total}`);
    
    // Remove duplicates, keeping only the one with the lowest ID for each name
    const [result] = await connection.execute(`
      DELETE t1 FROM wallet_topup_methods t1
      INNER JOIN wallet_topup_methods t2 
      WHERE t1.name = t2.name 
      AND t1.id > t2.id
    `);
    
    console.log(`Removed ${result.affectedRows} duplicate records`);
    
    // Get all topup methods after cleanup
    const [afterRows] = await connection.execute(
      'SELECT COUNT(*) as total FROM wallet_topup_methods'
    );
    console.log(`Total topup methods after cleanup: ${afterRows[0].total}`);
    
    // Show remaining methods
    const [remainingMethods] = await connection.execute(
      'SELECT id, name, type, is_active FROM wallet_topup_methods ORDER BY name'
    );
    
    console.log('\n=== Remaining Topup Methods ===');
    remainingMethods.forEach(method => {
      console.log(`ID: ${method.id}, Name: ${method.name}, Type: ${method.type}, Active: ${method.is_active}`);
    });
    
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    if (connection) {
      await connection.end();
      console.log('\nDatabase connection closed');
    }
  }
}

removeDuplicateTopupMethods();