import mysql from 'mysql2/promise';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '..', '.env') });

async function checkDuplicateTopupMethods() {
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
    
    // Check for duplicate topup methods
    const [rows] = await connection.execute(
      'SELECT id, name, type, is_active FROM wallet_topup_methods ORDER BY name, id'
    );
    
    console.log('\n=== All Topup Methods ===');
    rows.forEach(row => {
      console.log(`ID: ${row.id}, Name: ${row.name}, Type: ${row.type}, Active: ${row.is_active}`);
    });
    
    // Check for duplicates by name
    const [duplicates] = await connection.execute(
      'SELECT name, COUNT(*) as count FROM wallet_topup_methods GROUP BY name HAVING COUNT(*) > 1'
    );
    
    if (duplicates.length > 0) {
      console.log('\n=== Duplicate Names Found ===');
      duplicates.forEach(dup => {
        console.log(`Name: ${dup.name}, Count: ${dup.count}`);
      });
    } else {
      console.log('\n✅ No duplicate names found');
    }
    
    // Check for duplicates by type
    const [typeDuplicates] = await connection.execute(
      'SELECT type, COUNT(*) as count FROM wallet_topup_methods GROUP BY type HAVING COUNT(*) > 1'
    );
    
    if (typeDuplicates.length > 0) {
      console.log('\n=== Duplicate Types Found ===');
      typeDuplicates.forEach(dup => {
        console.log(`Type: ${dup.type}, Count: ${dup.count}`);
      });
    } else {
      console.log('\n✅ No duplicate types found');
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

checkDuplicateTopupMethods();