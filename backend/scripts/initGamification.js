import { executeQuery } from '../config/database.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function initGamification() {
  try {
    console.log('Starting gamification database initialization...');
    
    // Read the SQL file
    const sqlFilePath = path.join(__dirname, '..', 'setup-gamification.sql');
    const sqlContent = fs.readFileSync(sqlFilePath, 'utf8');
    
    // Split SQL commands by semicolon and filter out empty commands
    const sqlCommands = sqlContent
      .split(';')
      .map(cmd => cmd.trim())
      .filter(cmd => cmd.length > 0 && !cmd.startsWith('--') && !cmd.startsWith('/*'));
    
    console.log(`Found ${sqlCommands.length} SQL commands to execute...`);
    
    // Execute each command
    for (let i = 0; i < sqlCommands.length; i++) {
      const command = sqlCommands[i];
      if (command.toLowerCase().includes('select ')) {
        // Skip SELECT statements that are just messages
        continue;
      }
      
      try {
        console.log(`Executing command ${i + 1}/${sqlCommands.length}...`);
        await executeQuery(command);
      } catch (error) {
        // Some commands might fail if tables/columns already exist, that's okay
        if (error.code === 'ER_DUP_FIELDNAME' || 
            error.code === 'ER_TABLE_EXISTS_ERROR' ||
            error.code === 'ER_DUP_ENTRY') {
          console.log(`Command ${i + 1} skipped (already exists):`, error.message);
        } else {
          console.error(`Error executing command ${i + 1}:`, error.message);
          console.log('Command was:', command);
        }
      }
    }
    
    console.log('Gamification database initialization completed!');
    
    // Verify the setup by checking if tables exist
    try {
      const games = await executeQuery('SELECT COUNT(*) as count FROM games');
      const rewards = await executeQuery('SELECT COUNT(*) as count FROM rewards');
      console.log(`Verification: ${games[0].count} games and ${rewards[0].count} rewards available`);
    } catch (error) {
      console.error('Verification failed:', error.message);
    }
    
  } catch (error) {
    console.error('Failed to initialize gamification database:', error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  initGamification().then(() => {
    console.log('Script completed successfully!');
    process.exit(0);
  }).catch(error => {
    console.error('Script failed:', error);
    process.exit(1);
  });
}

export { initGamification };