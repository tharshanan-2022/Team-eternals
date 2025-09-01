import { executeQuery } from './config/database.js';

// Generate trip ID (same as in bookings.js)
const generateTripId = () => {
  const prefix = 'TB';
  const timestamp = Date.now().toString().slice(-6);
  const random = Math.random().toString(36).substring(2, 6).toUpperCase();
  return `${prefix}${timestamp}${random}`;
};

async function testTripId() {
  try {
    // Generate a test trip ID
    const testTripId = generateTripId();
    console.log('Generated Trip ID:', testTripId);
    
    // Check recent bookings
    const recentBookings = await executeQuery(
      'SELECT trip_id, customer_name, created_at FROM bookings ORDER BY created_at DESC LIMIT 3'
    );
    
    console.log('Recent bookings from database:');
    recentBookings.forEach(booking => {
      console.log(`- Trip ID: ${booking.trip_id}, Customer: ${booking.customer_name}`);
    });
    
  } catch (error) {
    console.error('Error:', error);
  }
  
  process.exit(0);
}

testTripId();