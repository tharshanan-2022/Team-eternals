import express from 'express';
import crypto from 'crypto';
import { executeQuery, executeTransaction } from '../config/database.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Helper function to retry transaction on deadlock
async function executeTransactionWithRetry(queries, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await executeTransaction(queries);
    } catch (error) {
      if (error.code === 'ER_LOCK_DEADLOCK' && attempt < maxRetries) {
        console.log(`Deadlock detected, retrying transaction (attempt ${attempt}/${maxRetries})`);
        const delay = Math.random() * Math.pow(2, attempt) * 100;
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
}

// Get wallet balance and recent transactions
router.get('/balance', authenticateToken, async (req, res) => {
  try {
    // Get user wallet info
    const userRows = await executeQuery(
      'SELECT wallet_balance, wallet_enabled, points FROM users WHERE id = ?',
      [req.user.id]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userRows[0];

    // Get recent transactions
    const transactions = await executeQuery(`
      SELECT 
        id,
        transaction_type,
        amount,
        balance_after,
        description,
        reference_type,
        status,
        created_at
      FROM wallet_transactions 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 10
    `, [req.user.id]);

    // Get wallet settings for conversion rates
    const settings = await executeQuery(
      'SELECT setting_key, setting_value FROM wallet_settings'
    );

    const settingsMap = {};
    settings.forEach(setting => {
      settingsMap[setting.setting_key] = setting.setting_value;
    });

    res.json({
      balance: parseFloat(user.wallet_balance),
      enabled: user.wallet_enabled,
      points: user.points,
      transactions,
      settings: {
        pointsToMoneyRate: parseInt(settingsMap.points_to_money_rate || 100),
        minConversionPoints: parseInt(settingsMap.min_conversion_points || 500),
        maxDailyConversion: parseFloat(settingsMap.max_daily_conversion || 50),
        maxBalance: parseFloat(settingsMap.wallet_max_balance || 5000)
      }
    });
  } catch (error) {
    console.error('Error fetching wallet balance:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get available top-up methods
router.get('/topup-methods', authenticateToken, async (req, res) => {
  try {
    const methods = await executeQuery(
      'SELECT * FROM wallet_topup_methods WHERE is_active = TRUE ORDER BY name'
    );
    res.json(methods);
  } catch (error) {
    console.error('Error fetching top-up methods:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Top-up wallet
router.post('/topup', authenticateToken, async (req, res) => {
  try {
    const { amount, methodId, paymentDetails } = req.body;

    // Validate and sanitize amount
    const numericAmount = parseFloat(amount);
    if (!amount || isNaN(numericAmount) || numericAmount <= 0 || numericAmount > 999999.99) {
      return res.status(400).json({ error: 'Invalid amount. Must be between $0.01 and $999,999.99' });
    }

    if (!methodId) {
      return res.status(400).json({ error: 'Payment method is required' });
    }

    // Get user current balance
    const userRows = await executeQuery(
      'SELECT wallet_balance, wallet_enabled FROM users WHERE id = ?',
      [req.user.id]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userRows[0];

    if (!user.wallet_enabled) {
      return res.status(400).json({ error: 'Wallet is disabled for this user' });
    }

    // Get payment method details
    const methodRows = await executeQuery(
      'SELECT * FROM wallet_topup_methods WHERE id = ? AND is_active = TRUE',
      [methodId]
    );

    if (methodRows.length === 0) {
      return res.status(404).json({ error: 'Payment method not found' });
    }

    const method = methodRows[0];

    // Validate amount limits
    if (numericAmount < method.min_amount || numericAmount > method.max_amount) {
      return res.status(400).json({ 
        error: `Amount must be between $${method.min_amount} and $${method.max_amount}` 
      });
    }

    // Calculate processing fee with validation
    const processingFee = (numericAmount * parseFloat(method.processing_fee_percentage) / 100) + parseFloat(method.processing_fee_fixed);
    const netAmount = numericAmount - processingFee;
    
    // Validate current balance
    const currentBalance = parseFloat(user.wallet_balance || 0);
    if (isNaN(currentBalance) || currentBalance < 0) {
      return res.status(400).json({ error: 'Invalid current wallet balance' });
    }
    
    const newBalance = currentBalance + netAmount;
    
    // Validate calculated values are within safe ranges
    if (isNaN(netAmount) || isNaN(newBalance) || netAmount <= 0 || newBalance > 999999.99) {
      return res.status(400).json({ error: 'Calculated values are out of valid range' });
    }

    // Check maximum balance limit
    const settings = await executeQuery(
      'SELECT setting_value FROM wallet_settings WHERE setting_key = "wallet_max_balance"'
    );
    const maxBalance = parseFloat(settings[0]?.setting_value || 5000);

    if (newBalance > maxBalance) {
      return res.status(400).json({ 
        error: `Wallet balance cannot exceed $${maxBalance}` 
      });
    }

    // Simulate payment processing (in real app, integrate with payment gateway)
    const paymentSuccess = await simulatePaymentProcessing(numericAmount, method.type, paymentDetails);

    if (!paymentSuccess.success) {
      return res.status(400).json({ error: paymentSuccess.error });
    }

    // Execute wallet top-up transaction
    await executeTransactionWithRetry([
      {
        sql: 'UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?',
        params: [netAmount, req.user.id]
      },
      {
        sql: `INSERT INTO wallet_transactions 
              (user_id, transaction_type, amount, balance_before, balance_after, description, reference_type, status) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        params: [
          req.user.id,
          'credit',
          netAmount,
          currentBalance,
          newBalance,
          `Wallet top-up via ${method.name} (Fee: $${processingFee.toFixed(2)})`,
          'topup',
          'completed'
        ]
      }
    ]);

    res.json({
      success: true,
      amount: netAmount,
      processingFee: processingFee,
      newBalance: newBalance,
      message: `Successfully added $${netAmount.toFixed(2)} to your wallet`
    });
  } catch (error) {
    console.error('Error processing wallet top-up:', error);
    if (error.code === 'ER_LOCK_DEADLOCK') {
      res.status(503).json({ error: 'Service temporarily unavailable. Please try again.' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

// Convert points to wallet money
router.post('/convert-points', authenticateToken, async (req, res) => {
  try {
    const { points } = req.body;

    // Validate and sanitize points
    const numericPoints = parseInt(points);
    if (!points || isNaN(numericPoints) || numericPoints <= 0 || numericPoints > 1000000) {
      return res.status(400).json({ error: 'Invalid points amount. Must be between 1 and 1,000,000' });
    }

    // Get user data
    const userRows = await executeQuery(
      'SELECT points, wallet_balance, wallet_enabled FROM users WHERE id = ?',
      [req.user.id]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userRows[0];

    if (!user.wallet_enabled) {
      return res.status(400).json({ error: 'Wallet is disabled for this user' });
    }

    if (user.points < numericPoints) {
      return res.status(400).json({ error: 'Insufficient points' });
    }

    // Get conversion settings
    const settings = await executeQuery(`
      SELECT setting_key, setting_value FROM wallet_settings 
      WHERE setting_key IN ('points_to_money_rate', 'min_conversion_points', 'max_daily_conversion')
    `);

    const settingsMap = {};
    settings.forEach(setting => {
      settingsMap[setting.setting_key] = setting.setting_value;
    });

    const conversionRate = parseInt(settingsMap.points_to_money_rate || 100);
    const minPoints = parseInt(settingsMap.min_conversion_points || 500);
    const maxDailyConversion = parseFloat(settingsMap.max_daily_conversion || 50);

    if (numericPoints < minPoints) {
      return res.status(400).json({ 
        error: `Minimum ${minPoints} points required for conversion` 
      });
    }

    // Check daily conversion limit
    const today = new Date().toISOString().split('T')[0];
    const dailyConversions = await executeQuery(`
      SELECT COALESCE(SUM(money_earned), 0) as total_converted 
      FROM reward_conversions 
      WHERE user_id = ? AND DATE(created_at) = ?
    `, [req.user.id, today]);

    const todayConverted = parseFloat(dailyConversions[0].total_converted || 0);
    const moneyToEarn = numericPoints / conversionRate;
    
    // Validate calculated money amount
    if (isNaN(moneyToEarn) || moneyToEarn <= 0 || moneyToEarn > 999999.99) {
      return res.status(400).json({ error: 'Calculated money amount is out of valid range' });
    }

    if (todayConverted + moneyToEarn > maxDailyConversion) {
      return res.status(400).json({ 
        error: `Daily conversion limit of $${maxDailyConversion} would be exceeded` 
      });
    }

    const currentBalance = parseFloat(user.wallet_balance || 0);
    if (isNaN(currentBalance) || currentBalance < 0) {
      return res.status(400).json({ error: 'Invalid current wallet balance' });
    }
    
    const newBalance = currentBalance + moneyToEarn;
    
    // Validate new balance is within safe range
    if (isNaN(newBalance) || newBalance > 999999.99) {
      return res.status(400).json({ error: 'New balance would exceed maximum allowed amount' });
    }

    // Generate UUID for the wallet transaction
    const transactionId = crypto.randomUUID();

    // Execute conversion transaction
    const results = await executeTransactionWithRetry([
      {
        sql: 'UPDATE users SET points = points - ?, wallet_balance = wallet_balance + ? WHERE id = ?',
        params: [numericPoints, moneyToEarn, req.user.id]
      },
      {
        sql: `INSERT INTO wallet_transactions 
              (id, user_id, transaction_type, amount, balance_before, balance_after, description, reference_type, status) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        params: [
          transactionId,
          req.user.id,
          'reward_conversion',
          moneyToEarn,
          currentBalance,
          newBalance,
          `Converted ${numericPoints} points to wallet money`,
          'reward',
          'completed'
        ]
      },
      {
        sql: `INSERT INTO reward_conversions (user_id, points_used, money_earned, conversion_rate, transaction_id) 
              VALUES (?, ?, ?, ?, ?)`,
        params: [req.user.id, numericPoints, moneyToEarn, conversionRate, transactionId]
      }
    ]);

    res.json({
      success: true,
      pointsUsed: numericPoints,
      moneyEarned: moneyToEarn,
      newBalance: newBalance,
      remainingPoints: user.points - numericPoints,
      message: `Successfully converted ${numericPoints} points to $${moneyToEarn.toFixed(2)}`
    });
  } catch (error) {
    console.error('Error converting points to money:', error);
    if (error.code === 'ER_LOCK_DEADLOCK') {
      res.status(503).json({ error: 'Service temporarily unavailable. Please try again.' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

// Process wallet payment for booking
router.post('/pay', authenticateToken, async (req, res) => {
  try {
    const { amount, bookingId, description } = req.body;

    // Validate and sanitize amount
    const numericAmount = parseFloat(amount);
    if (!amount || isNaN(numericAmount) || numericAmount <= 0 || numericAmount > 999999.99) {
      return res.status(400).json({ error: 'Invalid amount. Must be between $0.01 and $999,999.99' });
    }

    if (!bookingId) {
      return res.status(400).json({ error: 'Booking ID is required' });
    }

    // Get user wallet balance
    const userRows = await executeQuery(
      'SELECT wallet_balance, wallet_enabled FROM users WHERE id = ?',
      [req.user.id]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userRows[0];

    if (!user.wallet_enabled) {
      return res.status(400).json({ error: 'Wallet is disabled for this user' });
    }

    const currentBalance = parseFloat(user.wallet_balance || 0);
    if (isNaN(currentBalance) || currentBalance < 0) {
      return res.status(400).json({ error: 'Invalid current wallet balance' });
    }

    if (currentBalance < numericAmount) {
      return res.status(400).json({ 
        error: 'Insufficient wallet balance',
        currentBalance: currentBalance,
        required: numericAmount
      });
    }

    const newBalance = currentBalance - numericAmount;
    
    // Validate new balance is within safe range
    if (isNaN(newBalance) || newBalance < 0) {
      return res.status(400).json({ error: 'Invalid transaction would result in negative balance' });
    }

    // Execute payment transaction
    await executeTransactionWithRetry([
      {
        sql: 'UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?',
        params: [numericAmount, req.user.id]
      },
      {
        sql: `INSERT INTO wallet_transactions 
              (user_id, transaction_type, amount, balance_before, balance_after, description, reference_id, reference_type, status) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        params: [
          req.user.id,
          'debit',
          numericAmount,
          currentBalance,
          newBalance,
          description || `Payment for booking`,
          bookingId,
          'booking',
          'completed'
        ]
      }
    ]);

    res.json({
      success: true,
      amountPaid: numericAmount,
      newBalance: newBalance,
      message: 'Payment processed successfully'
    });
  } catch (error) {
    console.error('Error processing wallet payment:', error);
    if (error.code === 'ER_LOCK_DEADLOCK') {
      res.status(503).json({ error: 'Service temporarily unavailable. Please try again.' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

// Get wallet transaction history with pagination
router.get('/transactions', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    const type = req.query.type; // Optional filter by transaction type

    let whereClause = 'WHERE user_id = ?';
    let params = [req.user.id];

    if (type) {
      whereClause += ' AND transaction_type = ?';
      params.push(type);
    }

    // Get transactions with pagination
    const transactions = await executeQuery(`
      SELECT 
        id,
        transaction_type,
        amount,
        balance_before,
        balance_after,
        description,
        reference_id,
        reference_type,
        status,
        created_at
      FROM wallet_transactions 
      ${whereClause}
      ORDER BY created_at DESC 
      LIMIT ? OFFSET ?
    `, [...params, limit, offset]);

    // Get total count for pagination
    const countResult = await executeQuery(`
      SELECT COUNT(*) as total FROM wallet_transactions ${whereClause}
    `, params);

    const total = countResult[0].total;
    const totalPages = Math.ceil(total / limit);

    res.json({
      transactions,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error fetching wallet transactions:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Toggle wallet enabled/disabled
router.post('/toggle', authenticateToken, async (req, res) => {
  try {
    const { enabled } = req.body;

    await executeQuery(
      'UPDATE users SET wallet_enabled = ? WHERE id = ?',
      [enabled, req.user.id]
    );

    res.json({
      walletEnabled: enabled,
      message: `Wallet ${enabled ? 'enabled' : 'disabled'} successfully`
    });
  } catch (error) {
    console.error('Error toggling wallet:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Simulate payment processing (replace with real payment gateway integration)
async function simulatePaymentProcessing(amount, paymentType, paymentDetails) {
  // Simulate processing delay
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Simulate random payment failures (5% failure rate)
  if (Math.random() < 0.05) {
    return {
      success: false,
      error: 'Payment processing failed. Please try again or use a different payment method.'
    };
  }

  // Validate payment details based on payment type
  if (paymentType === 'credit_card' || paymentType === 'debit_card') {
    if (!paymentDetails?.cardNumber || !paymentDetails?.expiryDate || !paymentDetails?.cvv || !paymentDetails?.cardholderName) {
      return {
        success: false,
        error: 'Invalid card details provided. Please ensure all card fields are filled.'
      };
    }
    
    // Basic card number validation (should be 13-19 digits)
    const cardNumber = paymentDetails.cardNumber.replace(/\s/g, '');
    if (!/^\d{13,19}$/.test(cardNumber)) {
      return {
        success: false,
        error: 'Invalid card number format'
      };
    }
    
    // Basic expiry date validation (MM/YY format)
    if (!/^(0[1-9]|1[0-2])\/\d{2}$/.test(paymentDetails.expiryDate)) {
      return {
        success: false,
        error: 'Invalid expiry date format. Use MM/YY format.'
      };
    }
    
    // Basic CVV validation (3-4 digits)
    if (!/^\d{3,4}$/.test(paymentDetails.cvv)) {
      return {
        success: false,
        error: 'Invalid CVV format'
      };
    }
  }
  
  else if (paymentType === 'bank_transfer') {
    if (!paymentDetails?.bankName || !paymentDetails?.accountNumber || !paymentDetails?.routingNumber || !paymentDetails?.accountHolderName) {
      return {
        success: false,
        error: 'Invalid bank transfer details. Please ensure all bank fields are filled.'
      };
    }
    
    // Basic account number validation (6-17 digits)
    if (!/^\d{6,17}$/.test(paymentDetails.accountNumber)) {
      return {
        success: false,
        error: 'Invalid account number format'
      };
    }
    
    // Basic routing number validation (9 digits for US)
    if (!/^\d{9}$/.test(paymentDetails.routingNumber)) {
      return {
        success: false,
        error: 'Invalid routing number format. Must be 9 digits.'
      };
    }
  }
  
  else if (paymentType === 'digital_wallet') {
    if (!paymentDetails?.walletProvider || !paymentDetails?.email) {
      return {
        success: false,
        error: 'Invalid digital wallet details. Please select a provider and provide email.'
      };
    }
    
    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(paymentDetails.email)) {
      return {
        success: false,
        error: 'Invalid email address format'
      };
    }
    
    // Validate wallet ID based on provider
    if (paymentDetails.walletProvider === 'paypal' && paymentDetails.walletId) {
      if (!emailRegex.test(paymentDetails.walletId)) {
        return {
          success: false,
          error: 'Invalid PayPal email format'
        };
      }
    }
    
    if (paymentDetails.walletProvider === 'venmo' && paymentDetails.walletId) {
      if (!/^@[a-zA-Z0-9_-]+$/.test(paymentDetails.walletId)) {
        return {
          success: false,
          error: 'Invalid Venmo username format. Must start with @'
        };
      }
    }
    
    if (paymentDetails.walletProvider === 'cashapp' && paymentDetails.walletId) {
      if (!/^\$[a-zA-Z0-9_-]+$/.test(paymentDetails.walletId)) {
        return {
          success: false,
          error: 'Invalid Cash App username format. Must start with $'
        };
      }
    }
  }

  return {
    success: true,
    transactionId: `txn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    paymentMethod: paymentType
  };
}

export default router;