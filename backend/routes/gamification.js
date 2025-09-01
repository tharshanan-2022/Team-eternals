import express from 'express';
import { executeQuery, executeTransaction } from '../config/database.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Test endpoint to verify gamification system is working
router.get('/test', async (req, res) => {
  try {
    const gameRows = await executeQuery('SELECT COUNT(*) as count FROM games');
    const rewardRows = await executeQuery('SELECT COUNT(*) as count FROM rewards');
    
    res.json({
      status: 'Gamification system is working',
      gamesCount: gameRows[0].count,
      rewardsCount: rewardRows[0].count,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error in gamification test:', error);
    res.status(500).json({ error: 'Gamification system error', message: error.message });
  }
});

// Get user's points and game stats
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const userRows = await executeQuery(
      'SELECT points, total_points_earned, rewards_enabled FROM users WHERE id = ?',
      [req.user.id]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userRows[0];

    // Get recent game sessions
    const sessionRows = await executeQuery(`
      SELECT gs.*, g.name as game_name, g.difficulty 
      FROM game_sessions gs 
      JOIN games g ON gs.game_id = g.id 
      WHERE gs.user_id = ? 
      ORDER BY gs.completed_at DESC 
      LIMIT 10
    `, [req.user.id]);

    // Get available rewards
    const rewardRows = await executeQuery(`
      SELECT * FROM rewards 
      WHERE is_active = TRUE AND points_required <= ? 
      ORDER BY points_required ASC
    `, [user.points]);

    res.json({
      points: user.points,
      totalPointsEarned: user.total_points_earned,
      rewardsEnabled: user.rewards_enabled,
      recentSessions: sessionRows,
      availableRewards: rewardRows
    });
  } catch (error) {
    console.error('Error fetching gamification profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all available games
router.get('/games', authenticateToken, async (req, res) => {
  try {
    const rows = await executeQuery(
      'SELECT * FROM games WHERE is_active = TRUE ORDER BY difficulty, name'
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching games:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start a game session
router.post('/games/:gameId/start', authenticateToken, async (req, res) => {
  try {
    const { gameId } = req.params;
    
    // Verify game exists and is active
    const gameRows = await executeQuery(
      'SELECT * FROM games WHERE id = ? AND is_active = TRUE',
      [gameId]
    );

    if (gameRows.length === 0) {
      return res.status(404).json({ error: 'Game not found or inactive' });
    }

    const game = gameRows[0];
    res.json({
      gameId: game.id,
      name: game.name,
      description: game.description,
      maxPoints: game.max_points,
      difficulty: game.difficulty,
      sessionStarted: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error starting game session:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper function to retry transaction on deadlock
async function executeTransactionWithRetry(queries, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await executeTransaction(queries);
    } catch (error) {
      if (error.code === 'ER_LOCK_DEADLOCK' && attempt < maxRetries) {
        console.log(`Deadlock detected, retrying transaction (attempt ${attempt}/${maxRetries})`);
        // Wait a random amount of time before retrying (exponential backoff)
        const delay = Math.random() * Math.pow(2, attempt) * 100;
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
}

// Submit game score and earn points
router.post('/games/:gameId/complete', authenticateToken, async (req, res) => {
  try {
    const { gameId } = req.params;
    const { score, durationSeconds } = req.body;

    if (!score || score < 0) {
      return res.status(400).json({ error: 'Invalid score' });
    }

    // Get game details
    const gameRows = await executeQuery(
      'SELECT * FROM games WHERE id = ? AND is_active = TRUE',
      [gameId]
    );

    if (gameRows.length === 0) {
      return res.status(404).json({ error: 'Game not found or inactive' });
    }

    const game = gameRows[0];
    
    // Calculate points earned (score cannot exceed max_points)
    const pointsEarned = Math.min(score, game.max_points);

    // Execute transaction with deadlock retry
    const results = await executeTransactionWithRetry([
      {
        sql: `INSERT INTO game_sessions (user_id, game_id, score, points_earned, duration_seconds) 
              VALUES (?, ?, ?, ?, ?)`,
        params: [req.user.id, gameId, score, pointsEarned, durationSeconds || null]
      },
      {
        sql: `UPDATE users 
              SET points = points + ?, total_points_earned = total_points_earned + ? 
              WHERE id = ?`,
        params: [pointsEarned, pointsEarned, req.user.id]
      },
      {
        sql: 'SELECT points, total_points_earned FROM users WHERE id = ?',
        params: [req.user.id]
      }
    ]);

    const userRows = results[2][0]; // Get the rows from the SELECT result

    res.json({
      score,
      pointsEarned,
      totalPoints: userRows[0].points,
      totalPointsEarned: userRows[0].total_points_earned,
      message: `Congratulations! You earned ${pointsEarned} points!`
    });
  } catch (error) {
    console.error('Error completing game session:', error);
    if (error.code === 'ER_LOCK_DEADLOCK') {
      res.status(503).json({ error: 'Service temporarily unavailable. Please try again.' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

// Get available rewards for user
router.get('/rewards', authenticateToken, async (req, res) => {
  try {
    const userRows = await executeQuery(
      'SELECT points FROM users WHERE id = ?',
      [req.user.id]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userPoints = userRows[0].points;

    // Get all rewards with availability status
    const rewardRows = await executeQuery(`
      SELECT *, 
        CASE WHEN points_required <= ? THEN TRUE ELSE FALSE END as available
      FROM rewards 
      WHERE is_active = TRUE 
      ORDER BY points_required ASC
    `, [userPoints]);

    res.json({
      userPoints,
      rewards: rewardRows
    });
  } catch (error) {
    console.error('Error fetching rewards:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Calculate discount for booking
router.post('/calculate-discount', authenticateToken, async (req, res) => {
  try {
    const { totalFare, rewardId } = req.body;

    if (!totalFare || totalFare <= 0) {
      return res.status(400).json({ error: 'Invalid total fare' });
    }

    // Get user points and rewards status
    const userRows = await executeQuery(
      'SELECT points, rewards_enabled FROM users WHERE id = ?',
      [req.user.id]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userRows[0];

    if (!user.rewards_enabled) {
      return res.json({
        discountApplicable: false,
        message: 'Rewards are disabled for this user'
      });
    }

    let bestReward = null;
    let discountAmount = 0;

    if (rewardId) {
      // Use specific reward
      const rewardRows = await executeQuery(
        'SELECT * FROM rewards WHERE id = ? AND is_active = TRUE',
        [rewardId]
      );

      if (rewardRows.length === 0) {
        return res.status(404).json({ error: 'Reward not found' });
      }

      const reward = rewardRows[0];
      
      if (user.points >= reward.points_required) {
        bestReward = reward;
        discountAmount = Math.min(
          (totalFare * reward.discount_percentage) / 100,
          reward.max_discount_amount || totalFare
        );
      }
    } else {
      // Find best available reward
      const rewardRows = await executeQuery(`
        SELECT * FROM rewards 
        WHERE is_active = TRUE AND points_required <= ? 
        ORDER BY discount_percentage DESC, points_required DESC 
        LIMIT 1
      `, [user.points]);

      if (rewardRows.length > 0) {
        bestReward = rewardRows[0];
        discountAmount = Math.min(
          (totalFare * bestReward.discount_percentage) / 100,
          bestReward.max_discount_amount || totalFare
        );
      }
    }

    res.json({
      discountApplicable: bestReward !== null,
      reward: bestReward,
      discountAmount: Math.round(discountAmount * 100) / 100,
      finalAmount: Math.round((totalFare - discountAmount) * 100) / 100,
      userPoints: user.points
    });
  } catch (error) {
    console.error('Error calculating discount:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Toggle rewards enabled/disabled
router.post('/toggle-rewards', authenticateToken, async (req, res) => {
  try {
    const { enabled } = req.body;

    await executeQuery(
      'UPDATE users SET rewards_enabled = ? WHERE id = ?',
      [enabled, req.user.id]
    );

    res.json({
      rewardsEnabled: enabled,
      message: `Rewards ${enabled ? 'enabled' : 'disabled'} successfully`
    });
  } catch (error) {
    console.error('Error toggling rewards:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Apply reward to booking (called during booking creation)
router.post('/apply-reward', authenticateToken, async (req, res) => {
  try {
    const { rewardId, bookingId, totalFare } = req.body;

    if (!rewardId || !bookingId || !totalFare) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Get user and reward details first
    const userRows = await executeQuery(
      'SELECT points, rewards_enabled FROM users WHERE id = ?',
      [req.user.id]
    );

    const rewardRows = await executeQuery(
      'SELECT * FROM rewards WHERE id = ? AND is_active = TRUE',
      [rewardId]
    );

    if (userRows.length === 0 || rewardRows.length === 0) {
      return res.status(404).json({ error: 'User or reward not found' });
    }

    const user = userRows[0];
    const reward = rewardRows[0];

    if (!user.rewards_enabled) {
      return res.status(400).json({ error: 'Rewards are disabled for this user' });
    }

    if (user.points < reward.points_required) {
      return res.status(400).json({ error: 'Insufficient points' });
    }

    // Calculate discount
    const discountAmount = Math.min(
      (totalFare * reward.discount_percentage) / 100,
      reward.max_discount_amount || totalFare
    );

    // Execute transaction with deadlock retry
    await executeTransactionWithRetry([
      {
        sql: 'UPDATE users SET points = points - ? WHERE id = ?',
        params: [reward.points_required, req.user.id]
      },
      {
        sql: `INSERT INTO user_rewards (user_id, reward_id, booking_id, points_used, discount_amount) 
              VALUES (?, ?, ?, ?, ?)`,
        params: [req.user.id, rewardId, bookingId, reward.points_required, discountAmount]
      }
    ]);

    res.json({
      success: true,
      discountAmount: Math.round(discountAmount * 100) / 100,
      pointsUsed: reward.points_required,
      remainingPoints: user.points - reward.points_required,
      message: `${reward.name} applied successfully!`
    });
  } catch (error) {
    console.error('Error applying reward:', error);
    if (error.code === 'ER_LOCK_DEADLOCK') {
      res.status(503).json({ error: 'Service temporarily unavailable. Please try again.' });
    } else {
      res.status(500).json({ error: error.message || 'Internal server error' });
    }
  }
});

// Redeem points for rewards (direct redemption without booking)
router.post('/redeem-reward', authenticateToken, async (req, res) => {
  try {
    const { rewardId } = req.body;

    if (!rewardId) {
      return res.status(400).json({ error: 'Reward ID is required' });
    }

    // Get user and reward details
    const userRows = await executeQuery(
      'SELECT points, rewards_enabled FROM users WHERE id = ?',
      [req.user.id]
    );

    const rewardRows = await executeQuery(
      'SELECT * FROM rewards WHERE id = ? AND is_active = TRUE',
      [rewardId]
    );

    if (userRows.length === 0 || rewardRows.length === 0) {
      return res.status(404).json({ error: 'User or reward not found' });
    }

    const user = userRows[0];
    const reward = rewardRows[0];

    if (!user.rewards_enabled) {
      return res.status(400).json({ error: 'Rewards are disabled for this user' });
    }

    if (user.points < reward.points_required) {
      return res.status(400).json({ 
        error: `Insufficient points. You have ${user.points} points but need ${reward.points_required} points.` 
      });
    }

    // For direct redemption, we'll create a voucher or credit
    const voucherCode = `REWARD-${Date.now()}-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    const rewardValue = reward.max_discount_amount || (reward.discount_percentage * 100); // Default value calculation

    // Execute transaction with deadlock retry
    await executeTransactionWithRetry([
      {
        sql: 'UPDATE users SET points = points - ? WHERE id = ?',
        params: [reward.points_required, req.user.id]
      },
      {
        sql: `INSERT INTO user_rewards (user_id, reward_id, points_used, discount_amount, voucher_code, status, created_at) 
              VALUES (?, ?, ?, ?, ?, 'redeemed', NOW())`,
        params: [req.user.id, rewardId, reward.points_required, rewardValue, voucherCode]
      }
    ]);

    res.json({
      success: true,
      reward: {
        name: reward.name,
        description: reward.description,
        value: rewardValue,
        voucherCode: voucherCode
      },
      pointsUsed: reward.points_required,
      remainingPoints: user.points - reward.points_required,
      message: `${reward.name} redeemed successfully! Your voucher code is: ${voucherCode}`
    });
  } catch (error) {
    console.error('Error redeeming reward:', error);
    if (error.code === 'ER_LOCK_DEADLOCK') {
      res.status(503).json({ error: 'Service temporarily unavailable. Please try again.' });
    } else {
      res.status(500).json({ error: error.message || 'Internal server error' });
    }
  }
});

// Get user's redeemed rewards/vouchers
router.get('/my-rewards', authenticateToken, async (req, res) => {
  try {
    const rewardRows = await executeQuery(`
      SELECT 
        ur.id,
        ur.voucher_code,
        ur.discount_amount as value,
        ur.points_used,
        ur.status,
        ur.created_at,
        ur.used_at,
        r.name as reward_name,
        r.description as reward_description
      FROM user_rewards ur
      JOIN rewards r ON ur.reward_id = r.id
      WHERE ur.user_id = ? AND ur.voucher_code IS NOT NULL
      ORDER BY ur.created_at DESC
    `, [req.user.id]);

    res.json({
      rewards: rewardRows
    });
  } catch (error) {
    console.error('Error fetching user rewards:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;