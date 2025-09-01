-- Update user_rewards table to support voucher functionality
ALTER TABLE user_rewards 
ADD COLUMN voucher_code VARCHAR(50) AFTER discount_amount,
ADD COLUMN status ENUM('redeemed', 'used', 'expired') DEFAULT 'redeemed' AFTER voucher_code,
ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP AFTER status,
ADD COLUMN used_at TIMESTAMP NULL AFTER redeemed_at;

-- Add indexes for the new columns
ALTER TABLE user_rewards 
ADD INDEX idx_voucher_code (voucher_code),
ADD INDEX idx_status (status);