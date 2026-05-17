-- Add burn_tx_digest column to threats table
ALTER TABLE "threats"
ADD COLUMN IF NOT EXISTS burn_tx_digest text;
