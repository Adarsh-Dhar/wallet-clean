-- Migration: add wallet_address column to threats
ALTER TABLE "threats" ADD COLUMN IF NOT EXISTS wallet_address text;
