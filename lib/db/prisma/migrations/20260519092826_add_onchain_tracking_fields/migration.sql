-- AlterTable
ALTER TABLE "threats" ADD COLUMN     "object_source" TEXT NOT NULL DEFAULT 'real',
ADD COLUMN     "on_chain_event_id" TEXT,
ADD COLUMN     "release_on_chain_tx_digest" TEXT;
