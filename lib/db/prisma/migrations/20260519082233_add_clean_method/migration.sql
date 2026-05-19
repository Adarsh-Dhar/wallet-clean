-- AlterTable
ALTER TABLE "threats" ADD COLUMN     "clean_method" TEXT NOT NULL DEFAULT 'transfer_to_dead';
