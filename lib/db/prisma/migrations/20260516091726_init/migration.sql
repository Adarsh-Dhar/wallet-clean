-- CreateTable
CREATE TABLE "threats" (
    "id" SERIAL NOT NULL,
    "object_id" TEXT NOT NULL,
    "object_type" TEXT NOT NULL,
    "sender_address" TEXT NOT NULL,
    "display_name" TEXT,
    "display_url" TEXT,
    "risk_score" INTEGER NOT NULL,
    "verdict" TEXT NOT NULL,
    "reason_code" INTEGER NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "flags" JSONB NOT NULL DEFAULT '[]',
    "reasoning" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'quarantined',
    "walrus_blob_id" TEXT,
    "quarantine_tx_digest" TEXT,
    "detected_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "threats_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "watched_wallets" (
    "id" SERIAL NOT NULL,
    "address" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "threats_detected" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "watched_wallets_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "watched_wallets_address_key" ON "watched_wallets"("address");
