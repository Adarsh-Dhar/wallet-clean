import { pgTable, serial, text, integer, real, boolean, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const threatsTable = pgTable("threats", {
  id: serial("id").primaryKey(),
  objectId: text("object_id").notNull(),
  objectType: text("object_type").notNull(),
  senderAddress: text("sender_address").notNull(),
  displayName: text("display_name"),
  displayUrl: text("display_url"),
  riskScore: integer("risk_score").notNull(),
  verdict: text("verdict").notNull(), // SAFE | SUSPICIOUS | MALICIOUS
  reasonCode: integer("reason_code").notNull(),
  confidence: real("confidence").notNull(),
  flags: jsonb("flags").$type<string[]>().notNull().default([]),
  reasoning: text("reasoning").notNull(),
  status: text("status").notNull().default("quarantined"), // quarantined | released | burned
  walrusBlobId: text("walrus_blob_id"),
  burnTxDigest: text("burn_tx_digest"),
  quarantineTxDigest: text("quarantine_tx_digest"),
  detectedAt: timestamp("detected_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const insertThreatSchema = createInsertSchema(threatsTable).omit({ id: true, detectedAt: true, updatedAt: true });
export type InsertThreat = z.infer<typeof insertThreatSchema>;
export type Threat = typeof threatsTable.$inferSelect;
