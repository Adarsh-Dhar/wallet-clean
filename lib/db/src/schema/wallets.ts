import { pgTable, serial, text, boolean, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const watchedWalletsTable = pgTable("watched_wallets", {
  id: serial("id").primaryKey(),
  address: text("address").notNull().unique(),
  label: text("label").notNull(),
  isActive: boolean("is_active").notNull().default(true),
  threatsDetected: integer("threats_detected").notNull().default(0),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertWatchedWalletSchema = createInsertSchema(watchedWalletsTable).omit({ id: true, createdAt: true, threatsDetected: true });
export type InsertWatchedWallet = z.infer<typeof insertWatchedWalletSchema>;
export type WatchedWallet = typeof watchedWalletsTable.$inferSelect;
