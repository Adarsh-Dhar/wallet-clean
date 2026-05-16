import { z } from "zod";

export const threatAnalysisSchema = z.object({
  objectId: z.string().min(1, "Object ID is required"),
  objectType: z.string().min(1, "Object Type is required"),
  senderAddress: z.string().min(1, "Sender Address is required"),
  displayName: z.string().optional(),
  displayUrl: z.string().optional(),
  moveAbi: z.string().optional(),
});

export type ThreatAnalysisFormValues = z.infer<typeof threatAnalysisSchema>;

export const walletSchema = z.object({
  address: z.string().min(1, "Address is required"),
  label: z.string().min(1, "Label is required"),
});

export type WalletFormValues = z.infer<typeof walletSchema>;
