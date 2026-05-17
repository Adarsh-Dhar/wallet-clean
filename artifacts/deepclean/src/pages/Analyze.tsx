import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useAnalyzeThreat } from "@workspace/api-client-react";
import { useState } from "react";
import { useLocation } from "wouter";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { VerdictBadge, RiskBar, ReasonLabel } from "@/components/ThreatBadge";
import { threatAnalysisSchema, type ThreatAnalysisFormValues } from "@/lib/schemas";
import { Search, AlertTriangle, ExternalLink } from "lucide-react";

const DEMO_INPUTS = [
  {
    label: "Phishing NFT",
    objectId: "0xdemo_phishing_nft_001234567890abcdef",
    objectType: "0xscammer::fake_nft::SuiFoundationNFT",
    senderAddress: "0xbad_actor_0000000000000000000001",
    displayName: "Sui Official NFT",
    displayUrl: "https://sui-0fficial.com/claim",
    moveAbi: "",
  },
  {
    label: "Spam Airdrop",
    objectId: "0xdemo_spam_token_abcdef01234567890",
    objectType: "0xspam::airdrop::FreeTokenClaim",
    senderAddress: "0xbad_actor_0000000000000000000002",
    displayName: "FREE 1000 SUI AIRDROP",
    displayUrl: "https://free-sui-tokens.xyz/mint",
    moveAbi: "",
  },
  {
    label: "Legitimate Token",
    objectId: "0xdemo_legit_token_abcdef0123456789",
    objectType: "0x2::coin::Coin",
    senderAddress: "0xlegit_issuer_000000000000000001",
    displayName: "USD Coin",
    displayUrl: "https://circle.com",
    moveAbi: "",
  },
];

export default function Analyze() {
  const [result, setResult] = useState<{
    riskScore: number;
    verdict: string;
    reasonCode: number;
    confidence: number;
    flags: string[];
    reasoning: string;
    savedThreatId?: number | null;
  } | null>(null);
  const [, setLocation] = useLocation();

  const form = useForm<ThreatAnalysisFormValues>({
    resolver: zodResolver(threatAnalysisSchema),
    defaultValues: {
      objectId: "",
      objectType: "",
      senderAddress: "",
      displayName: "",
      displayUrl: "",
      moveAbi: "",
    },
  });

  const analyze = useAnalyzeThreat({
    mutation: {
      onSuccess: (data) => {
        setResult(data);
      },
      onError: () => {
        form.setError("root", { message: "Analysis failed. Please try again." });
      },
    },
  });

  function onSubmit(values: ThreatAnalysisFormValues) {
    setResult(null);
    analyze.mutate({
      data: {
        objectId: values.objectId,
        objectType: values.objectType,
        senderAddress: values.senderAddress,
        displayName: values.displayName || null,
        displayUrl: values.displayUrl || null,
        moveAbi: values.moveAbi || null,
      },
    });
  }

  function loadDemo(demo: (typeof DEMO_INPUTS)[0]) {
    form.reset({
      objectId: demo.objectId,
      objectType: demo.objectType,
      senderAddress: demo.senderAddress,
      displayName: demo.displayName,
      displayUrl: demo.displayUrl,
      moveAbi: demo.moveAbi,
    });
    setResult(null);
  }

  return (
    <div className="p-6 max-w-3xl space-y-6">
      <div>
        <h1 className="text-xl font-bold text-foreground">Analyze Object</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Submit a Sui object for AI-powered threat analysis using GitHub Models gpt-4o
        </p>
      </div>

      {/* Demo inputs */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-muted-foreground">Try demo:</span>
        {DEMO_INPUTS.map((demo) => (
          <button
            key={demo.label}
            onClick={() => loadDemo(demo)}
            className="text-xs px-2.5 py-1 rounded border border-border text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors"
            data-testid={`demo-${demo.label.toLowerCase().replace(/\s+/g, "-")}`}
          >
            {demo.label}
          </button>
        ))}
      </div>

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          <div className="rounded-lg border border-border bg-card p-5 space-y-4">
            <FormField
              control={form.control}
              name="objectId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs text-muted-foreground uppercase tracking-wider">Object ID *</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      placeholder="0x1234567890abcdef..."
                      className="font-mono text-sm"
                      data-testid="input-object-id"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="objectType"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs text-muted-foreground uppercase tracking-wider">Object Type *</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      placeholder="0xpackage::module::Struct"
                      className="font-mono text-sm"
                      data-testid="input-object-type"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="senderAddress"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs text-muted-foreground uppercase tracking-wider">Sender Address *</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      placeholder="0xsender..."
                      className="font-mono text-sm"
                      data-testid="input-sender-address"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="displayName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-xs text-muted-foreground uppercase tracking-wider">Display Name</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="Token name..." data-testid="input-display-name" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="displayUrl"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-xs text-muted-foreground uppercase tracking-wider">Display URL</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="https://..." data-testid="input-display-url" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <FormField
              control={form.control}
              name="moveAbi"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs text-muted-foreground uppercase tracking-wider">Move ABI JSON (optional)</FormLabel>
                  <FormControl>
                    <Textarea
                      {...field}
                      placeholder='{"functions": [...], "structs": [...]}'
                      className="font-mono text-xs h-28 resize-none"
                      data-testid="input-move-abi"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          {form.formState.errors.root && (
            <div className="text-sm text-red-400 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              {form.formState.errors.root.message}
            </div>
          )}

          <Button
            type="submit"
            className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90"
            disabled={analyze.isPending}
            data-testid="button-analyze"
          >
            <Search className="w-4 h-4" />
            {analyze.isPending ? "Analyzing with GitHub Models..." : "Analyze Object"}
          </Button>
        </form>
      </Form>

      {/* Result */}
      {result && (
        <div className="rounded-lg border border-border bg-card p-5 space-y-4" data-testid="analysis-result">
          <div className="flex items-center gap-3">
            <VerdictBadge verdict={result.verdict} />
            <RiskBar score={result.riskScore} />
            <span className="text-xs text-muted-foreground ml-2">
              <ReasonLabel code={result.reasonCode} />
            </span>
          </div>

          <div className="text-sm text-muted-foreground">
            <span className="text-foreground font-medium">Confidence:</span>{" "}
            {(result.confidence * 100).toFixed(0)}%
          </div>

          <blockquote className="border-l-2 border-primary/50 pl-3 text-sm text-muted-foreground italic leading-relaxed">
            {result.reasoning}
          </blockquote>

          {result.flags.length > 0 && (
            <div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Flags</div>
              <div className="flex flex-wrap gap-2">
                {result.flags.map((f, i) => (
                  <span key={i} className="text-xs px-2 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                    {f}
                  </span>
                ))}
              </div>
            </div>
          )}

          {result.savedThreatId && (
            <div className="flex items-center gap-2 text-sm text-amber-400">
              <AlertTriangle className="w-4 h-4" />
              High-risk asset auto-quarantined.{" "}
              <button
                onClick={() => setLocation(`/threats/${result.savedThreatId}`)}
                className="underline flex items-center gap-1"
                data-testid="link-view-threat"
              >
                View threat <ExternalLink className="w-3 h-3" />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
