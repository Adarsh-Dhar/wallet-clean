/// DeepClean Quarantine Vault
///
/// Provides an on-chain escrow for suspected spam/phishing objects on Sui.
/// The agent backend mints a QuarantinedAsset record when it detects a threat,
/// and the owner can later release or burn the record once the dashboard verdict
/// is reviewed.
///
/// Design notes:
/// - The vault stores *metadata* about the quarantined object, not the object
///   itself (Move's type-erasing limitations mean we cannot generically wrap
///   any arbitrary object without knowing its type at compile time).
/// - The walrus_blob_id field links every quarantine record to an immutable
///   Walrus off-chain AI-analysis log, satisfying the Walrus track requirement.
/// - Admin capability follows the "capability pattern" — only the address that
///   deployed the contract holds AdminCap and can quarantine/release/burn on
///   behalf of the agent.
module deepclean::quarantine_vault {
    use sui::event;
    use std::string::{Self, String};
    use std::vector;
    use sui::coin::{Self, Coin};

    // ────────────────────────────────────────────────────────────────────────
    // Errors
    // ────────────────────────────────────────────────────────────────────────
    const ENotQuarantined: u64 = 2;

    // ────────────────────────────────────────────────────────────────────────
    // Status constants
    // ────────────────────────────────────────────────────────────────────────
    const STATUS_QUARANTINED: u8 = 0;
    const STATUS_RELEASED:    u8 = 1;
    const STATUS_BURNED:      u8 = 2;

    // ────────────────────────────────────────────────────────────────────────
    // Capability — held by the deployer / agent backend
    // ────────────────────────────────────────────────────────────────────────
    public struct AdminCap has key, store {
        id: UID,
    }

    // ────────────────────────────────────────────────────────────────────────
    // Core object — one per quarantined asset
    // ────────────────────────────────────────────────────────────────────────
    public struct QuarantinedAsset has key, store {
        id: UID,
        /// Sui object ID of the suspect asset (32 bytes hex string)
        object_id: String,
        /// Full Move type string, e.g. "0xspam::fake_nft::FakeNFT"
        object_type: String,
        /// Address that sent the asset to the monitored wallet
        sender_address: address,
        /// Risk score 0–100 assigned by the AI agent
        risk_score: u8,
        /// Verdict: 0=SAFE, 1=SUSPICIOUS, 2=MALICIOUS
        verdict: u8,
        /// Reason code: 1=honeypot 2=phishing 3=spoofed 4=spam 5=unknown
        reason_code: u8,
        /// Confidence 0–100 (stored as integer percentage)
        confidence_pct: u8,
        /// Walrus blob ID linking to the immutable AI analysis log
        walrus_blob_id: String,
        /// Current status
        status: u8,
    }

    // ────────────────────────────────────────────────────────────────────────
    // Events
    // ────────────────────────────────────────────────────────────────────────
    public struct AssetQuarantined has copy, drop {
        asset_id: ID,
        object_id: String,
        risk_score: u8,
        verdict: u8,
    }

    public struct AssetReleased has copy, drop {
        asset_id: ID,
        object_id: String,
    }

    public struct AssetBurned has copy, drop {
        asset_id: ID,
        object_id: String,
    }

    // ────────────────────────────────────────────────────────────────────────
    // Init — called once at publish time; sends AdminCap to deployer
    // ────────────────────────────────────────────────────────────────────────
    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, ctx.sender());
    }

    // ────────────────────────────────────────────────────────────────────────
    // Quarantine — agent calls this after AI analysis flags a threat
    // ────────────────────────────────────────────────────────────────────────
    public fun quarantine(
        _cap: &AdminCap,
        object_id: vector<u8>,
        object_type: vector<u8>,
        sender_address: address,
        risk_score: u8,
        verdict: u8,
        reason_code: u8,
        confidence_pct: u8,
        walrus_blob_id: vector<u8>,
        ctx: &mut TxContext,
    ): ID {
        let asset = QuarantinedAsset {
            id: object::new(ctx),
            object_id: string::utf8(object_id),
            object_type: string::utf8(object_type),
            sender_address,
            risk_score,
            verdict,
            reason_code,
            confidence_pct,
            walrus_blob_id: string::utf8(walrus_blob_id),
            status: STATUS_QUARANTINED,
        };

        let asset_id = object::id(&asset);

        event::emit(AssetQuarantined {
            asset_id,
            object_id: asset.object_id,
            risk_score,
            verdict,
        });

        transfer::share_object(asset);
        asset_id
    }

    // ────────────────────────────────────────────────────────────────────────
    // Release — owner reviewed and cleared the asset
    // ────────────────────────────────────────────────────────────────────────
    public fun release(
        _cap: &AdminCap,
        asset: &mut QuarantinedAsset,
    ) {
        assert!(asset.status == STATUS_QUARANTINED, ENotQuarantined);
        asset.status = STATUS_RELEASED;
        event::emit(AssetReleased {
            asset_id: object::id(asset),
            object_id: asset.object_id,
        });
    }

    // ────────────────────────────────────────────────────────────────────────
    // Burn — permanently mark as destroyed (object stays on chain, status = 2)
    // ────────────────────────────────────────────────────────────────────────
    public fun burn(
        _cap: &AdminCap,
        asset: &mut QuarantinedAsset,
    ) {
        assert!(asset.status == STATUS_QUARANTINED, ENotQuarantined);
        asset.status = STATUS_BURNED;
        event::emit(AssetBurned {
            asset_id: object::id(asset),
            object_id: asset.object_id,
        });
    }

    // ── Dead-address sink (used for actual object disposal) ───────────────
    const DEAD_ADDRESS: address = @0x0;

    /// Transfer a spam object to the dead address so it leaves the user's wallet.
    /// The caller must pass the object as a generic with `store` ability.
    /// This is a separate entry from `burn()` — burn() only marks the metadata
    /// record; this function moves the real object off-chain.
    public entry fun send_to_dead<T: key + store>(
        _cap: &AdminCap,
        obj: T,
        _ctx: &mut TxContext,
    ) {
        transfer::public_transfer(obj, DEAD_ADDRESS);
    }

    /// Merge all dust coins into the primary coin then send the combined
    /// amount to the dead address, effectively removing all dust in one PTB.
    /// `primary` is the coin that absorbs the others; `dusts` is the remainder.
    public entry fun merge_and_send_dust<T>(
        _cap: &AdminCap,
        mut primary: Coin<T>,
        mut dusts: vector<Coin<T>>,
        _ctx: &mut TxContext,
    ) {
        let mut i = 0;
        let len = vector::length(&dusts);
        while (i < len) {
            coin::join(&mut primary, vector::pop_back(&mut dusts));
            i = i + 1;
        };
        vector::destroy_empty(dusts);
        transfer::public_transfer(primary, DEAD_ADDRESS);
    }

    // ────────────────────────────────────────────────────────────────────────
    // View helpers
    // ────────────────────────────────────────────────────────────────────────
    public fun status(asset: &QuarantinedAsset): u8 { asset.status }
    public fun risk_score(asset: &QuarantinedAsset): u8 { asset.risk_score }
    public fun verdict(asset: &QuarantinedAsset): u8 { asset.verdict }
    public fun walrus_blob_id(asset: &QuarantinedAsset): &String { &asset.walrus_blob_id }

    // ────────────────────────────────────────────────────────────────────────
    // Constants re-exported for test modules
    // ────────────────────────────────────────────────────────────────────────
    public fun quarantined_status(): u8 { STATUS_QUARANTINED }
    public fun released_status(): u8 { STATUS_RELEASED }
    public fun burned_status(): u8 { STATUS_BURNED }
}
