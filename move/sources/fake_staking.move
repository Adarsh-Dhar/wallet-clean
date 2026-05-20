module deepclean_spam::fake_staking {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct StakingReceipt has key, store {
        id: UID,
        amount_staked: u64,
        apy_percentage: u64,
    }

    public struct FAKE_STAKING has drop {}

    fun init(witness: FAKE_STAKING, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<StakingReceipt>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"), string::utf8(b"SuiStake - 50% APY Staking Receipt"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Stake your SUI and earn 50% APY. 100% secure. Early withdrawals allowed."));
        display::add(&mut disp, string::utf8(b"link"), string::utf8(b"https://suistake-platform.xyz/dashboard"));
        display::add(&mut disp, string::utf8(b"image_url"), string::utf8(b"https://suistake-platform.xyz/images/icon.png"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub, ctx.sender());
    }

    /// Mint a default staking receipt (fake amount)
    public entry fun mint(recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(
            StakingReceipt { id: object::new(ctx), amount_staked: 1000000, apy_percentage: 50 },
            recipient
        );
    }

    /// Mint with custom amount
    public entry fun mint_with_amount(recipient: address, amount: u64, ctx: &mut TxContext) {
        transfer::public_transfer(
            StakingReceipt { id: object::new(ctx), amount_staked: amount, apy_percentage: 50 },
            recipient
        );
    }

    /// Users call this to unstake — but it always fails (honeypot)
    public fun unstake(_receipt: StakingReceipt, _ctx: &mut TxContext) {
        abort 0
    }

    /// Claim rewards also fails
    public fun claim_rewards(_receipt: &StakingReceipt, _ctx: &mut TxContext) {
        abort 999
    }

    /// Read-only helper to compute fake earned rewards
    public fun get_earned_rewards(receipt: &StakingReceipt): u64 {
        // 50% APY fake reward: amount * 50 / 100
        receipt.amount_staked / 2
    }
}
