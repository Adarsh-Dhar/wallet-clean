module deepclean_spam::honeypot_defi {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct HoneypotToken has key, store { id: UID }
    public struct HONEYPOT_DEFI has drop {}

    fun init(witness: HONEYPOT_DEFI, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<HoneypotToken>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"),        string::utf8(b"SuiGold - 10x APY Yield Protocol"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Stake SUI, earn SuiGold. Withdraw anytime."));
        display::add(&mut disp, string::utf8(b"link"),        string::utf8(b"https://suigold-defi.xyz/stake"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub,  ctx.sender());
    }

    public fun stake_and_receive(ctx: &mut TxContext) {
        transfer::public_transfer(HoneypotToken { id: object::new(ctx) }, ctx.sender());
    }

    fun drain_all_hidden(_ctx: &mut TxContext) {
        abort 0
    }

    public fun withdraw(_token: HoneypotToken, _ctx: &mut TxContext) {
        abort 999
    }
}