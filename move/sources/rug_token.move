module deepclean_spam::rug_token {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct MemeCoin has key, store { id: UID }
    public struct AdminCap has key { id: UID }
    public struct RUG_TOKEN has drop {}

    fun init(witness: RUG_TOKEN, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<MemeCoin>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"),        string::utf8(b"SuiDoge - 100x Meme Coin"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"The fastest growing meme coin on Sui."));
        display::add(&mut disp, string::utf8(b"link"),        string::utf8(b"https://suidoge-token.xyz/stake"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub,  ctx.sender());
        transfer::transfer(AdminCap { id: object::new(ctx) }, ctx.sender());
    }

    public fun airdrop_to(recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(MemeCoin { id: object::new(ctx) }, recipient);
    }

    public fun freeze_all(_cap: &AdminCap, _ctx: &mut TxContext) {
    }

    public fun migrate_funds(_cap: &AdminCap, _to: address, _ctx: &mut TxContext) {
    }
}