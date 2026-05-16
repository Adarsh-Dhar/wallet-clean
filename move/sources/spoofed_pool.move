module deepclean_spam::pool {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct Position has key, store { id: UID }
    public struct POOL has drop {}

    fun init(witness: POOL, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<Position>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"),        string::utf8(b"Cetus LP Position"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Your liquidity position in the Cetus AMM pool."));
        display::add(&mut disp, string::utf8(b"link"),        string::utf8(b"https://cetus.zone/position/{id}"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub,  ctx.sender());
    }

    public fun fake_mint(ctx: &mut TxContext) {
        transfer::public_transfer(Position { id: object::new(ctx) }, ctx.sender());
    }

    public fun collect_fees(_pos: &Position, _ctx: &mut TxContext) {
        abort 0
    }
}