module deepclean_spam::marketplace_escrow {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct EscrowTicket has key, store { id: UID }
    public struct MARKETPLACE_ESCROW has drop {}

    fun init(witness: MARKETPLACE_ESCROW, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<EscrowTicket>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"), string::utf8(b"Escrowed Item — Pending Sale"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Your item is held in escrow on FakeMarket. Click to resolve."));
        display::add(&mut disp, string::utf8(b"link"), string::utf8(b"https://fake-market.xyz/resolve"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub, ctx.sender());
    }

    public entry fun mint(recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(EscrowTicket { id: object::new(ctx) }, recipient);
    }
}
