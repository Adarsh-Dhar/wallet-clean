module deepclean_spam::swap_tracker {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct SwapReceipt has key, store { id: UID }
    public struct SWAP_TRACKER has drop {}

    fun init(witness: SWAP_TRACKER, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<SwapReceipt>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"), string::utf8(b"Swap Receipt — Unsettled Swap"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Your token swap appears to be pending. Click to check details."));
        display::add(&mut disp, string::utf8(b"link"), string::utf8(b"https://fake-dex.xyz/swap/claim"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub, ctx.sender());
    }

    public entry fun mint(recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(SwapReceipt { id: object::new(ctx) }, recipient);
    }
}
