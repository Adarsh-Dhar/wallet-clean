module deepclean_spam::bridge_faker {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct BridgeNotification has key, store { id: UID }
    public struct BRIDGE_FAKER has drop {}

    fun init(witness: BRIDGE_FAKER, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<BridgeNotification>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"), string::utf8(b"Bridge Notification — Action Required"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Your bridge transaction is stuck. Claim here to resolve."));
        display::add(&mut disp, string::utf8(b"link"), string::utf8(b"https://fake-bridge.xyz/resolve"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub, ctx.sender());
    }

    public entry fun mint(recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(BridgeNotification { id: object::new(ctx) }, recipient);
    }
}
