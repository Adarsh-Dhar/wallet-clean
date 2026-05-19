module deepclean_spam::fake_foundation_nft {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct FounderPass has key, store { id: UID }
    public struct FAKE_FOUNDATION_NFT has drop {}

    fun init(witness: FAKE_FOUNDATION_NFT, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<FounderPass>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"),        string::utf8(b"Sui Foundation VIP Founder Pass"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Exclusive NFT for early Sui community members."));
        display::add(&mut disp, string::utf8(b"link"),        string::utf8(b"https://suі.io/founder-claim"));
        display::add(&mut disp, string::utf8(b"image_url"),   string::utf8(b"https://sui.io/og-image.png"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub,  ctx.sender());
    }

    public entry fun mint(recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(
            FounderPass { id: object::new(ctx) },
            recipient
        );
    }
}