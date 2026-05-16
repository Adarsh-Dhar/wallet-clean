module deepclean_spam::malicious_airdrop {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct AirdropToken has key, store { id: UID }
    public struct MALICIOUS_AIRDROP has drop {}

    fun init(witness: MALICIOUS_AIRDROP, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<AirdropToken>(&pub, ctx);
        // Realistic urgency language — this is exactly what real spam looks like
        display::add(&mut disp, string::utf8(b"name"),        string::utf8(b"5000 SUI Airdrop — Claim Expires in 24h"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"You have been selected for the official SUI genesis airdrop."));
        display::add(&mut disp, string::utf8(b"link"),        string::utf8(b"https://sui-airdrop-2026.xyz/claim?wallet={id}"));
        display::add(&mut disp, string::utf8(b"image_url"),   string::utf8(b"https://sui-airdrop-2026.xyz/img/sui-logo.png"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub,  ctx.sender());
    }

    public fun mint(ctx: &mut TxContext) {
        transfer::public_transfer(
            AirdropToken { id: object::new(ctx) },
            ctx.sender()
        );
    }
}