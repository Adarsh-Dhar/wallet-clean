module deepclean_spam::counterfeit_nft {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct CounterfeitCollectable has key, store { id: UID }
    public struct COUNTERFEIT_NFT has drop {}

    fun init(witness: COUNTERFEIT_NFT, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<CounterfeitCollectable>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"), string::utf8(b"Sui Legends #1 (Verified)"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Rare collectible from the official Sui Legends collection"));
        display::add(&mut disp, string::utf8(b"link"), string::utf8(b"https://sui-legends-fake.xyz/nft/1"));
        display::add(&mut disp, string::utf8(b"image_url"), string::utf8(b"https://cdn.fake-nft.xyz/legends/1.png"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub, ctx.sender());
    }

    public entry fun mint(recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(CounterfeitCollectable { id: object::new(ctx) }, recipient);
    }
}
