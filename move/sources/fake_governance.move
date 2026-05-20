module deepclean_spam::fake_governance {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct GovernanceToken has key, store { id: UID }
    public struct FAKE_GOVERNANCE has drop {}

    fun init(witness: FAKE_GOVERNANCE, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<GovernanceToken>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"), string::utf8(b"Governance Token — Vote Now"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Participate in the FakeDAO vote to receive rewards."));
        display::add(&mut disp, string::utf8(b"link"), string::utf8(b"https://fake-dao.xyz/vote"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub, ctx.sender());
    }

    public entry fun mint(recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(GovernanceToken { id: object::new(ctx) }, recipient);
    }
}
