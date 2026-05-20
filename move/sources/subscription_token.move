module deepclean_spam::subscription_token {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct SubscriptionToken has key, store { id: UID }
    public struct SUBSCRIPTION_TOKEN has drop {}

    fun init(witness: SUBSCRIPTION_TOKEN, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<SubscriptionToken>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"), string::utf8(b"Premium Access Subscription Token"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Unlock premium access, but renewals and withdrawals never actually work."));
        display::add(&mut disp, string::utf8(b"link"), string::utf8(b"https://premium-access.xyz/subscribe"));
        display::add(&mut disp, string::utf8(b"image_url"), string::utf8(b"https://premium-access.xyz/assets/subscription.png"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub, ctx.sender());
    }

    public entry fun mint(recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(
            SubscriptionToken { id: object::new(ctx) },
            recipient
        );
    }

    public fun renew_subscription(_token: &SubscriptionToken, _ctx: &mut TxContext) {
        abort 13
    }
}