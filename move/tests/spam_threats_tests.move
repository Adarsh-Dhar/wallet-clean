/// Move unit tests for deepclean_spam threat modules.
///
/// Run with: sui move test --path move/
#[test_only]
module deepclean_spam::spam_threats_tests {
    use deepclean_spam::fake_foundation_nft;
    use deepclean_spam::honeypot_defi;
    use deepclean_spam::malicious_airdrop;
    use deepclean_spam::pool;
    use deepclean_spam::rug_token;
    use sui::test_scenario::{Self as ts, Scenario};

    const OWNER: address = @0xBEEF;

    fun scenario(): Scenario { ts::begin(OWNER) }

    #[test]
    fun test_malicious_airdrop_mints() {
        let mut s = scenario();
        ts::next_tx(&mut s, OWNER);
        malicious_airdrop::mint(OWNER, ts::ctx(&mut s));
        ts::end(s);
    }

    #[test]
    fun test_fake_foundation_nft_mints() {
        let mut s = scenario();
        ts::next_tx(&mut s, OWNER);
        fake_foundation_nft::mint(OWNER, ts::ctx(&mut s));
        ts::end(s);
    }

    #[test]
    fun test_rug_token_airdrop_mints() {
        let mut s = scenario();
        ts::next_tx(&mut s, OWNER);
        rug_token::airdrop_to(OWNER, ts::ctx(&mut s));
        ts::end(s);
    }

    #[test]
    fun test_spoofed_pool_mints() {
        let mut s = scenario();
        ts::next_tx(&mut s, OWNER);
        pool::mint(OWNER, ts::ctx(&mut s));
        ts::end(s);
    }

    #[test]
    fun test_honeypot_stake_mints() {
        let mut s = scenario();
        ts::next_tx(&mut s, OWNER);
        honeypot_defi::stake_and_receive(OWNER, ts::ctx(&mut s));
        ts::end(s);
    }

    #[test]
    #[expected_failure(abort_code = 999)]
    fun test_honeypot_withdraw_aborts() {
        let mut s = scenario();
        ts::next_tx(&mut s, OWNER);
        honeypot_defi::stake_and_receive(OWNER, ts::ctx(&mut s));
        ts::next_tx(&mut s, OWNER);
        let token = ts::take_from_address<honeypot_defi::HoneypotToken>(&mut s, OWNER);
        honeypot_defi::withdraw(token, ts::ctx(&mut s));
        ts::end(s);
    }
}