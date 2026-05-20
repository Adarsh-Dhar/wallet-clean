#[test_only]
module deepclean_spam::new_junk_tests {
    use deepclean_spam::fake_staking;
    use deepclean_spam::counterfeit_nft;
    use deepclean_spam::flash_loan_faker;
    use deepclean_spam::marketplace_escrow;
    use deepclean_spam::swap_tracker;
    use deepclean_spam::fake_governance;
    use deepclean_spam::bridge_faker;
    use deepclean_spam::subscription_token;

    #[test]
    fun test_compile_only() {
        assert!(true, 0);
    }
}
