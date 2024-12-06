//! run with `cargo test --features testing`

use assert_matches::assert_matches;
use blockifier::{
    blockifier::stateful_validator::{StatefulValidator, StatefulValidatorError},
    context::BlockContext,
    state::cached_state::CachedState,
    test_utils::{CairoVersion, contracts::FeatureContract, dict_state_reader::DictStateReader},
    transaction::{
        account_transaction::{AccountTransaction, ExecutionFlags},
        errors::{TransactionFeeError, TransactionPreValidationError},
    },
};
use starknet_api::{
    class_hash, compiled_class_hash, contract_address,
    transaction::{InvokeTransaction as ApiInvokeTx, InvokeTransactionV1},
};
use starknet_api::{
    executable_transaction::{AccountTransaction as Transaction, InvokeTransaction},
    transaction::TransactionHash,
};

fn state() -> CachedState<DictStateReader> {
    let class_hash = class_hash!("0x1337");
    let compiled_class_hash = compiled_class_hash!(0x1337);
    let class = FeatureContract::AccountWithLongValidate(CairoVersion::Cairo1).get_runnable_class();
    let address = contract_address!("0x80085");

    let mut dict = DictStateReader::default();

    dict.class_hash_to_class.insert(class_hash, class);
    dict.class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash);
    dict.address_to_class_hash.insert(address, class_hash);

    CachedState::new(dict)
}

fn validator() -> StatefulValidator<DictStateReader> {
    let block_context = BlockContext::create_for_account_testing();
    StatefulValidator::create(state(), block_context)
}

#[test]
fn test_stateful_validator_skip_all() {
    // ------------------------------------------------
    // Start setup

    let mut validator = validator();

    // setup the transaction to execute

    let execution_flags =
        ExecutionFlags { charge_fee: true, nonce_check: true, only_query: true, validate: true };

    let sender = contract_address!("0x80085");

    let tx = ApiInvokeTx::V1(InvokeTransactionV1 { sender_address: sender, ..Default::default() });
    let tx = Transaction::Invoke(InvokeTransaction { tx, tx_hash: TransactionHash::default() });
    let tx = AccountTransaction { execution_flags, tx };

    // Finish setup
    // ------------------------------------------------

    let initial_nonce = validator.get_nonce(sender).expect("failed to get initial nonce");

    let skip_validate = true;
    let skip_fee_check = false;

    validator
        .perform_validations(tx, skip_validate, skip_fee_check)
        .expect("failed to validate transaction");

    // check nonce is update
    let new_nonce = validator.get_nonce(sender).expect("failed to get initial nonce");
    assert_eq!(initial_nonce.try_increment().unwrap(), new_nonce);
}

#[test]
fn test_stateful_validator_fail_account_validation() {
    // ------------------------------------------------
    // Start setup

    let mut validator = validator();

    // setup the transaction to execute

    let execution_flags =
        ExecutionFlags { charge_fee: true, nonce_check: true, only_query: true, validate: true };

    let sender = contract_address!("0x80085");

    let tx = ApiInvokeTx::V1(InvokeTransactionV1 { sender_address: sender, ..Default::default() });
    let tx = Transaction::Invoke(InvokeTransaction { tx, tx_hash: TransactionHash::default() });
    let tx = AccountTransaction { execution_flags, tx };

    // Finish setup
    // ------------------------------------------------

    let initial_nonce = validator.get_nonce(sender).expect("failed to get initial nonce");

    let skip_validate = false;
    let skip_fee_check = true;

    let err = validator
        .perform_validations(tx, skip_validate, skip_fee_check)
        .expect_err("should fail due to no signature");

    assert_matches!(err, StatefulValidatorError::TransactionExecutionError(..));

    // check nonce isn't updated
    let new_nonce = validator.get_nonce(sender).expect("failed to get initial nonce");
    assert_eq!(initial_nonce, new_nonce);
}

#[test]
fn test_stateful_validator_fail_fee_check() {
    // ------------------------------------------------
    // Start setup

    let mut validator = validator();

    // setup the transaction to execute

    let execution_flags =
        ExecutionFlags { charge_fee: true, nonce_check: true, only_query: true, validate: true };

    let sender = contract_address!("0x80085");

    let tx = ApiInvokeTx::V1(InvokeTransactionV1 { sender_address: sender, ..Default::default() });
    let tx = Transaction::Invoke(InvokeTransaction { tx, tx_hash: TransactionHash::default() });
    let tx = AccountTransaction { execution_flags, tx };

    // Finish setup
    // ------------------------------------------------

    let initial_nonce = validator.get_nonce(sender).expect("failed to get initial nonce");

    let skip_validate = true;
    let skip_fee_check = false;

    let err = validator
        .perform_validations(tx, skip_validate, skip_fee_check)
        .expect_err("should fail due to no balance");

    assert_matches!(
        err,
        StatefulValidatorError::TransactionPreValidationError(
            TransactionPreValidationError::TransactionFeeError(
                TransactionFeeError::MaxFeeTooLow { .. }
            )
        )
    );

    // check nonce isn't updated
    let new_nonce = validator.get_nonce(sender).expect("failed to get initial nonce");
    assert_eq!(initial_nonce, new_nonce);
}
