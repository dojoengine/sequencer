use std::sync::Arc;

use starknet_api::core::{ContractAddress, Nonce};
use starknet_api::executable_transaction::AccountTransaction as ApiTransaction;
use thiserror::Error;

use crate::blockifier::config::TransactionExecutorConfig;
use crate::blockifier::transaction_executor::{
    BLOCK_STATE_ACCESS_ERR,
    TransactionExecutor,
    TransactionExecutorError,
};
use crate::context::{BlockContext, TransactionContext};
use crate::execution::call_info::CallInfo;
use crate::fee::fee_checks::PostValidationReport;
use crate::fee::receipt::TransactionReceipt;
use crate::state::cached_state::CachedState;
use crate::state::errors::StateError;
use crate::state::state_api::{State, StateReader};
use crate::transaction::account_transaction::AccountTransaction;
use crate::transaction::errors::{TransactionExecutionError, TransactionPreValidationError};
use crate::transaction::transaction_execution::Transaction;
use crate::transaction::transactions::ValidatableTransaction;

#[cfg(test)]
#[path = "stateful_validator_test.rs"]
pub mod stateful_validator_test;

#[derive(Debug, Error)]
pub enum StatefulValidatorError {
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error(transparent)]
    TransactionExecutionError(#[from] TransactionExecutionError),
    #[error(transparent)]
    TransactionExecutorError(#[from] TransactionExecutorError),
    #[error(transparent)]
    TransactionPreValidationError(#[from] TransactionPreValidationError),
}

pub type StatefulValidatorResult<T> = Result<T, StatefulValidatorError>;

/// Manages state related transaction validations for pre-execution flows.
pub struct StatefulValidator<S: StateReader> {
    tx_executor: TransactionExecutor<S>,
}

impl<S: StateReader> StatefulValidator<S> {
    pub fn create(state: CachedState<S>, block_context: BlockContext) -> Self {
        let tx_executor =
            TransactionExecutor::new(state, block_context, TransactionExecutorConfig::default());
        Self { tx_executor }
    }

    /// Perform validations on an account transaction.
    ///
    /// # Arguments
    ///
    /// * `tx` - The account transaction to validate.
    /// * `skip_validate` - If true, skip the account validation.
    /// * `skip_fee_check` - If true, ignore any fee related checks on the transaction and account
    ///   balance.
    ///
    /// NOTE:
    ///
    /// We add a flag specifically for avoiding fee checks to allow the pool validator
    /// in Katana to run in 'fee disabled' mode. Basically, to adapt StatefulValidator to Katana's
    /// execution flag abstraction (Katana's config that allows running in fee-disabled or
    /// no-validation mode).
    pub fn perform_validations(
        &mut self,
        tx: AccountTransaction,
        skip_validate: bool,
        skip_fee_check: bool,
    ) -> StatefulValidatorResult<()> {
        // Deploy account transactions should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        if let ApiTransaction::DeployAccount(_) = tx.tx {
            self.execute(tx)?;
            return Ok(());
        }

        let tx_context = self.tx_executor.block_context.to_tx_context(&tx);
        let fee_check = !skip_fee_check;
        self.perform_pre_validation_stage(&tx, &tx_context, fee_check)?;

        if !skip_validate {
            // `__validate__` call.
            let (_optional_call_info, actual_cost) =
                self.validate(&tx, tx_context.initial_sierra_gas())?;

            // Post validations.
            PostValidationReport::verify(&tx_context, &actual_cost)?;
        }

        // See similar comment in `run_revertible` for context.
        //
        // From what I've seen there is not suitable method that is used by both the validator and
        // the normal transaction flow where the nonce increment logic can be placed. So
        // this is manually placed here.
        //
        // TODO: find a better place to put this without needing this duplication.
        self.tx_executor
            .block_state
            .as_mut()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .increment_nonce(tx_context.tx_info.sender_address())?;

        Ok(())
    }

    fn execute(&mut self, tx: AccountTransaction) -> StatefulValidatorResult<()> {
        self.tx_executor.execute(&Transaction::Account(tx))?;
        Ok(())
    }

    fn perform_pre_validation_stage(
        &mut self,
        tx: &AccountTransaction,
        tx_context: &TransactionContext,
        fee_check: bool,
    ) -> StatefulValidatorResult<()> {
        let strict_nonce_check = false;
        // Run pre-validation in charge fee mode to perform fee and balance related checks.
        // let charge_fee = tx.enforce_fee();
        tx.perform_pre_validation_stage(
            self.tx_executor.block_state.as_mut().expect(BLOCK_STATE_ACCESS_ERR),
            tx_context,
            fee_check,
            strict_nonce_check,
        )?;

        Ok(())
    }

    fn validate(
        &mut self,
        tx: &AccountTransaction,
        mut remaining_gas: u64,
    ) -> StatefulValidatorResult<(Option<CallInfo>, TransactionReceipt)> {
        let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(tx));

        let limit_steps_by_resources = tx.enforce_fee();
        let validate_call_info = tx.validate_tx(
            self.tx_executor.block_state.as_mut().expect(BLOCK_STATE_ACCESS_ERR),
            tx_context.clone(),
            &mut remaining_gas,
            limit_steps_by_resources,
        )?;

        let tx_receipt = TransactionReceipt::from_account_tx(
            tx,
            &tx_context,
            &self
                .tx_executor
                .block_state
                .as_mut()
                .expect(BLOCK_STATE_ACCESS_ERR)
                .get_actual_state_changes()?,
            CallInfo::summarize_many(
                validate_call_info.iter(),
                &tx_context.block_context.versioned_constants,
            ),
            0,
        );

        Ok((validate_call_info, tx_receipt))
    }

    pub fn get_nonce(
        &mut self,
        account_address: ContractAddress,
    ) -> StatefulValidatorResult<Nonce> {
        Ok(self
            .tx_executor
            .block_state
            .as_ref()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .get_nonce_at(account_address)?)
    }
}
