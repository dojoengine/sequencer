use std::sync::Arc;

use axum::body::{Bytes, HttpBody};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use blockifier::context::ChainInfo;
use blockifier::test_utils::CairoVersion;
use mempool_test_utils::starknet_api_test_utils::invoke_tx;
use mockall::predicate::eq;
use starknet_api::core::ContractAddress;
use starknet_api::rpc_transaction::RpcTransaction;
use starknet_api::transaction::TransactionHash;
use starknet_mempool_types::communication::MockMempoolClient;
use starknet_mempool_types::mempool_types::{Account, AccountState, MempoolInput, ThinTransaction};

use crate::compilation::GatewayCompiler;
use crate::config::{
    GatewayCompilerConfig,
    StatefulTransactionValidatorConfig,
    StatelessTransactionValidatorConfig,
};
use crate::gateway::{add_tx, AppState, SharedMempoolClient};
use crate::state_reader_test_utils::{local_test_state_reader_factory, TestStateReaderFactory};
use crate::stateful_transaction_validator::StatefulTransactionValidator;
use crate::stateless_transaction_validator::StatelessTransactionValidator;
use crate::utils::{external_tx_to_account_tx, get_tx_hash};

pub fn app_state(
    mempool_client: SharedMempoolClient,
    state_reader_factory: TestStateReaderFactory,
) -> AppState {
    AppState {
        stateless_tx_validator: StatelessTransactionValidator {
            config: StatelessTransactionValidatorConfig {
                validate_non_zero_l1_gas_fee: true,
                max_calldata_length: 10,
                max_signature_length: 2,
                max_bytecode_size: 10000,
                max_raw_class_size: 1000000,
                ..Default::default()
            },
        },
        stateful_tx_validator: Arc::new(StatefulTransactionValidator {
            config: StatefulTransactionValidatorConfig::create_for_testing(),
        }),
        gateway_compiler: GatewayCompiler { config: GatewayCompilerConfig {} },
        state_reader_factory: Arc::new(state_reader_factory),
        mempool_client,
    }
}

type SenderAddress = ContractAddress;

fn create_tx() -> (RpcTransaction, SenderAddress) {
    let tx = invoke_tx(CairoVersion::Cairo1);
    let sender_address = match &tx {
        RpcTransaction::Invoke(starknet_api::rpc_transaction::RpcInvokeTransaction::V3(
            invoke_tx,
        )) => invoke_tx.sender_address,
        _ => panic!("Unexpected transaction type"),
    };
    (tx, sender_address)
}

#[tokio::test]
async fn test_add_tx() {
    let (tx, sender_address) = create_tx();
    let tx_hash = calculate_hash(&tx);

    let mut mock_mempool_client = MockMempoolClient::new();
    mock_mempool_client
        .expect_add_tx()
        .once()
        .with(eq(MempoolInput {
            tx: ThinTransaction { sender_address, tx_hash, tip: *tx.tip(), nonce: *tx.nonce() },
            account: Account { sender_address, state: AccountState { nonce: *tx.nonce() } },
        }))
        .return_once(|_| Ok(()));
    let state_reader_factory = local_test_state_reader_factory(CairoVersion::Cairo1, false);
    let app_state = app_state(Arc::new(mock_mempool_client), state_reader_factory);

    let response = add_tx(State(app_state), tx.into()).await.into_response();

    let status_code = response.status();
    let response_bytes = &to_bytes(response).await;

    assert_eq!(status_code, StatusCode::OK, "{response_bytes:?}");
    assert_eq!(tx_hash, serde_json::from_slice(response_bytes).unwrap());
}

async fn to_bytes(res: Response) -> Bytes {
    res.into_body().collect().await.unwrap().to_bytes()
}

fn calculate_hash(external_tx: &RpcTransaction) -> TransactionHash {
    let optional_class_info = match &external_tx {
        RpcTransaction::Declare(_declare_tx) => {
            panic!("Declare transactions are not supported in this test")
        }
        _ => None,
    };

    let account_tx = external_tx_to_account_tx(
        external_tx,
        optional_class_info,
        &ChainInfo::create_for_testing().chain_id,
    )
    .unwrap();
    get_tx_hash(&account_tx)
}
