use cairo_vm::felt::Felt252;
use num_traits::Zero;

use crate::{
    definitions::constants::SUPPORTED_VERSIONS,
    state::state_api::{State, StateReader},
    utils::Address,
};

use super::error::TransactionError;

pub fn verify_version(
    version: &Felt252,
    max_fee: u128,
    nonce: &Felt252,
    signature: &Vec<Felt252>,
) -> Result<(), TransactionError> {
    if !SUPPORTED_VERSIONS.contains(version) {
        return Err(TransactionError::UnsupportedVersion(version.to_string()));
    }

    if version == &0.into() {
        if max_fee != 0 {
            return Err(TransactionError::InvalidMaxFee);
        }
        if nonce != &0.into() {
            return Err(TransactionError::InvalidNonce);
        }
        if !signature.is_empty() {
            return Err(TransactionError::InvalidSignature);
        }
    }

    Ok(())
}

pub fn handle_nonce<S: State + StateReader>(
    transaction_nonce: &Felt252,
    version: &Felt252,
    address: &Address,
    state: &mut S,
) -> Result<(), TransactionError> {
    if version.is_zero() {
        return Ok(());
    }

    // retrieve the contract's current nonce from the state
    let actual = state.get_nonce_at(address)?;
    let expected = transaction_nonce.clone();

    // check that the transaction nonce is the same as the one from the state
    if actual != expected {
        let address = address.clone();
        return Err(TransactionError::InvalidTransactionNonce {
            address,
            actual,
            expected,
        });
    }

    // increment the nonce for this contract.
    state.increment_nonce(address)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::transaction::error::TransactionError;

    use super::verify_version;

    #[test]
    fn version_0_with_max_fee_0_nonce_0_and_empty_signature_should_return_ok() {
        let version = 0.into();
        let max_fee = 0;
        let nonce = 0.into();
        let signature = vec![];
        let result = verify_version(&version, max_fee, &nonce, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn version_1_should_return_ok() {
        let version = 1.into();
        let max_fee = 2;
        let nonce = 3.into();
        let signature = vec![5.into()];
        let result = verify_version(&version, max_fee, &nonce, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn version_2_should_return_ok() {
        let version = 2.into();
        let max_fee = 43;
        let nonce = 4.into();
        let signature = vec![6.into()];
        let result = verify_version(&version, max_fee, &nonce, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn version_3_should_fail() {
        let version = 3.into();
        let max_fee = 0;
        let nonce = 0.into();
        let signature = vec![];
        let result = verify_version(&version, max_fee, &nonce, &signature).unwrap_err();
        assert_matches!(result, TransactionError::UnsupportedVersion(_));
    }

    #[test]
    fn version_0_with_max_fee_greater_than_0_should_fail() {
        let version = 0.into();
        let max_fee = 1;
        let nonce = 0.into();
        let signature = vec![];
        let result = verify_version(&version, max_fee, &nonce, &signature).unwrap_err();
        assert_matches!(result, TransactionError::InvalidMaxFee);
    }

    #[test]
    fn version_0_with_nonce_greater_than_0_should_fail() {
        let version = 0.into();
        let max_fee = 0;
        let nonce = 1.into();
        let signature = vec![];
        let result = verify_version(&version, max_fee, &nonce, &signature).unwrap_err();
        assert_matches!(result, TransactionError::InvalidNonce);
    }

    #[test]
    fn version_0_with_non_empty_signature_should_fail() {
        let version = 0.into();
        let max_fee = 0;
        let nonce = 0.into();
        let signature = vec![2.into()];
        let result = verify_version(&version, max_fee, &nonce, &signature).unwrap_err();
        assert_matches!(result, TransactionError::InvalidSignature);
    }
}
