//! Transaction signing utilities.

use chia::bls::{SecretKey, Signature};
use chia::protocol::CoinSpend;
use crate::error::{WalletError, WalletResult};

/// Transaction signing context.
pub struct SigningContext {
    /// Whether this is a testnet transaction
    pub testnet: bool,
}

impl SigningContext {
    /// Create a new signing context for mainnet.
    pub fn mainnet() -> Self {
        Self { testnet: false }
    }

    /// Create a new signing context for testnet.
    pub fn testnet() -> Self {
        Self { testnet: true }
    }
}

/// Transaction signing utilities.
pub struct TransactionSigner;

impl TransactionSigner {
    /// Sign coin spends using the correct network constants (mainnet or testnet).
    ///
    /// This replaces `chia_sdk_test::sign_transaction` which hardcodes testnet constants.
    pub fn sign_coin_spends(
        coin_spends: &[CoinSpend],
        secret_key: &SecretKey,
        context: &SigningContext,
    ) -> WalletResult<Signature> {
        use chia::bls::sign;
        use chia_wallet_sdk::prelude::{
            AggSigConstants, RequiredSignature, MAINNET_CONSTANTS, TESTNET11_CONSTANTS,
        };
        use chia_wallet_sdk::clvmr::Allocator;
        use std::collections::HashMap;

        // Use correct constants based on network
        let constants = if context.testnet {
            AggSigConstants::from(&*TESTNET11_CONSTANTS)
        } else {
            AggSigConstants::from(&*MAINNET_CONSTANTS)
        };

        let mut allocator = Allocator::new();
        let required_signatures = RequiredSignature::from_coin_spends(
            &mut allocator,
            coin_spends,
            &constants,
        )
        .map_err(|e| WalletError::Transaction(format!("Failed to parse required signatures: {:?}", e)))?;

        // Map public key to secret key for signing
        let public_key = secret_key.public_key();
        let key_pairs: HashMap<_, _> = [(public_key.clone(), secret_key)].into_iter().collect();

        // Collect all BLS signatures
        let mut signatures = Vec::new();

        for required in required_signatures {
            match required {
                RequiredSignature::Bls(bls_sig) => {
                    let Some(sk) = key_pairs.get(&bls_sig.public_key) else {
                        return Err(WalletError::Transaction(format!(
                            "Missing secret key for public key: {}",
                            hex::encode(bls_sig.public_key.to_bytes())
                        )));
                    };
                    signatures.push(sign(sk, bls_sig.message()));
                }
                RequiredSignature::Secp(_) => {
                    return Err(WalletError::Transaction(
                        "SECP signatures are not supported".into(),
                    ));
                }
            }
        }

        // Aggregate all signatures
        let aggregate = signatures.iter().fold(
            Signature::default(),
            |acc, sig| acc + sig,
        );

        Ok(aggregate)
    }

    /// Parse amount string (supports "1.5xch", "1000000mojo", or plain number).
    pub fn parse_amount(amount_str: &str) -> WalletResult<u64> {
        let amount_lower = amount_str.to_lowercase();

        if amount_lower.ends_with("xch") {
            // Parse as XCH
            let num_str = amount_lower.trim_end_matches("xch").trim();
            let xch: f64 = num_str
                .parse()
                .map_err(|_| WalletError::InvalidAmount(format!("Invalid amount: {}", amount_str)))?;
            Ok((xch * 1_000_000_000_000.0) as u64)
        } else if amount_lower.ends_with("mojo") || amount_lower.ends_with("mojos") {
            // Parse as mojos
            let num_str = amount_lower
                .trim_end_matches("mojos")
                .trim_end_matches("mojo")
                .trim();
            num_str.parse().map_err(|_| {
                WalletError::InvalidAmount(format!("Invalid amount: {}", amount_str))
            })
        } else {
            // Assume mojos
            amount_str.parse().map_err(|_| {
                WalletError::InvalidAmount(format!("Invalid amount: {}", amount_str))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_amount_xch() {
        assert_eq!(TransactionSigner::parse_amount("1.5xch").unwrap(), 1_500_000_000_000);
        assert_eq!(TransactionSigner::parse_amount("0.1xch").unwrap(), 100_000_000_000);
    }

    #[test]
    fn test_parse_amount_mojos() {
        assert_eq!(TransactionSigner::parse_amount("1000000mojo").unwrap(), 1_000_000);
        assert_eq!(TransactionSigner::parse_amount("5000000mojos").unwrap(), 5_000_000);
    }

    #[test]
    fn test_parse_amount_plain() {
        assert_eq!(TransactionSigner::parse_amount("1000000").unwrap(), 1_000_000);
    }
}
