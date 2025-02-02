use std::{collections::BTreeMap, str::FromStr, sync::Arc};

use miniscript::{
    bitcoin::{
        absolute::{Height, LockTime},
        bip32::Xpub,
        consensus,
        psbt::{Input, Output},
        secp256k1::{self, All},
        transaction::Version,
        Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    },
    descriptor::Wildcard,
    policy::concrete::Policy,
    psbt::{PsbtInputExt, PsbtOutputExt},
    Descriptor, DescriptorPublicKey, RelLockTime,
};

fn main() {
    let covenant_key = DescriptorPublicKey::from_str("<cov_xpub>").unwrap();
    let spend_key = DescriptorPublicKey::from_str("<spend_xpub>").unwrap();
    let covenant = Covenant::new(covenant_key, spend_key, 4500, Network::Regtest);

    let _funding_addr = covenant.cov_addr(0);

    // Send 0.4 BTC to funding addr

    // fetch funding tx
    let tx0: Transaction = consensus::encode::deserialize_hex("<funding_tx_hex>").unwrap();

    let psbt1 = covenant.craft_tx(tx0.clone(), 1, 0.1, 0.3);
    let (psbt1, tx1) = Covenant::sign_psbt(psbt1);

    let psbt2 = covenant.craft_tx(tx1.clone(), 2, 0.1, 0.2);
    let (psbt2, tx2) = Covenant::sign_psbt(psbt2);

    let psbt3 = covenant.craft_tx(tx2.clone(), 3, 0.1, 0.1);
    let (psbt3, tx3) = Covenant::sign_psbt(psbt3);

    let psbt4 = covenant.craft_tx(tx3.clone(), 4, 0.1, 0.0);
    let (psbt4, tx4) = Covenant::sign_psbt(psbt4);
}

fn bip341_nums() -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_str(
        "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .expect("Valid pubkey: NUMS from BIP341")
}

fn unspendable(network: Network) -> DescriptorPublicKey {
    DescriptorPublicKey::XPub(miniscript::descriptor::DescriptorXKey {
        origin: None,
        xkey: Xpub {
            network: network.into(),
            depth: 0,
            parent_fingerprint: [0; 4].into(),
            child_number: 0.into(),
            public_key: bip341_nums(),
            chain_code: [0; 32].into(),
        },
        derivation_path: vec![].into(),
        wildcard: Wildcard::None,
    })
}

pub fn txin(outpoint: OutPoint, sequence: u16) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::from_height(sequence),
        witness: Witness::new(),
    }
}

#[allow(unused)]
pub struct Covenant {
    cov: DescriptorPublicKey,
    spend: DescriptorPublicKey,
    timelock: u16,
    network: Network,
    cov_descriptor: Descriptor<DescriptorPublicKey>,
    spend_descriptor: Descriptor<DescriptorPublicKey>,
    secp: secp256k1::Secp256k1<All>,
}

impl Covenant {
    pub fn new(
        cov: DescriptorPublicKey,
        spend: DescriptorPublicKey,
        timelock: u16,
        network: Network,
    ) -> Self {
        let cov_policy = Arc::new(Policy::Key(cov.clone()));
        let spend_policy = Arc::new(Policy::Key(spend.clone()));
        let backup = Arc::new(Policy::And(vec![cov_policy.clone(), spend_policy.clone()]));
        let tl = Arc::new(Policy::Older(RelLockTime::from_height(timelock)));
        let timelocked = Arc::new(Policy::And(vec![spend_policy.clone(), tl]));

        let unspendable = unspendable(network);

        let cov_descriptor = Policy::Or(vec![(1, backup), (9, timelocked)])
            .compile_tr(Some(unspendable))
            .expect("infaillible");
        let spend_descriptor = spend_policy.compile_tr(None).expect("infaillible");

        let secp = secp256k1::Secp256k1::new();

        // TODO: we actually do not use /<0;1>/ account

        Self {
            cov,
            spend,
            timelock,
            network,
            cov_descriptor,
            spend_descriptor,
            secp,
        }
    }

    fn spend_addr(&self, index: u32) -> Address {
        self.spend_descriptor
            .at_derivation_index(index)
            .expect("must not fail")
            .address(self.network)
            .expect("must not fail")
    }

    fn cov_addr(&self, index: u32) -> Address {
        self.cov_descriptor
            .at_derivation_index(index)
            .expect("must not fail")
            .address(self.network)
            .expect("must not fail")
    }

    pub fn craft_tx(&self, previous_tx: Transaction, index: u32, spend: f64, relock: f64) -> Psbt {
        let spend = Amount::from_btc(spend).unwrap();
        let relock = Amount::from_btc(relock).unwrap();
        let relock_addr = self.cov_addr(index);
        let relock_out = TxOut {
            value: relock,
            script_pubkey: relock_addr.into(),
        };
        let spend_addr = self.spend_addr(index);
        let spend_out = TxOut {
            value: spend,
            script_pubkey: spend_addr.into(),
        };

        let outpoint = OutPoint {
            txid: previous_tx.compute_txid(),
            vout: 0,
        };
        let tx_input = txin(outpoint, self.timelock);

        let outputs = if relock != Amount::ZERO {
            vec![relock_out, spend_out]
        } else {
            vec![spend_out]
        };

        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::Blocks(Height::ZERO),
            input: vec![tx_input],
            output: outputs,
        };
        let mut psbt_input = Input::default();

        // the previous tx address must have been generated at index-1
        assert!(self
            .cov_addr(index - 1)
            .matches_script_pubkey(&previous_tx.output[0].script_pubkey));
        let spend_descriptor = self.cov_descriptor.at_derivation_index(index - 1).unwrap();

        psbt_input
            .update_with_descriptor_unchecked(&spend_descriptor)
            .unwrap();

        psbt_input.witness_utxo = Some(previous_tx.output[0].clone());

        let psbt_inputs = vec![psbt_input];

        let mut psbt_relock = Output::default();
        let out_descriptor = self.cov_descriptor.at_derivation_index(index).unwrap();
        psbt_relock
            .update_with_descriptor_unchecked(&out_descriptor)
            .unwrap();
        let psbt_spend = Output::default();

        let psbt_outputs = if relock != Amount::ZERO {
            vec![psbt_relock, psbt_spend]
        } else {
            vec![psbt_spend]
        };

        Psbt {
            unsigned_tx: tx,
            version: 0,
            xpub: BTreeMap::new(),
            // TODO: register spend descriptor in proprietary
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
            inputs: psbt_inputs,
            outputs: psbt_outputs,
        }
    }

    pub fn sign_psbt(psbt: Psbt) -> (Psbt, Transaction) {
        // TODO: sign w/ signing device
        todo!()
    }
}
