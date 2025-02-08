use std::collections::BTreeMap;

use miniscript::{
    bitcoin::{
        absolute::{Height, LockTime},
        psbt::{Input, Output},
        transaction::Version,
        Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    },
    descriptor::Wpkh,
    psbt::{PsbtInputExt, PsbtOutputExt},
    Descriptor, DescriptorPublicKey,
};

use crate::covenant_state::CovenantState;

pub fn txin(outpoint: OutPoint, sequence: u16) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::from_height(sequence),
        witness: Witness::new(),
    }
}

pub struct Covenant {
    #[allow(unused)]
    cov: DescriptorPublicKey,
    #[allow(unused)]
    spend: DescriptorPublicKey,
    timelock: u16,
    network: Network,
    cov_descriptor: Descriptor<DescriptorPublicKey>,
    spend_descriptor: Descriptor<DescriptorPublicKey>,
}

impl Covenant {
    pub fn from_state(state: &CovenantState) -> Self {
        let cov = state.cov_xpub(1).unwrap();
        let spend = state.spend_xpub(1).unwrap();
        let timelock = state.delay();
        let network = state.network;

        let cov_descriptor = Descriptor::Wpkh(Wpkh::new(cov.clone()).unwrap());

        println!("cov_descriptor: \n \n{} \n \n", cov_descriptor);

        let spend_descriptor = Descriptor::Wpkh(Wpkh::new(spend.clone()).unwrap());

        println!("spend_descriptor: \n \n{} \n \n", spend_descriptor);

        Self {
            cov,
            spend,
            timelock,
            network,
            cov_descriptor,
            spend_descriptor,
        }
    }

    pub fn spend_addr(&self, index: u32) -> Address {
        self.spend_descriptor
            .at_derivation_index(index)
            .expect("must not fail")
            .address(self.network)
            .expect("must not fail")
    }

    pub fn cov_addr(&self, index: u32) -> Address {
        self.cov_descriptor
            .at_derivation_index(index)
            .expect("must not fail")
            .address(self.network)
            .expect("must not fail")
    }

    pub fn craft_tx(&self, previous_tx: Transaction, index: u32, spend: u64, relock: u64) -> Psbt {
        println!(
            "craft_tx(index: {}, spend: {}, relock: {})",
            index, spend, relock,
        );
        let spend = Amount::from_sat(spend);
        let relock = Amount::from_sat(relock);
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
        let sequence = if index == 1 { 0 } else { self.timelock };
        let tx_input = txin(outpoint, sequence);

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

    pub fn sign_psbt(_psbt: Psbt) -> (Psbt, Transaction) {
        // TODO: sign w/ signing device
        todo!()
    }
}
