use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    path::PathBuf,
    str::FromStr,
};

use bip39::Mnemonic;
use lazy_static::lazy_static;
use miniscript::{
    bitcoin::{
        absolute::{Height, LockTime},
        bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
        consensus,
        psbt::{Input, Output},
        secp256k1::{self, All},
        transaction::Version,
        Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    },
    descriptor::{DescriptorXKey, Wildcard, Wpkh},
    psbt::{PsbtInputExt, PsbtOutputExt},
    Descriptor, DescriptorPublicKey,
};
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref SECP: secp256k1::Secp256k1<All> = secp256k1::Secp256k1::new();
}

pub const FEE: u64 = 600;
pub const MAX_DERIV: u32 = (2u64.pow(31) - 1) as u32;

pub fn parse_tx(raw_tx: &str) -> Result<Transaction, String> {
    let tx: Result<Transaction, _> = consensus::encode::deserialize_hex(raw_tx);
    tx.map_err(|e| e.to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Round {
    // Psbt of this round, already signed
    psbt: Psbt,
    // The transaction that have unlocked this round
    spend: Option<Transaction>,
    // Spending txs (ancestors of `coins`)
    transactions: Vec<Transaction>,
    // Coins spendable by the spend key
    coins: Vec<OutPoint>,
    // Blockheight we must wait to unlock
    unlock: Option<u64>,
    // Blockheight of the block containing the unlock tx
    unlocked: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CovenantState {
    pub cov_mnemonic: String,
    pub spend_mnemonic: String,
    pub amount: u64,
    pub delay: u16,
    pub index: u32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub rounds: Vec<Round>,
}

impl PartialEq for CovenantState {
    fn eq(&self, other: &Self) -> bool {
        self.cov_mnemonic == other.cov_mnemonic
            && self.spend_mnemonic == other.spend_mnemonic
            && self.amount == other.amount
            && self.delay == other.delay
            && self.index == other.index
            && self.rounds.len() == other.rounds.len()
    }
}

#[derive(Debug)]
pub enum Error {
    ParseConfigPath,
    ParseConfig,
    ConfigNotExists,
    ConfigNotFile,
    OpenConfig,
    ReadConfig,
    Mnemonic,
    Xpriv,
    DeriveXpriv,
    DumpConfig,
    IO(io::Error),
    SerdeJson(serde_json::Error),
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::SerdeJson(value)
    }
}

impl CovenantState {
    pub fn origin_path(&self) -> Vec<ChildNumber> {
        vec![84, 1, self.index]
            .into_iter()
            .map(|c| ChildNumber::from_hardened_idx(c).unwrap())
            .collect()
    }

    pub fn from_file(path: &str) -> Result<Self, Error> {
        let path = PathBuf::from_str(path).map_err(|_| Error::ParseConfigPath)?;
        if !path.exists() {
            return Err(Error::ConfigNotExists);
        } else if !path.is_file() {
            return Err(Error::ConfigNotFile);
        }
        let mut file = File::open(path).map_err(|_| Error::OpenConfig)?;
        let mut conf_str = String::new();
        let _conf_size = file
            .read_to_string(&mut conf_str)
            .map_err(|_| Error::ReadConfig)?;
        let conf: Self = serde_json::from_str(&conf_str).map_err(|_| Error::ParseConfig)?;
        Ok(conf)
    }

    pub fn to_file(&self, path: PathBuf) -> Result<(), Error> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }

    fn master_xpriv(mnemonic: &str) -> Result<Xpriv, Error> {
        let mnemonic = Mnemonic::from_str(mnemonic).map_err(|_| Error::Mnemonic)?;
        let seed = mnemonic.to_seed("");
        Xpriv::new_master(Network::Regtest, &seed).map_err(|_| Error::Xpriv)
    }

    fn derived_xpriv(xpriv: Xpriv, path: Vec<ChildNumber>) -> Result<Xpriv, Error> {
        xpriv
            .derive_priv(&SECP, &path)
            .map_err(|_| Error::DeriveXpriv)
    }

    fn cov_master_xpriv(&self) -> Result<Xpriv, Error> {
        Self::master_xpriv(&self.cov_mnemonic)
    }

    fn spend_master_xpriv(&self) -> Result<Xpriv, Error> {
        Self::master_xpriv(&self.spend_mnemonic)
    }

    fn xpub(&self, master_xpriv: Xpriv, sub_account: u32) -> Result<DescriptorPublicKey, Error> {
        let fg = master_xpriv.fingerprint(&SECP);
        let xpriv = Self::derived_xpriv(master_xpriv, self.origin_path())?;
        let xpub = Xpub::from_priv(&SECP, &xpriv);

        let key = DescriptorXKey {
            origin: Some((fg, self.origin_path().into())),
            xkey: xpub,
            derivation_path: DerivationPath::from_iter(vec![sub_account.into()]),
            wildcard: Wildcard::Unhardened,
        };
        Ok(DescriptorPublicKey::XPub(key))
    }

    pub fn cov_xpub(&self, sub_account: u32) -> Result<DescriptorPublicKey, Error> {
        self.xpub(self.cov_master_xpriv()?, sub_account)
    }

    pub fn spend_xpub(&self, sub_account: u32) -> Result<DescriptorPublicKey, Error> {
        self.xpub(self.spend_master_xpriv()?, sub_account)
    }

    pub fn delay(&self) -> u16 {
        self.delay
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }
}

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
    pub fn new(
        cov: DescriptorPublicKey,
        spend: DescriptorPublicKey,
        timelock: u16,
        network: Network,
    ) -> Self {
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

#[cfg(test)]
mod tests {

    use bip39::Mnemonic;

    use super::*;

    #[test]
    fn serialize_conf() {
        let cov_mnemonic = Mnemonic::generate(12).unwrap().to_string();
        let spend_mnemonic = Mnemonic::generate(12).unwrap().to_string();

        let conf = CovenantState {
            cov_mnemonic,
            spend_mnemonic,
            amount: 10_000_000,
            delay: 4500,
            index: 0,
            rounds: Vec::new(),
        };

        let conf_str = serde_json::to_string_pretty(&conf).unwrap();
        let parsed: CovenantState = serde_json::from_str(&conf_str).unwrap();
        assert_eq!(conf, parsed);
    }
}
