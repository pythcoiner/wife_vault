use std::{collections::BTreeMap, env, fs::File, io::Read, path::PathBuf, str::FromStr};

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
    static ref SECP: secp256k1::Secp256k1<All> = secp256k1::Secp256k1::new();
}

const FEE: u64 = 600;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!(
            "Path to config file must be passed as argument: \n{} <path>",
            args[0]
        );
        std::process::exit(1);
    }

    let conf = match CovenantConfig::from_file(&args[1]) {
        Ok(c) => c,
        Err(e) => {
            println!("Fail to get configuration: {:?} ", e);
            std::process::exit(1);
        }
    };
    let conf_str = serde_json::to_string_pretty(&conf).unwrap();
    println!("Configuration: \n {}", conf_str);
    let covenant = Covenant::new(
        conf.cov_xpub(0).unwrap(),
        conf.spend_xpub(0).unwrap(),
        conf.delay(),
        Network::Regtest,
    );

    let funding_addr = covenant.cov_addr(0);

    println!("Address to fund the contract: {}", funding_addr);

    println!("Enter raw tx that fund the contract:");

    let mut raw_tx = String::new();
    std::io::stdin().read_line(&mut raw_tx).unwrap();
    raw_tx = raw_tx.trim().into();

    let tx0: Result<Transaction, _> = consensus::encode::deserialize_hex(&raw_tx);
    let tx0 = match tx0 {
        Ok(tx) => tx,
        Err(e) => {
            println!("Fail to parse transaction: \n {} \n {}", raw_tx, e);
            std::process::exit(1);
        }
    };

    if tx0.output[0].script_pubkey != funding_addr.script_pubkey() {
        println!("The first output of the tx must fund the funding address!");
        std::process::exit(1);
    }

    let amount = tx0.output[0].value.to_sat();

    if amount == 0 {
        println!("Amount of funding input must be > 0");
        std::process::exit(1);
    }

    println!("Amount to split: {}", amount);

    let mut txs = Vec::new();
    let mut previous_tx = tx0;
    let mut previous_amount = amount;
    let mut index = 1;

    loop {
        let (spend, relock) = if previous_amount > conf.amount {
            let mut relock = previous_amount.saturating_sub(conf.amount);
            if relock <= FEE {
                relock = 0;
            }
            let spend = if relock == 0 {
                previous_amount.saturating_sub(FEE)
            } else {
                conf.amount
            };
            (spend, relock)
        } else {
            (previous_amount - FEE, 0)
        };
        let psbt = covenant.craft_tx(previous_tx.clone(), index, spend, relock);
        previous_tx = psbt.unsigned_tx.clone();
        previous_amount = previous_tx.output[0].value.to_sat();
        index += 1;

        txs.push(psbt);

        if relock < (2 * FEE) {
            break;
        }
    }

    println!("{} unsigned psbts: \n", txs.len());

    let mut i = 0;
    for p in &txs {
        i += 1;
        println!("psbt {}: \n {} \n", i, p);
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct CovenantConfig {
    cov_mnemonic: String,
    spend_mnemonic: String,
    amount: u64,
    delay: u16,
    index: u32,
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
}

impl CovenantConfig {
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

        let conf = CovenantConfig {
            cov_mnemonic,
            spend_mnemonic,
            amount: 10_000_000,
            delay: 4500,
            index: 0,
        };

        let conf_str = serde_json::to_string_pretty(&conf).unwrap();
        let parsed: CovenantConfig = serde_json::from_str(&conf_str).unwrap();
        assert_eq!(conf, parsed);
    }
}
