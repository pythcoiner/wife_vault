use miniscript::bitcoin::{Amount, OutPoint, Psbt, Transaction, TxOut};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Round {
    // Psbt of this round, already signed
    pub psbt: Psbt,
    // The transaction that have unlocked this round
    pub spend: Option<Transaction>,
    // Spending txs (ancestors of `coins`)
    pub transactions: Vec<Transaction>,
    // Coins spendable by the spend key
    pub coins: Vec<OutPoint>,
    // Blockheight we must wait to unlock
    pub unlock: Option<u64>,
    // Blockheight of the block containing the unlock tx
    pub unlocked: Option<u64>,
    // Index of the round
    pub index: u32,
    // Previous round, populated at unlock
    pub previous: Option<Box<Round>>,
    // Next round, populated when unlock next
    pub next: Option<Box<Round>>,
}

pub enum State {
    /// Not yet unlocked
    Locked,
    /// Currently active round
    Active,
    /// Next(s) round(s) have been unlocked
    Inactive,
}

impl Round {
    pub fn state(&self) -> State {
        match self.is_unlocked() {
            false => State::Locked,
            true => match self.next.is_some() {
                false => State::Active,
                true => State::Inactive,
            },
        }
    }
    pub fn is_unlocked(&self) -> bool {
        self.spend.is_some()
    }

    pub fn is_spendable(&self) -> bool {
        self.is_unlocked() && !self.coins.is_empty()
    }

    fn tx_for_coin(&self, coin: &OutPoint) -> Option<&Transaction> {
        let mut tx = None;
        self.transactions.iter().for_each(|t| {
            if t.compute_txid() == coin.txid {
                tx = Some(t);
            }
        });
        tx
    }

    pub fn spendable_amount(&self) -> Amount {
        let mut amount = Amount::ZERO;
        self.spendable_coins().iter().for_each(|c| {
            amount += c.value;
        });
        amount
    }

    pub fn spendable_coins(&self) -> Vec<TxOut> {
        let mut coins = Vec::new();
        self.coins.iter().for_each(|c| {
            let tx = self.tx_for_coin(c).unwrap();
            coins.push(tx.output[c.vout as usize].clone());
        });
        coins
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Rounds(Vec<Round>);

impl Rounds {
    pub fn new() -> Self {
        let rounds = Vec::new();
        Rounds(rounds)
    }

    pub fn init(&mut self) {
        self.sort();
        // sanity check
        if !self.is_empty() {
            let mut last = 0u32;
            let mut active = 0usize;
            self.0.iter().for_each(|r| {
                assert!(r.index == last + 1);
                last += 1;
                if matches!(r.state(), State::Active) {
                    active += 1;
                }
                assert!(active < 2);
            });
        }
    }

    pub fn is_unlocked(&self) -> bool {
        if self.0.is_empty() {
            false
        } else {
            self.0[0].is_unlocked()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn sort(&mut self) {
        self.0.sort_by(|a, b| a.index.cmp(&b.index));
    }

    pub fn current_round_index(&mut self) -> usize {
        //sort & sanity check
        self.init();
        for (i, r) in self.0.iter().enumerate() {
            if matches!(r.state(), State::Active) {
                return i;
            }
        }
        unreachable!();
    }

    pub fn at(&mut self, pos: usize) -> Option<&mut Round> {
        if pos < self.0.len() {
            Some(&mut self.0[pos])
        } else {
            None
        }
    }

    pub fn push(&mut self, round: Round) {
        self.0.push(round);
    }

    pub fn spendable_coins(&self) -> Vec<TxOut> {
        let mut coins = Vec::new();
        self.0.iter().for_each(|r| {
            coins.append(&mut r.spendable_coins());
        });
        coins
    }

    pub fn spendable_amount(&self) -> Amount {
        let mut coins = Amount::ZERO;
        self.0.iter().for_each(|r| {
            coins += r.spendable_amount();
        });
        coins
    }
}

impl Default for Rounds {
    fn default() -> Self {
        Self::new()
    }
}
