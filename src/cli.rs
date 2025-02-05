use std::{io, path::PathBuf, process, str::FromStr};

use bip39::Mnemonic;
use clap::{value_parser, Parser, Subcommand};
use lfc::{parse_tx, CovenantState, MAX_DERIV};
use miniscript::bitcoin::{address::NetworkUnchecked, Address, Amount, Network, Transaction};

fn datadir() -> PathBuf {
    #[cfg(target_os = "linux")]
    let dir = {
        let mut dir = dirs::home_dir().unwrap();
        dir.push(".lfc");
        dir
    };

    #[cfg(not(target_os = "linux"))]
    let dir = {
        let mut dir = dirs::config_dir().unwrap();
        dir.push("Lfc");
        dir
    };

    maybe_create_dir(&dir);

    dir
}

fn maybe_create_dir(dir: &PathBuf) {
    if !dir.exists() {
        #[cfg(unix)]
        {
            use std::fs::DirBuilder;
            use std::os::unix::fs::DirBuilderExt;

            let mut builder = DirBuilder::new();
            builder.mode(0o700).recursive(true).create(dir).unwrap();
        }

        #[cfg(not(unix))]
        std::fs::create_dir_all(dir).unwrap();
    }
}

pub fn parse() -> Args {
    let mut args = Args::parse();
    let mut conf = datadir();
    let mut path = args.wallet.clone();
    match !path.is_empty() {
        true => {
            if path.contains("/") {
                eprintln!("wallet must be a name, not a path!");
                process::exit(1);
            }
            if !path.ends_with(".conf") {
                path = format!("{}.conf", path);
            }
            conf.push(path);
        }
        false => {
            conf.push("lfc.conf");
        }
    }

    if args.command != Command::Conf {
        if !conf.exists() {
            eprintln!("wallet {} does not exists!", args.wallet);
            process::exit(1);
        }
        if !conf.is_file() {
            eprintln!("wallet {} is not a file!", args.wallet);
            process::exit(1);
        }
    } else if conf.exists() {
        eprintln!("wallet {} already exists!", args.wallet);
        process::exit(1);
    }
    args.path = conf;
    args
}

#[derive(Parser, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
    /// Wallet name
    #[arg(global = true, default_value = "lfc")]
    pub wallet: String,
    /// Bitcoin network: bitcoin/testnet/signet/regtest
    #[arg(global = true, short, long, default_value_t = Network::Bitcoin)]
    pub network: Network,
    /// option to output raw json to stdout
    #[arg(short, long, default_value_t = false)]
    pub raw: bool,
    /// Validated file path
    #[arg(skip)]
    pub path: PathBuf,
    /// Parsed state
    #[arg(skip)]
    pub state: Option<CovenantState>,
}

#[derive(Subcommand, PartialEq, Debug)]
pub enum Command {
    /// Display the status of the wallet
    Status,
    /// Generate a new wallet config
    Conf,
    /// Create a chain of transaction
    Create,
    /// Sign all presigned PSBTs
    Sign,
    /// Register a broadcasted transaction
    Register {
        /// Block height where the transaction have been include
        height: u64,
        /// Transaction in hex format
        #[arg( value_parser = parse_tx)]
        transaction: Transaction,
    },
    /// Start an unlock round
    Unlock,
    /// Broadcast a lock transaction if available
    Lock,
    /// Relock an available coin
    Relock,
    /// Spend from an available coin
    #[command(alias = "send")]
    Spend {
        /// Amount to send in BTC
        amount: f64,
        /// Recipient address
        address: Address<NetworkUnchecked>,
    },
    /// Delete the wallet
    Del,
}

pub fn input(txt: &str) -> String {
    eprintln!("{}", txt);
    let mut name = String::new();
    _ = io::stdin().read_line(&mut name).unwrap();
    name = name.trim().to_string();
    name
}

pub fn del_wallet(args: Args) {
    let hint = format!("Are you sure to delete wallet {}?", args.wallet);
    let inp = input(&hint);
    if ["y".to_string(), "yes".to_string()].contains(&inp.to_lowercase()) {
        std::fs::remove_file(args.path).unwrap();
    }
}

pub fn conf(args: Args) {
    let index = input(&format!(
        "Select a derivation index for the wallet: 0-{}",
        lfc::MAX_DERIV
    ));
    let index = match index.parse::<u32>() {
        Ok(i) => {
            if i < MAX_DERIV {
                Some(i)
            } else {
                None
            }
        }
        Err(_) => None,
    }
    .unwrap();

    let mnemo = input(
        "Enter the mnemonic for your covenant wallet \
        (12 words), if the input is empty a mnemonic phrase will be automatically generated:",
    )
    .trim()
    .to_string();
    let cov_mnemonic = if mnemo.is_empty() {
        Mnemonic::generate(12).unwrap().to_string()
    } else {
        Mnemonic::from_str(&mnemo).unwrap().to_string()
    };

    let mnemo = input(
        "Enter the mnemonic for your spending wallet \
        (12 words), if the input is empty a mnemonic phrase will be automatically generated:",
    )
    .trim()
    .to_string();
    let spend_mnemonic = if mnemo.is_empty() {
        Mnemonic::generate(12).unwrap().to_string()
    } else {
        Mnemonic::from_str(&mnemo).unwrap().to_string()
    };

    let amount = input("Enter the max amount allowed to spend at each round: (BTC)");
    let amount = f64::from_str(&amount).unwrap();
    let amount = Amount::from_btc(amount).unwrap().to_sat();

    let delay = input("Enter the number of block minimum between 2 rounds:");
    let delay = delay.parse::<u16>().unwrap();

    let conf = CovenantState {
        cov_mnemonic,
        spend_mnemonic,
        amount,
        delay,
        index,
        rounds: Vec::new(),
    };
    conf.to_file(args.path).unwrap();
}
