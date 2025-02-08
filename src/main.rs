mod cli;

use cli::commands::Command;

fn main() {
    let args = cli::parse();
    match &args.command {
        Command::Status => cli::commands::status(args),
        Command::Conf { .. } => cli::commands::conf(args),
        Command::Create => cli::commands::create(args),
        Command::Unlock => todo!(),
        Command::Lock => todo!(),
        Command::Relock => todo!(),
        Command::Del => cli::commands::del_wallet(args),
        Command::Sign => todo!(),
        Command::Register {
            height: _,
            transaction: _,
        } => {
        }
        Command::Spend {
            amount: _,
            address: _,
        } => {
        }
    }
}
