// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

mod action;
mod opts;

use std::fs::File;
use std::io::Result;

use fleetspeak::Packet;
use log::error;
use opts::{Opts};

use self::action::{Response};

fn main() -> Result<()> {
    let opts = opts::from_args();
    init(&opts);

    fleetspeak::startup(env!("CARGO_PKG_VERSION"))?;

    use self::action::startup;
    match startup::handle(()) {
        Ok(response) => {
            let mut data = Vec::new();
            // TODO: Use proper error handling.
            prost::Message::encode(&response.into_proto(), &mut data)?;

            let message = rrg_proto::GrrMessage {
                session_id: Some(String::from("flows/F:Startup")),
                r#type: Some(rrg_proto::grr_message::Type::Message.into()),
                args_rdf_name: startup::Response::RDF_NAME.map(String::from),
                args: Some(data),
                ..Default::default()
            };

            fleetspeak::send(Packet {
                service: String::from("GRR"),
                kind: Some(String::from("GrrMessage")),
                data: message,
            })?;
        },
        Err(error) => error!("failed to execute startup action: {}", error),
    }

    loop {
        let packet = fleetspeak::collect(opts.heartbeat_rate)?;
        handle(packet.data);
    }
}

fn init(opts: &Opts) {
    init_log(opts);
}

fn init_log(opts: &Opts) {
    let level = opts.log_verbosity.level();

    let mut loggers = Vec::<Box<dyn simplelog::SharedLogger>>::new();

    if let Some(std) = &opts.log_std {
        let config = Default::default();
        let logger = simplelog::TermLogger::new(level, config, std.mode())
            .expect("failed to create a terminal logger");

        loggers.push(logger);
    }

    if let Some(path) = &opts.log_file {
        let file = File::create(path)
            .expect("failed to create the log file");

        let config = Default::default();
        let logger = simplelog::WriteLogger::new(level, config, file);

        loggers.push(logger);
    }

    simplelog::CombinedLogger::init(loggers)
        .expect("failed to init logging");
}

fn handle(message: rrg_proto::GrrMessage) {
    match message.name {
        Some(name) => println!("requested to execute the '{}' action", name),
        None => eprintln!("missing action name to execute"),
    }
}
