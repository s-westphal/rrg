// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::{os::unix::process::ExitStatusExt, process::ExitStatus};

use protobuf::{well_known_types::duration::Duration, Message};


/// Arguments of the `execute_signed_command` action.
pub struct Args {
    command: Vec<u8>,
    unsigned_stdin: Vec<u8>,
    command_ed25519_signature: Vec<u8>,
    timeout: Duration,
}

/// Result of the `execute_signed_command` action.
pub struct Item {
    /// Exit status of the command subprocess.
    exit_status: ExitStatus,
    /// Standard output of the command executiom.
    stdout: Vec<u8>,
    /// Standard error of the command executiom.
    stderr: Vec<u8>,
    /// True if the stdout is truncated.
    stdout_truncated: bool,
    /// True if the stderr is truncated.
    stderr_truncated: bool,
}


/// Handles invocations of the `execute_signed_command` action.
pub fn handle<S>(_session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    rrg_proto::execute_signed_command::SignedCommand::parse_from_bytes(&args.command[..])
        .map_err(crate::session::Error::action)?;
    let command_ed25519_signature = args.command_ed25519_signature;
    log::info!("Signature: {command_ed25519_signature:?}");
    let unsigned_stdin = args.unsigned_stdin;
    log::info!("Signature: {unsigned_stdin:?}");
    let timeout = args.timeout;
    log::info!("Signature: {timeout:?}");

    // TODO(swestphal): Verify signature
    // TODO(swestphal): Handle stdin
    // TODO(swestphal): Execute command with timeout
    // TODO(swestphal): Return result

    Ok(())
    
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::execute_signed_command::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {

        Ok(Args {
            command: proto.take_command(),
            unsigned_stdin: proto.take_unsigned_stdin(),
            command_ed25519_signature: proto.take_command_ed25519_signature(),
            timeout: proto.take_timeout(),
        })
    }
}

#[cfg(target_family = "windows")]
impl crate::response::Item for Item {

    type Proto = rrg_proto::execute_signed_command::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::execute_signed_command::Result::new();
        if let Some(exit_code) = self.exit_status.code() {
            proto.set_exit_code(exit_code);
        }
        proto.set_stdout(self.stdout);
        proto.set_stderr(self.stderr);
        proto.set_stdout_truncated(self.stdout_truncated);
        proto.set_stderr_truncated(self.stderr_truncated);

        proto
    }
}

#[cfg(target_family = "unix")]
impl crate::response::Item for Item {

    type Proto = rrg_proto::execute_signed_command::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::execute_signed_command::Result::new();
        if let Some(exit_code) = self.exit_status.code() {
            proto.set_exit_code(exit_code);
        }
        if let Some(exit_signal) = self.exit_status.signal() {
            proto.set_exit_signal(exit_signal);
        }
        proto.set_stdout(self.stdout);
        proto.set_stderr(self.stderr);
        proto.set_stdout_truncated(self.stdout_truncated);
        proto.set_stderr_truncated(self.stderr_truncated);

        proto
    }
}


#[cfg(test)]
mod tests {

    use protobuf::SpecialFields;

    use super::*;

    // TODO(swestphal): write actually useful tests.
    #[test]
    fn test_parse_command() {
        let command = rrg_proto::execute_signed_command::SignedCommand::default().write_to_bytes().unwrap();
        let unsigned_stdin = Vec::from([1, 2, 3, 4]);
        let command_ed25519_signature = Vec::from([100, 200]);
        let args = Args {
            command,
            unsigned_stdin,
            command_ed25519_signature,
            timeout: Duration { seconds: 10, nanos: 0, special_fields: SpecialFields::default() }
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();
    }

}