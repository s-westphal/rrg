// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::{io::{Read, Write}, os::{unix::process::ExitStatusExt}, process::{Command, ExitStatus}};

use protobuf::Message;

use crate::request::ParseArgsError;

// TODO(swestphal): Check and update max size.
const MAX_OUTPUT_SIZE: usize = 2048;

/// Arguments of the `execute_signed_command` action.
pub struct Args {
    raw_command: Vec<u8>,
    command: rrg_proto::execute_signed_command::SignedCommand,
    stdin: Stdin,
    ed25519_signature: ed25519_dalek::Signature,
    timeout: std::time::Duration,
}

/// Result of the `execute_signed_command` action.
pub struct Item {
    /// Exit status of the command subprocess.
    exit_status: ExitStatus,
    /// Standard output of the command executiom.
    stdout: Vec<u8>,
    /// Wheather standard output is truncated.
    truncated_stdout: bool,
    /// Standard error of the command executiom.
    stderr: Vec<u8>,
    /// Wheather stderr is truncated.
    truncated_stderr: bool,
    
}

enum Stdin {
    NONE,
    UNSIGNED(Vec<u8>),
    SIGNED(Vec<u8>),
}


fn verify_ed25519_signature(data: &Vec<u8>, ed25519_signature: &ed25519_dalek::Signature) -> Result<(), ed25519_dalek::SignatureError>
{   
    // TODO(swestphal): Load public key from config.
    let public_key_bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
        215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
        14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26];
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).unwrap();

    verifying_key.verify_strict(data, ed25519_signature)
}

/// Handles invocations of the `execute_signed_command` action.
pub fn handle<S>(session: &mut S, mut args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    verify_ed25519_signature(&args.raw_command, &args.ed25519_signature)
        .map_err(crate::session::Error::action)?;


    let command_path = &std::path::PathBuf::try_from(args.command.take_path()).unwrap();

    let mut command_process = Command::new(command_path)
        .stdin(std::process::Stdio::piped())
        .args(args.command.take_args())
        .envs(args.command.take_env())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(crate::session::Error::action)?;

    
    let mut command_stdin = command_process.stdin.take().unwrap();
    if let Stdin::SIGNED(stdin) = args.stdin {
        let _ = command_stdin.write(&stdin[..])
            .map_err(crate::session::Error::action);
    }
    else if let Stdin::UNSIGNED(stdin) = args.stdin {
        let _ = command_stdin.write(&stdin[..])
            .map_err(crate::session::Error::action);
    }

    let start = std::time::SystemTime::now();
    while std::time::SystemTime::now().duration_since(start).unwrap() < args.timeout {
        match command_process.try_wait() {
            Ok(None) => {
                dbg!("command not ready yet, wait");
            }
            _ => break,
        }
    }
    // Either the process has exited, then kill doesn't do anything,
    // or we kill the process.
    command_process.kill().map_err(crate::session::Error::action);

    let exit_status = command_process.wait()
        .map_err(crate::session::Error::action)?;


    let mut stdout = Vec::<u8>::new();
    let read_result = match command_process.stdout.take() {
        Some(mut process_stdout) => process_stdout.read_to_end(&mut stdout),
        None => Ok(0),
    };
    let length = read_result.unwrap();
    
    let truncate_stdout = length > MAX_OUTPUT_SIZE;
    if truncate_stdout {
        let mut truncated = Vec::<u8>::new();
        truncated.clone_from_slice(&stdout[..MAX_OUTPUT_SIZE]);
        stdout = truncated;
    };

    let mut stderr = Vec::<u8>::new();
    let read_result = match command_process.stderr.take() {
        Some(mut process_stderr) => process_stderr.read_to_end(&mut stderr),
        None => Ok(0),
    };
    let length_stderr = read_result.map_err(crate::session::Error::action)?;
    
    let truncate_stderr = length_stderr > MAX_OUTPUT_SIZE;
    if truncate_stderr {
        let mut truncated = Vec::<u8>::new();
        truncated.clone_from_slice(&stderr[..MAX_OUTPUT_SIZE]);
        stderr = truncated;
    };


    session.reply(Item{
        exit_status: exit_status,
        stdout: stdout.to_owned(),
        truncated_stdout: truncate_stdout,
        stderr: stderr.to_owned(),
        truncated_stderr: truncate_stderr,
    })?;
    
    Ok(())
    
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::execute_signed_command::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        let raw_signature= proto.take_command_ed25519_signature();

        let signature_bytes = match raw_signature.len() {
            ed25519_dalek::SIGNATURE_LENGTH => <&[u8; 64]>::try_from(&raw_signature[0..ed25519_dalek::SIGNATURE_LENGTH])
                .map_err(|error| ParseArgsError::invalid_field("command_ed25519_signature", error))?,
            len => return Err(ParseArgsError::invalid_field("command_ed25519_signature", SignatureFormatError {
                  len,
                })),
        };

        let raw_command = proto.take_command();
        let mut command = rrg_proto::execute_signed_command::SignedCommand::parse_from_bytes(&raw_command)
            .map_err(|error| ParseArgsError::invalid_field("command", error))?;


        let stdin: Stdin;
        if command.has_signed_stdin() {
            stdin = Stdin::SIGNED(command.take_signed_stdin());
        } else if command.unsigned_stdin() && !proto.unsigned_stdin.is_empty() {
            stdin = Stdin::UNSIGNED(proto.take_unsigned_stdin());
        } else {
            stdin = Stdin::NONE
        }

        let timeout = std::time::Duration::try_from(proto.take_timeout())
            .map_err(|error| ParseArgsError::invalid_field("command", error))?;
    
        Ok(Args {
            raw_command,
            command,
            ed25519_signature: ed25519_dalek::Signature::from_bytes(signature_bytes),
            stdin,
            timeout,
        })
    }
}




impl crate::response::Item for Item {

    type Proto = rrg_proto::execute_signed_command::Result;

    fn into_proto(self) -> Self::Proto {

        let mut proto = rrg_proto::execute_signed_command::Result::new();
        
        if let Some(exit_code) = self.exit_status.code() {
            proto.set_exit_code(exit_code);
        }
        
        #[cfg(target_family = "unix")]
        {
            if let Some(exit_signal) = self.exit_status.signal() {
                proto.set_exit_signal(exit_signal);
            }
        }

        proto.set_stdout(self.stdout);
        proto.set_stdout_truncated(self.truncated_stdout);

        proto.set_stderr(self.stderr);
        proto.set_stderr_truncated(self.truncated_stderr);

        proto
    }
}

#[derive(Debug)]
struct SignatureFormatError {
    len: usize,
}

impl std::fmt::Display for SignatureFormatError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write! {
            fmt,
            "provided signature length ({}) does not match the expected length ({})",
            self.len, ed25519_dalek::SIGNATURE_LENGTH
        }
    }
}

impl std::error::Error for SignatureFormatError {
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
        let signature_bytes: [u8; 64] = [
            215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
            14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26,
            215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
            14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26];
        let command_ed25519_signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
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