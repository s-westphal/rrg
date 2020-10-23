// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the file stat action.
//!
//! A file stat action responses with stat of a given file

use std::fs::Metadata;
use std::path::PathBuf;

use log::warn;

use crate::session::{self, Error, Session};

impl From<std::io::Error> for Error {

    fn from(e: std::io::Error) -> Error {
        Error::action(e)
    }
}

#[derive(Debug)]
pub struct Response {
    metadata: Metadata,
    #[cfg(target_os = "linux")]
    flags_linux: Option<u32>,
    symlink: Option<PathBuf>,
    path: PathBuf,
    #[cfg(target_family = "unix")]
    ext_attrs: Vec<crate::fs::unix::ExtAttr>,
}

#[derive(Debug)]
pub struct Request {
    path: PathBuf,
    collect_ext_attrs: bool,
    follow_symlink: bool,
}

pub fn handle<S: Session>(session: &mut S, request: Request) -> session::Result<()> {
    let metadata = if request.follow_symlink {
        std::fs::metadata(&request.path)?
    } else {
        std::fs::symlink_metadata(&request.path)?
    };

    let symlink = if metadata.file_type().is_symlink() {
        std::fs::read_link(&request.path).map_err(|error| {
            // TODO: Make the `ack!` macro more expressive and rewrite it.
            warn! {
                "failed to read symlink for '{path}': {cause}",
                path = request.path.display(),
                cause = error,
            }
        }).ok()
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let flags_linux = crate::fs::linux::flags(&request.path).map_err(|error| {
        // TODO: Make the `ack!` macro more expressive and rewrite it.
        warn! {
            "failed to collect flags for '{path}': {cause}",
            path = request.path.display(),
            cause = error,
        }
    }).ok();

    let mut response = Response {
        path: request.path,
        metadata: metadata,
        symlink: symlink,
        #[cfg(target_family = "unix")]
        ext_attrs: vec!(),
        #[cfg(target_os = "linux")]
        flags_linux: flags_linux,
    };

    if request.collect_ext_attrs {
        // TODO: This is not pretty. Consider creating a blank `ext_attrs`
        // implementation for Windows and make this code compile regardless of
        // the platform.
        #[cfg(target_family = "unix")]
        {
            // TODO: Do not fail on error.
            response.ext_attrs.extend(crate::fs::unix::ext_attrs(&response.path)?);
        }
    }

    session.reply(response)?;
    Ok(())
}

impl super::Request for Request {

    type Proto = rrg_proto::GetFileStatRequest;

    fn from_proto(proto: Self::Proto) -> Result<Self, session::ParseError> {
        use std::convert::TryInto as _;

        let path = proto.pathspec
            .ok_or(session::MissingFieldError::new("path spec"))?
            .try_into().map_err(session::ParseError::malformed)?;

        Ok(Request {
            path: path,
            follow_symlink: proto.follow_symlink.unwrap_or(false),
            collect_ext_attrs: proto.collect_ext_attrs.unwrap_or(false),
        })
    }
}

impl super::Response for Response {

    const RDF_NAME: Option<&'static str> = Some("StatEntry");

    type Proto = rrg_proto::StatEntry;

    fn into_proto(self) -> Self::Proto {
        use rrg_proto::convert::IntoLossy as _;

        rrg_proto::StatEntry {
            pathspec: Some(self.path.into()),
            #[cfg(target_os = "linux")]
            st_flags_linux: self.flags_linux,
            #[cfg(target_family = "unix")]
            ext_attrs: self.ext_attrs.into_iter().map(Into::into).collect(),
            ..self.metadata.into_lossy()
        }
    }
}

#[cfg(test)]
mod tests {
}
