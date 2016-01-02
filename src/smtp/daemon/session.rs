
use nom::IResult;
use super::Config;
use super::connection::{Direction, RecvBuf, SendBuf};
use super::super::parser::{parse_command, CommandError};
use super::super::protocol::Command;

// An SMTP session on top of an SMTP connection
//
pub struct Session<'a> {
    config: &'a Config,
    state: State,
}

impl<'a> Session<'a> {
    pub fn new(config: &'a Config) -> Session<'a> {
        Session {
            config: config,
            state: State::Early,
        }
    }

    pub fn process(&mut self, recv: &mut RecvBuf, send: &mut SendBuf)
                   -> Direction {
        let len = recv.len();
        let (advance, dir) = match parse_command(recv.as_slice()) {
            IResult::Done(rest, Ok(cmd)) => {
                (len - rest.len(), self.command(cmd, send, rest.len() == len))
            }
            IResult::Done(rest, Err(e)) => {
                send.push(translate_error(e));
                (len - rest.len(), Direction::Reply)
            }
            IResult::Error(..) => {
                (0, Direction::Closed)
            }
            IResult::Incomplete(..) => (0, Direction::Receive)
        };
        recv.advance(advance);
        dir
    }

    pub fn command(&mut self, cmd: Command, send: &mut SendBuf, last: bool)
                   -> Direction {
        match self.state {
            _ => self.closing(cmd, send, last)
        }
    }

    fn closing(&mut self, cmd: Command, send: &mut SendBuf, last: bool)
               -> Direction {
        match cmd {
            Command::Quit => {
                send.push(b"221 2.0.0 Bye\r\n");
                Direction::Closing
            }
            _ => {
                send.push(b"503 5.0.3 Please leave now\r\n");
                Direction::Reply
            }
        }
    }
}


//------------ State --------------------------------------------------------

/// The state of an SMTP connection.
///
#[derive(Debug)]
enum State {
    /// No Hello has been received yet
    Early,

    /// A Hello has been received and no mail transaction is going on
    Session,

    /// A mail transaction is beeing prepared (ie., we are collecting the
    /// RCPT commands)
    TransactionRcpt,

    /// A mail transaction's data is being received
    TransactionData,

    /// Something went wrong and we are waiting for QUIT
    Closing,

    /// We will close the connection next
    Closed,
}


//------------ Helpers ------------------------------------------------------

fn translate_error(err: CommandError) -> &'static [u8] {
    match err {
        CommandError::Syntax => 
            b"500 5.0.0 Command unrecognized\r\n",
        CommandError::Parameters =>
            b"501 5.0.1 Syntax error in parameters\r\n"
    }
}
