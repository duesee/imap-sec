use std::error::Error;

use imap_next::{
    client::{Client, Event, Options},
    stream::Stream,
};
use imap_types::{
    command::{Command, CommandBody},
    core::{IString, NString, Tag, Vec1},
    response::{Capability, Code, Data, Status, StatusBody, StatusKind, Tagged},
    utils::escape_byte_string,
};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{error, info, trace, warn};

use crate::bisect;

#[derive(Debug)]
pub(crate) struct Info {
    greeting_capability: Option<Vec1<Capability<'static>>>,
    pre_auth_capability: Option<Vec1<Capability<'static>>>,
    pre_auth_id: Option<Option<Vec<(IString<'static>, NString<'static>)>>>,
    post_auth_capability: Option<Vec1<Capability<'static>>>,
    post_auth_id: Option<Option<Vec<(IString<'static>, NString<'static>)>>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct InfoSimple {
    greeting_capability: Vec<Capability<'static>>,
    pre_auth_capability: Vec<Capability<'static>>,
    pre_auth_id: Option<Vec<(String, Option<String>)>>,
    post_auth_capability: Vec<Capability<'static>>,
    post_auth_id: Option<Vec<(String, Option<String>)>>,
}

impl From<Info> for InfoSimple {
    fn from(value: Info) -> Self {
        Self {
            greeting_capability: value
                .greeting_capability
                .map(|inner| inner.into_inner())
                .unwrap_or_default(),
            pre_auth_capability: value
                .pre_auth_capability
                .map(|inner| inner.into_inner())
                .unwrap_or_default(),
            pre_auth_id: value.pre_auth_id.flatten().map(|thing| {
                thing
                    .into_iter()
                    .map(|(k, NString(v))| {
                        (
                            String::from_utf8(k.as_ref().to_vec()).unwrap(),
                            v.map(|v| String::from_utf8(v.as_ref().to_vec()).unwrap()),
                        )
                    })
                    .collect()
            }),
            post_auth_capability: value
                .post_auth_capability
                .map(|inner| inner.into_inner())
                .unwrap_or_default(),
            post_auth_id: value.post_auth_id.flatten().map(|thing| {
                thing
                    .into_iter()
                    .map(|(k, NString(v))| {
                        (
                            String::from_utf8(k.as_ref().to_vec()).unwrap(),
                            v.map(|v| String::from_utf8(v.as_ref().to_vec()).unwrap()),
                        )
                    })
                    .collect::<Vec<_>>()
            }),
        }
    }
}

// TODO: Too much copy&paste ...
pub(crate) async fn info(
    host: String,
    username: Option<String>,
    password: Option<String>,
) -> Result<InfoSimple, Box<dyn Error>> {
    let mut stream = Stream::insecure(TcpStream::connect(host).await.unwrap());
    let mut client = Client::new(Options::default());

    let greeting = loop {
        match stream.next(&mut client).await.unwrap() {
            Event::GreetingReceived { greeting } => break greeting,
            event => println!("unexpected event: {event:?}"),
        }
    };

    let mut result = Info {
        greeting_capability: if let Some(Code::Capability(capabilities)) = greeting.code {
            Some(capabilities)
        } else {
            None
        },
        pre_auth_capability: None,
        pre_auth_id: None,
        post_auth_capability: None,
        post_auth_id: None,
    };

    client.enqueue_command(Command::new("X", CommandBody::Capability)?);

    loop {
        match stream.next(&mut client).await? {
            Event::CommandSent { .. } => {}
            Event::DataReceived {
                data: Data::Capability(capabilities),
            } => result.pre_auth_capability = Some(capabilities),
            Event::StatusReceived {
                status:
                    Status::Tagged(Tagged {
                        tag,
                        body: StatusBody { code, .. },
                    }),
            } => {
                if let Some(Code::Capability(capabilities)) = code {
                    result.pre_auth_capability = Some(capabilities);
                }

                if tag.as_ref() == "X" {
                    break;
                }
            }
            event => {
                warn!(?event, "unexpected event");
            }
        }
    }

    let id_body = CommandBody::Id {
        parameters: Some(vec![(
            IString::try_from("name").unwrap(),
            NString(Some(IString::try_from("imap-sec").unwrap())),
        )]),
    };

    client.enqueue_command(Command::new("A", id_body.clone())?);

    loop {
        match stream.next(&mut client).await? {
            Event::CommandSent { .. } => {}
            Event::DataReceived {
                data: Data::Id { parameters },
            } => result.pre_auth_id = Some(parameters),
            Event::StatusReceived {
                status: Status::Tagged(Tagged { tag, .. }),
            } if tag.as_ref() == "A" => {
                break;
            }
            event => {
                warn!(?event, "unexpected event");
            }
        }
    }

    if let (Some(username), Some(password)) = (username, password) {
        client.enqueue_command(Command::new("B", CommandBody::login(username, password)?)?);

        loop {
            match stream.next(&mut client).await? {
                Event::CommandSent { .. } => {}
                Event::StatusReceived {
                    status:
                        Status::Tagged(Tagged {
                            tag,
                            body: StatusBody { kind, code, text },
                        }),
                } if tag.as_ref() == "B" => {
                    if kind == StatusKind::Ok {
                        break;
                    } else {
                        error!(?code, ?text, "LOGIN failed");
                        return Err("LOGIN failed".into());
                    }
                }
                event => {
                    warn!(?event, "unexpected event");
                }
            }
        }

        client.enqueue_command(Command::new("X2", CommandBody::Capability)?);

        loop {
            match stream.next(&mut client).await? {
                Event::CommandSent { .. } => {}
                Event::DataReceived {
                    data: Data::Capability(capabilities),
                } => result.pre_auth_capability = Some(capabilities),
                Event::StatusReceived {
                    status:
                        Status::Tagged(Tagged {
                            tag,
                            body: StatusBody { code, .. },
                        }),
                } => {
                    if let Some(Code::Capability(capabilities)) = code {
                        result.pre_auth_capability = Some(capabilities);
                    }

                    if tag.as_ref() == "X2" {
                        break;
                    }
                }
                event => {
                    warn!(?event, "unexpected event");
                }
            }
        }

        client.enqueue_command(Command::new("C", id_body.clone())?);

        loop {
            match stream.next(&mut client).await? {
                Event::CommandSent { .. } => {}
                Event::DataReceived {
                    data: Data::Id { parameters },
                } => result.post_auth_id = Some(parameters),
                Event::StatusReceived {
                    status: Status::Tagged(Tagged { tag, .. }),
                } if tag.as_ref() == "C" => {
                    break;
                }
                event => {
                    warn!(?event, "unexpected event");
                }
            }
        }
    }

    Ok(InfoSimple::from(result))
}

pub(crate) async fn max_literal(host: &str, min: u64, max: u64) -> u64 {
    async fn _max_literal(host: &str, test: u64) -> bool {
        let mut stream = Stream::insecure(TcpStream::connect(host).await.unwrap());
        let mut client = Client::new(Options::default());

        let _ = loop {
            match stream.next(&mut client).await.unwrap() {
                Event::GreetingReceived { greeting } => break greeting,
                event => println!("unexpected event: {event:?}"),
            }
        };

        stream
            .stream_mut()
            .write_all(format!("A LOGIN {{{}}}\r\n", test).as_bytes())
            .await
            .unwrap();

        loop {
            match stream.next(&mut client).await {
                Ok(Event::StatusReceived {
                    status: Status::Tagged(Tagged { tag, .. }),
                }) if tag.as_ref() == "A" => {
                    return false;
                }
                Ok(Event::StatusReceived {
                    status: Status::Bye(_),
                }) => {
                    return false;
                }
                Ok(Event::ContinuationRequestReceived { .. }) => {
                    return true;
                }
                Ok(event) => warn!(?event, "unexpected event"),
                Err(error) => {
                    error!(?error);
                    return false;
                }
            }
        }
    }

    let mut bisect = bisect::Bisect::new(min, max);
    info!(min = bisect.min(), max = bisect.max());

    while let Some(next) = bisect.next() {
        if _max_literal(host, next).await {
            bisect.accept();
        } else {
            bisect.reject();
        }
        info!(min = bisect.min(), max = bisect.max());
    }

    bisect.finish().unwrap()
}

pub(crate) async fn max_tag(host: &str, min: u64, max: u64) -> u64 {
    async fn _max_tag(host: &str, test: u32) -> bool {
        let mut stream = Stream::insecure(TcpStream::connect(host).await.unwrap());
        let mut client = Client::new(Options::default());

        let _ = loop {
            match stream.next(&mut client).await.unwrap() {
                Event::GreetingReceived { greeting } => break greeting,
                event => println!("unexpected event: {event:?}"),
            }
        };

        let test = "A".repeat(test as usize);
        let tag = Tag::unvalidated(test.clone());

        client.enqueue_command(Command::new(tag, CommandBody::Noop).unwrap());

        loop {
            match stream.next(&mut client).await {
                Ok(Event::CommandSent { .. }) => {}
                Ok(Event::StatusReceived {
                    status: Status::Tagged(Tagged { tag, .. }),
                }) if tag.as_ref() == test.as_str() => {
                    return true;
                }
                Ok(Event::StatusReceived {
                    status: Status::Bye(_),
                }) => {
                    return false;
                }
                Ok(Event::StatusReceived {
                    status: Status::Untagged(StatusBody { kind, .. }),
                }) if kind == StatusKind::Bad => {
                    return false;
                }
                Ok(event) => warn!(?event, "unexpected event"),
                Err(error) => {
                    error!(?error);
                    return false;
                }
            }
        }
    }

    let mut bisect = bisect::Bisect::new(min, max);

    while let Some(next) = bisect.next() {
        if _max_tag(host, u32::try_from(next).unwrap()).await {
            bisect.accept();
        } else {
            bisect.reject();
        }
    }

    bisect.finish().unwrap()
}

#[derive(Debug)]
pub(crate) enum AllowedResult {
    Reflected,
    ReflectedBroken,
    Bad,
    Bye,
    Error,
}

pub(crate) async fn allowed_tag(host: &str) -> Vec<(u8, char, Option<AllowedResult>)> {
    let mut tests = (0..=255u8)
        .into_iter()
        .map(|dec| (dec, dec as char, None))
        .collect::<Vec<_>>();

    for (dec, _, res) in tests.iter_mut() {
        let mut stream = Stream::insecure(TcpStream::connect(host).await.unwrap());
        let mut client = Client::new(Options::default());

        let _ = loop {
            match stream.next(&mut client).await.unwrap() {
                Event::GreetingReceived { greeting } => break greeting,
                event => println!("unexpected event: {event:?}"),
            }
        };

        let mut test = Vec::new();
        test.push(b'A');
        test.push(*dec);

        let mut data = Vec::new();
        data.extend_from_slice(&test);
        data.extend_from_slice(b" NOOP\r\n");

        // TODO: Hack
        trace!(data = escape_byte_string(&data), "io/write/raw");
        stream.stream_mut().write_all(&data).await.unwrap();

        loop {
            match stream.next(&mut client).await {
                Ok(Event::StatusReceived {
                    status: Status::Tagged(Tagged { tag, .. }),
                }) => {
                    *res = Some(if test == tag.as_ref().as_bytes() {
                        AllowedResult::Reflected
                    } else {
                        AllowedResult::ReflectedBroken
                    });
                    break;
                }
                Ok(Event::StatusReceived {
                    status: Status::Untagged(StatusBody { kind, .. }),
                }) if kind == StatusKind::Bad => {
                    *res = Some(AllowedResult::Bad);
                    break;
                }
                Ok(Event::StatusReceived {
                    status: Status::Bye(_),
                }) => {
                    *res = Some(AllowedResult::Bye);
                    break;
                }
                Ok(event) => warn!(?event, "unexpected event"),
                Err(error) => {
                    error!(?error);
                    *res = Some(AllowedResult::Error);
                    break;
                }
            }
        }
    }

    tests
}
