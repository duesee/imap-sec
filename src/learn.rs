use imap_flow::{
    client::{ClientFlow, ClientFlowEvent, ClientFlowOptions},
    stream::AnyStream,
};
use imap_types::{
    command::{Command, CommandBody},
    core::Tag,
    response::{Status, StatusBody, StatusKind, Tagged},
};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{error, info, warn};

use crate::bisect;

pub(crate) async fn max_literal(host: &str, min: u64, max: u64) -> u64 {
    async fn _max_literal(host: &str, test: u64) -> bool {
        let (mut client, _) = ClientFlow::receive_greeting(
            AnyStream::new(TcpStream::connect(host).await.unwrap()),
            ClientFlowOptions::default(),
        )
        .await
        .unwrap();

        client
            .stream_mut()
            .0
            .write_all(format!("A LOGIN {{{}}}\r\n", test).as_bytes())
            .await
            .unwrap();

        loop {
            match client.progress().await {
                Ok(ClientFlowEvent::StatusReceived {
                    status: Status::Tagged(Tagged { tag, .. }),
                }) if tag.as_ref() == "A" => {
                    return false;
                }
                Ok(ClientFlowEvent::StatusReceived {
                    status: Status::Bye(_),
                }) => {
                    return false;
                }
                Ok(ClientFlowEvent::ContinuationReceived { .. }) => {
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
        let (mut client, _) = ClientFlow::receive_greeting(
            AnyStream::new(TcpStream::connect(host).await.unwrap()),
            ClientFlowOptions::default(),
        )
        .await
        .unwrap();

        let test = "A".repeat(test as usize);
        let tag = Tag::unvalidated(test.clone());

        client.enqueue_command(Command::new(tag, CommandBody::Noop).unwrap());

        loop {
            match client.progress().await {
                Ok(ClientFlowEvent::StatusReceived {
                    status: Status::Tagged(Tagged { tag, .. }),
                }) if tag.as_ref() == test.as_str() => {
                    return true;
                }
                Ok(ClientFlowEvent::StatusReceived {
                    status: Status::Bye(_),
                }) => {
                    return false;
                }
                Ok(ClientFlowEvent::StatusReceived {
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

    for (_, char, res) in tests.iter_mut() {
        let (mut client, _) = ClientFlow::receive_greeting(
            AnyStream::new(TcpStream::connect(host).await.unwrap()),
            ClientFlowOptions::default(),
        )
        .await
        .unwrap();

        let test = format!("A{}", char);

        client
            .stream_mut()
            .0
            .write_all(format!("{test} NOOP\r\n").as_bytes())
            .await
            .unwrap();

        loop {
            match client.progress().await {
                Ok(ClientFlowEvent::StatusReceived {
                    status: Status::Tagged(Tagged { tag, .. }),
                }) => {
                    *res = Some(if test.as_str() == tag.as_ref() {
                        AllowedResult::Reflected
                    } else {
                        AllowedResult::ReflectedBroken
                    });
                    break;
                }
                Ok(ClientFlowEvent::StatusReceived {
                    status: Status::Untagged(StatusBody { kind, .. }),
                }) if kind == StatusKind::Bad => {
                    *res = Some(AllowedResult::Bad);
                    break;
                }
                Ok(ClientFlowEvent::StatusReceived {
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
