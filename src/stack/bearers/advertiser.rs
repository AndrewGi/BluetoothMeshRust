use crate::stack::bearer::{BearerError, OutgoingMessage};
use btle::advertiser::Advertiser;
use core::pin::Pin;
use futures_sink::Sink;
use futures_util::task::{Context, Poll};

pub struct AdvertiserSink<A: Advertiser>(A);
impl<A: Advertiser> AdvertiserSink<A> {
    pub fn new(advertiser: A) -> Self {
        Self(advertiser)
    }
    pub fn into_advertiser(self) -> A {
        self.0
    }
    fn sink(self: Pin<&mut Self>) -> Pin<&mut A> {
        unsafe { self.map_unchecked_mut(|s| &mut s.0) }
    }
}

impl<A: Advertiser> Sink<OutgoingMessage> for AdvertiserSink<A> {
    type Error = BearerError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sink()
            .poll_ready(cx)
            .map_err(BearerError::AdvertiserError)
    }

    fn start_send(self: Pin<&mut Self>, item: OutgoingMessage) -> Result<(), Self::Error> {
        self.sink()
            .start_send(item.into())
            .map_err(BearerError::AdvertiserError)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sink()
            .poll_flush(cx)
            .map_err(BearerError::AdvertiserError)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sink()
            .poll_close(cx)
            .map_err(BearerError::AdvertiserError)
    }
}
