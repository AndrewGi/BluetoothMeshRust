use btle::error::Error;
use core::future::Future;
use core::pin::Pin;
use core::task::Context;
use core::task::Poll;
pub use core::time::Duration;

#[cfg(feature = "tokio")]
pub mod time_impl {
    use super::{Context, Duration, Future, Pin, Poll};

    pub struct DelayImpl(tokio::time::Delay);
    impl DelayImpl {
        pub fn new(duration: Duration) -> Self {
            Self(tokio::time::delay_for(duration))
        }
        pub fn reset(&mut self, dur: Duration) {
            self.0.reset(tokio::time::Instant::now() + dur)
        }
    }
    impl Future for DelayImpl {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
        }
    }
}

pub fn delay_for(duration: Duration) -> Delay {
    Delay::new(duration)
}

pub struct Delay(time_impl::DelayImpl);
impl Delay {
    fn new(duration: Duration) -> Self {
        Self(time_impl::DelayImpl::new(duration))
    }
    pub fn reset(&mut self, duration: Duration) {
        self.0.reset(duration)
    }
}
impl Future for Delay {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
    }
}

pub fn timeout<T, F: Future<Output = T>>(duration: Duration, future: F) -> TimeoutFuture<F> {
    TimeoutFuture {
        future,
        delay: Delay::new(duration),
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Default)]
pub struct TimeoutError(());
impl Error for TimeoutError {}
pub struct TimeoutFuture<F: Future> {
    future: F,
    delay: Delay,
}
impl<F: Future> Future for TimeoutFuture<F> {
    type Output = Result<F::Output, TimeoutError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.future) }.poll(cx) {
            Poll::Ready(v) => Poll::Ready(Ok(v)),
            Poll::Pending => {
                match unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.delay) }.poll(cx) {
                    Poll::Ready(_) => Poll::Ready(Err(TimeoutError(()))),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}
