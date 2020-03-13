use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
#[cfg(feature = "tokio")]
pub mod task_impl {
    use super::{Context, Future, Pin, Poll};

    pub struct JoinHandleImpl<T>(tokio::task::JoinHandle<T>);
    impl<T> Future for JoinHandleImpl<T> {
        type Output = T;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx) {
                Poll::Ready(r) => Poll::Ready(r.expect("task join failed")),
                Poll::Pending => Poll::Pending,
            }
        }
    }
    pub fn spawn<T: Send + 'static, F: Future<Output = T> + Send + 'static>(
        future: F,
    ) -> JoinHandleImpl<T> {
        JoinHandleImpl(tokio::task::spawn(future))
    }
}
pub fn spawn<T: Send + 'static, F: Future<Output = T> + Send + 'static>(
    future: F,
) -> JoinHandle<T> {
    JoinHandle(task_impl::spawn(future))
}
pub struct JoinHandle<T>(task_impl::JoinHandleImpl<T>);
impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
    }
}
