use crate::asyncs::sync::rwlock::rwlock_impl::{
    RwLockImpl, RwLockReadGuardImpl, RwLockWriteGuardImpl,
};
use core::ops::{Deref, DerefMut};

#[cfg(feature = "tokio")]
pub mod rwlock_impl {
    pub type ActualRwLock<T> = tokio::sync::RwLock<T>;
    pub type ActualRwLockWriteGuard<'a, T> = tokio::sync::RwLockWriteGuard<'a, T>;
    pub type ActualRwLockReadGuard<'a, T> = tokio::sync::RwLockReadGuard<'a, T>;

    pub struct RwLockImpl<T>(ActualRwLock<T>);
    impl<T> RwLockImpl<T> {
        pub fn new(t: T) -> Self {
            Self(ActualRwLock::new(t))
        }
        pub async fn write(&self) -> RwLockWriteGuardImpl<'_, T> {
            RwLockWriteGuardImpl(self.0.write().await)
        }
        pub async fn read(&self) -> RwLockReadGuardImpl<'_, T> {
            RwLockReadGuardImpl(self.0.read().await)
        }
    }

    pub struct RwLockWriteGuardImpl<'a, T>(ActualRwLockWriteGuard<'a, T>);
    impl<T> core::ops::Deref for RwLockWriteGuardImpl<'_, T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            self.0.deref()
        }
    }
    impl<T> core::ops::DerefMut for RwLockWriteGuardImpl<'_, T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.0.deref_mut()
        }
    }

    pub struct RwLockReadGuardImpl<'a, T>(ActualRwLockReadGuard<'a, T>);
    impl<T> core::ops::Deref for RwLockReadGuardImpl<'_, T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            self.0.deref()
        }
    }
}
pub struct RwLock<T>(RwLockImpl<T>);
impl<T> RwLock<T> {
    pub fn new(t: T) -> Self {
        Self(RwLockImpl::new(t))
    }
    pub async fn read(&self) -> RwLockReadGuard<'_, T> {
        RwLockReadGuard(self.0.read().await)
    }
    pub async fn write(&self) -> RwLockWriteGuard<'_, T> {
        RwLockWriteGuard(self.0.write().await)
    }
}
pub struct RwLockReadGuard<'a, T>(RwLockReadGuardImpl<'a, T>);
impl<T> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}
pub struct RwLockWriteGuard<'a, T>(RwLockWriteGuardImpl<'a, T>);
impl<T> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}
impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}
