use core::convert::TryFrom;
use core::num::FpCategory::Nan;
use core::time::Duration;

#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
pub struct Milliseconds(u32);
#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
pub struct Microseconds(u32);
#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
pub struct Nanoseconds(u32);

impl TryFrom<Milliseconds> for Microseconds {
    type Error = ();

    fn try_from(v: Milliseconds) -> Result<Microseconds, Self::Error> {
        Ok(Microseconds((v.0).checked_mul(1000).ok_or(())?))
    }
}

impl TryFrom<Milliseconds> for Nanoseconds {
    type Error = ();

    fn try_from(v: Milliseconds) -> Result<Nanoseconds, Self::Error> {
        Ok(Nanoseconds((v.0).checked_mul(1000 * 1000).ok_or(())?))
    }
}

impl From<Microseconds> for Milliseconds {
    fn from(v: Microseconds) -> Milliseconds {
        Milliseconds((v.0) / 1000)
    }
}

impl TryFrom<Microseconds> for Nanoseconds {
    type Error = ();

    fn try_from(v: Microseconds) -> Result<Nanoseconds, Self::Error> {
        Ok(Nanoseconds((v.0).checked_mul(1000).ok_or(())?))
    }
}

impl From<Nanoseconds> for Microseconds {
    fn from(v: Nanoseconds) -> Microseconds {
        Microseconds((v.0) / 1000)
    }
}

impl From<Nanoseconds> for Milliseconds {
    fn from(v: Nanoseconds) -> Milliseconds {
        Milliseconds((v.0) / (1000 * 1000))
    }
}

#[cfg(test)]
mod test {
    use crate::time::*;
    use core::convert::{TryFrom, TryInto};

    #[test]
    fn test_into() {
        let milli = Milliseconds(1000);
        let nano = Nanoseconds(1000 * 1000 * 1000);
        let big_milli = Milliseconds(1000 * 1000);
        assert_eq!(
            Microseconds::try_from(milli).unwrap(),
            Microseconds(1000 * 1000)
        );
        assert_eq!(Nanoseconds::try_from(milli).unwrap(), nano);

        assert!(Microseconds::try_from(big_milli).is_ok());
        assert!(Nanoseconds::try_from(big_milli).is_err());
    }
}
