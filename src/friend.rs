//! Optional Bluetooth Mesh Friends feature.
use crate::address::UnicastAddress;
use crate::mesh::{IVIndex, IVUpdateFlag, KeyRefreshFlag, U24};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Flags(u8);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FSN(bool);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct MD(u8);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Criteria(u8);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct ReceiveDelay(u8);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct PollTimeout(U24);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct LPNCounter(u16);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum RSSIFactor {
    Factor1 = 0b00,
    Factor2 = 0b01,
    Factor3 = 0b10,
    Factor4 = 0b11,
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum ReceiveWindowFactor {
    Window1 = 0b00,
    Window2 = 0b01,
    Window3 = 0b10,
    Window4 = 0b11,
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum MinQueueSizeLog {
    Prohibited = 0b000,
    N2 = 0b001,
    N4 = 0b010,
    N8 = 0b011,
    N16 = 0b100,
    N32 = 0b101,
    N64 = 0b110,
    N128 = 0b111,
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendPoll {
    fsn: FSN,
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendUpdate {
    key_refresh_flag: KeyRefreshFlag,
    iv_update_flag: IVUpdateFlag,
    iv_index: IVIndex,
    md: MD,
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendRequest {
    criteria: Criteria,
    receive_delay: ReceiveDelay,
    poll_timeout: PollTimeout,
    previous_address: UnicastAddress,
    num_elements: u8,
    lpn_counter: LPNCounter,
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendClear {
    address: UnicastAddress,
    counter: LPNCounter,
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendClearConfirm {
    address: UnicastAddress,
    counter: LPNCounter,
}
