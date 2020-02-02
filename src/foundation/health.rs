/// FaultID. According to Bluetooth Mesh Spec v1.0. Odd values are usually Warnings while even
/// values are Errors.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FaultID {
    NoFault,
    BatteryLowWarning,
    BatterLowError,
    SupplyVoltageTooLowWarning,
    SupplyVoltageTooLowError,
    SupplyVoltageTooHighWarning,
    SupplyVoltageTooHighError,
    PowerSupplyInterruptedWarning,
    PowerSupplyInterruptedError,
    NoLoadWarning,
    NoLoadError,
    OverloadWarning,
    OverloadError,
    OverheatWarning,
    OverheatError,
    CondensationWarning,
    CondensationError,
    VibrationWarning,
    VibrationError,
    ConfigurationWarning,
    ConfigurationError,
    ElementNotCalibratedWarning,
    ElementNotCalibratedError,
    MemoryWarning,
    MemoryError,
    SelfTestWarning,
    SelfTestError,
    InputTooLowWarning,
    InputTooLowError,
    InputTooHighWarning,
    InputTooHighError,
    InputNoChangeWarning,
    InputNoChangeError,
    ActuatorBlockedWarning,
    ActuatorBlockedError,
    HousingOpenedWarning,
    HousingOpenedError,
    TamperWarning,
    TamperError,
    DeviceMovedWarning,
    DeviceMovedError,
    DeviceDroppedWarning,
    DeviceDroppedError,
    OverflowWarning,
    OverflowError,
    EmptyWarning,
    EmptyError,
    InternalBusWarning,
    InternalBusError,
    MechanismJammedWarning,
    MechanismJammedError,
    RFU(u8),
    Vendor(u8),
}

impl From<FaultID> for u8 {
    fn from(fault_id: FaultID) -> Self {
        match fault_id {
            FaultID::NoFault => 0x00,
            FaultID::BatteryLowWarning => 0x01,
            FaultID::BatterLowError => 0x02,
            FaultID::SupplyVoltageTooLowWarning => 0x03,
            FaultID::SupplyVoltageTooLowError => 0x04,
            FaultID::SupplyVoltageTooHighWarning => 0x05,
            FaultID::SupplyVoltageTooHighError => 0x06,
            FaultID::PowerSupplyInterruptedWarning => 0x07,
            FaultID::PowerSupplyInterruptedError => 0x08,
            FaultID::NoLoadWarning => 0x09,
            FaultID::NoLoadError => 0x0A,
            FaultID::OverloadWarning => 0x0B,
            FaultID::OverloadError => 0x0C,
            FaultID::OverheatWarning => 0x0D,
            FaultID::OverheatError => 0x0E,
            FaultID::CondensationWarning => 0x0F,
            FaultID::CondensationError => 0x10,
            FaultID::VibrationWarning => 0x11,
            FaultID::VibrationError => 0x12,
            FaultID::ConfigurationWarning => 0x13,
            FaultID::ConfigurationError => 0x14,
            FaultID::ElementNotCalibratedWarning => 0x15,
            FaultID::ElementNotCalibratedError => 0x16,
            FaultID::MemoryWarning => 0x17,
            FaultID::MemoryError => 0x18,
            FaultID::SelfTestWarning => 0x19,
            FaultID::SelfTestError => 0x1A,
            FaultID::InputTooLowWarning => 0x1B,
            FaultID::InputTooLowError => 0x1C,
            FaultID::InputTooHighWarning => 0x1D,
            FaultID::InputTooHighError => 0x1E,
            FaultID::InputNoChangeWarning => 0x1F,
            FaultID::InputNoChangeError => 0x20,
            FaultID::ActuatorBlockedWarning => 0x21,
            FaultID::ActuatorBlockedError => 0x22,
            FaultID::HousingOpenedWarning => 0x23,
            FaultID::HousingOpenedError => 0x24,
            FaultID::TamperWarning => 0x25,
            FaultID::TamperError => 0x26,
            FaultID::DeviceMovedWarning => 0x27,
            FaultID::DeviceMovedError => 0x28,
            FaultID::DeviceDroppedWarning => 0x29,
            FaultID::DeviceDroppedError => 0x2A,
            FaultID::OverflowWarning => 0x2B,
            FaultID::OverflowError => 0x2C,
            FaultID::EmptyWarning => 0x2D,
            FaultID::EmptyError => 0x2E,
            FaultID::InternalBusWarning => 0x2F,
            FaultID::InternalBusError => 0x30,
            FaultID::MechanismJammedWarning => 0x31,
            FaultID::MechanismJammedError => 0x32,
            FaultID::RFU(id) => id,
            FaultID::Vendor(id) => id,
        }
    }
}
impl From<u8> for FaultID {
    fn from(b: u8) -> Self {
        match b {
            0x00 => FaultID::NoFault,
            0x01 => FaultID::BatteryLowWarning,
            0x02 => FaultID::BatterLowError,
            0x03 => FaultID::SupplyVoltageTooLowWarning,
            0x04 => FaultID::SupplyVoltageTooLowError,
            0x05 => FaultID::SupplyVoltageTooHighWarning,
            0x06 => FaultID::SupplyVoltageTooHighError,
            0x07 => FaultID::PowerSupplyInterruptedWarning,
            0x08 => FaultID::PowerSupplyInterruptedError,
            0x09 => FaultID::NoLoadWarning,
            0x0A => FaultID::NoLoadError,
            0x0B => FaultID::OverloadWarning,
            0x0C => FaultID::OverloadError,
            0x0D => FaultID::OverheatWarning,
            0x0E => FaultID::OverheatError,
            0x0F => FaultID::CondensationWarning,
            0x10 => FaultID::CondensationError,
            0x11 => FaultID::VibrationWarning,
            0x12 => FaultID::VibrationError,
            0x13 => FaultID::ConfigurationWarning,
            0x14 => FaultID::ConfigurationError,
            0x15 => FaultID::ElementNotCalibratedWarning,
            0x16 => FaultID::ElementNotCalibratedError,
            0x17 => FaultID::MemoryWarning,
            0x18 => FaultID::MemoryError,
            0x19 => FaultID::SelfTestWarning,
            0x1A => FaultID::SelfTestError,
            0x1B => FaultID::InputTooLowWarning,
            0x1C => FaultID::InputTooLowError,
            0x1D => FaultID::InputTooHighWarning,
            0x1E => FaultID::InputTooHighError,
            0x1F => FaultID::InputNoChangeWarning,
            0x20 => FaultID::InputNoChangeError,
            0x21 => FaultID::ActuatorBlockedWarning,
            0x22 => FaultID::ActuatorBlockedError,
            0x23 => FaultID::HousingOpenedWarning,
            0x24 => FaultID::HousingOpenedError,
            0x25 => FaultID::TamperWarning,
            0x26 => FaultID::TamperError,
            0x27 => FaultID::DeviceMovedWarning,
            0x28 => FaultID::DeviceMovedError,
            0x29 => FaultID::DeviceDroppedWarning,
            0x2A => FaultID::DeviceDroppedError,
            0x2B => FaultID::OverflowWarning,
            0x2C => FaultID::OverflowError,
            0x2D => FaultID::EmptyWarning,
            0x2E => FaultID::EmptyError,
            0x2F => FaultID::InternalBusWarning,
            0x30 => FaultID::InternalBusError,
            0x31 => FaultID::MechanismJammedWarning,
            0x32 => FaultID::MechanismJammedError,
            0x33..=0x7F => FaultID::RFU(b),
            0x80..=0xFF => FaultID::Vendor(b),
            _ => unreachable!("all u8 values should be handled"), //IntellJ complains if I remove this line
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FaultID;
    /// Tests to make sure that the `From` trait is matching the `Into` trait.
    #[test]
    pub fn test_fault_id() {
        for i in 0..=0xFFu8 {
            let fault_id = FaultID::from(i);
            assert_eq!(u8::from(fault_id), i);
        }
    }
}
