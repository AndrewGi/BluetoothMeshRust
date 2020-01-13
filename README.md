# Bluetooth Mesh Rust
Bluetooth Mesh stack implemented in Rust. In progress port/rewrite of Ero Bluetooth Mesh. Following the Bluetooth Mesh Spec Core v1.0. Designed to work with any BLE radio but currently targeting linux for testing. The complete stack still needs more glue between the layers but all the parts should be fully functional. If any mistake are found, please contact me!

`#![no_std]` excepts for dependence on `std::Instant` for time but a different source can be provided. While not provided, on ARM; a crystal oscilator can be the time source. 

Partially `serde` support but still needs much more work.

The only heap allocations made durning processing a message is allocating memory for the message at the access layer. Most Mesh PDUs are <31 bytes (to fit in a single BLE Advertisement) so the Network and Lower Transport Layer stores its data staticly on the stack.

## 8 Layer system
![The 8 Layer of the Bluetooth Mesh Stack](/mesh_layout.PNG)

### Big Endian
- Network
- Lower
- Upper
- Beacons
- Provisioning
### Little Endian
- Access
- Foundation


TODO:
- [ ] Model
  - [ ] Isolated SDK layer
- [ ] Stack
  - [ ] Access
    - [x] Elements
    - [x] Models
    - [ ] States
    - [x] Messages
    - [ ] Acknowledgements
  - [ ] Transport
    - [ ] Upper
      - [x] Control
        - [ ] Heartbeat
        - [ ] Friend
          - [ ] Poll
          - [ ] Update
          - [ ] Request
          - [ ] Offer
          - [ ] Clear
          - [ ] Clear Confirm
          - [ ] Subscription List
            - [ ] Add
            - [ ] Remove
            - [ ] Confirm
    - [ ] Lower
      - [x] Segment
      - [x] Reassembly
      - [ ] Friend Queue
  - [ ] Net
    - [ ] Encrypting
    - [x] Payload
    - [x] Header
  - [ ] Bearers
    - [x] PB-ADV
      - [x] Links for Provisioning
    - [ ] PB-GATT
    - [ ] PB-Proxy
    - [ ] Custom Proxy?
  - [ ] Crypto Functions
    - [x] k1
    - [x] k2
    - [x] k3
    - [x] k4
    - [x] s1
    - [x] Tests for k1-k4, s1
    - [x] id128
    - [ ] ECDH
    - [x] AES-CMAC
    - [x] AES-ECB
  - [ ] Provisioning
    - [ ] PB-GATT
    - [x] PB_ADV
      - [x] Links
    - [ ] Generic
    - [ ] Key Exchange
    - [ ] Segmentation
    - [ ] Reassembly
    
- [ ] Serialization
  - [ ] Wire Serialization
    - [x] Tests written
  - [ ] Text Serialization

- [ ] Models
  - [ ] Config
    - [ ] Composition Data
    - [ ] Model Publication
    - [ ] Subscription List
    - [ ] NetKey List
    - [ ] AppKey List
    - [ ] Model to AppKey List
    - [ ] Default TTL
    - [ ] Relay
    - [ ] Attention Timer
    - [ ] Secure Network Beacon
    - [ ] GATT Proxy
    - [ ] Node Identity
    - [ ] Friend
    - [ ] Key Refresh Phase
    - [ ] Health Fault
    - [ ] Health Fast Period Divisor
    - [ ] Heartbeat Publication
    - [ ] Heartbeat Subscription
    - [ ] Network Transmit
    - [ ] Relay Retransmit
    - [ ] PollTimeout List
  - [ ] Health
  
