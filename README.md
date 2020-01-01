# Bluetooth Mesh Rust
Bluetooth Mesh stack implemented in Rust. In progress port/rewrite of Ero Bluetooth Mesh.

`#[no_std]`
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
    - [ ] Elements
    - [ ] Models
    - [ ] States
    - [ ] Messages
    - [ ] Acknoledgements
  - [ ] Transport
    - [ ] Upper
      - [ ] Control
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
      - [ ] Segment
      - [ ] Reassembly
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
  - [ ] Text Serialization
    - [x] Tests written

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
  
