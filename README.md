### Bluetooth Mesh Rust
Bluetooth Mesh stack implemented in Rust. In progress port/rewrite of Ero Bluetooth Mesh


# Big Endian
- Network, Lower, Upper, Beacon, Provisioning
- Lower
- Upper
- Beacons
- Provisioning
# Little Endian
- Access
- Foundation


TODO:
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
  - [ ] Bearers
    - [ ] PB-ADV
      - [ ] Links for Provisioning
    - [ ] PB-GATT
    - [ ] PB-Proxy
    - [ ] Custom Proxy?


- [ ] Serialization
  - [ ] Wire Serialization
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
  
