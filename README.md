# Demo of SPA-protected communication of IoT devices

The present project is a demonstration of an authentication and authorization mechanism for IoT devices using the Single Packet Authorization (SPA) technique. The SPA technique is used for device identity authentication, currently implemented by fwknop software for Cloud Security Alliance's SDP networks.

The idea around IoT-SPA, is that the IoT device produces and sends to the gateway a single UDP encrypted packet, the credentials to which are part of the packet payload. The sender’s identity check is done based on this packet. If the SPA packet is successfully authenticated, the Gateway will open a port in the server’s firewall, so that the client can create a safe and encrypted connection to the service demanded.

During the designing and implementation of the packet, contractions in processing speed, memory, and energy consumption of the IoT devices were taken into consideration. The use of the encryption algorithm AES-CCM on authentication ensured the Integrity and Confidentiality of the SPA packet.

The demo includes a Low-Resources device, running contiki-ng, and a remote server where the device authentication takes place. In particular:
* `udp-client.c`: This is the main process that runs in the IoT device, produces the UDP-SPA packet and initiates the authentication process. It also includes an example service (`udp-client` process) that requires SPA to communicate with the server.
* `gateway_controller/gateway_controller.c`: This is the authentication server process that listens for the UDP-SPA packet. If the packet is valid, the device is authorized by adding a new UFW rule at the server.
* `gateway_controller/auth_devices.db`: Sqlte3 Database that contains the authentication keys of the certified devices.
* `gateway_controller/app_server.c`: Server listening for packets of the example service that is protected by the SPA mechanism.

## SPA packet description

The implemented SPA packet has an overall frame size at the physical layer of 90 bytes. The payload has a length of 26 bytes and consists of the following fields:
* `id_mote` *(2 bytes)*: This is unique for each device. Ideally, it consists of the last 2 bytes of the hardware MAC address of the device. For example, if our device has MAC `0012.4b00.1204.d6b0`, then id_mote=`0xd6b0`.
* `crypto_suite` *(1 byte)*: Identifier of the encryption algorithm that will be used for the message encryption. Currently, only AES-CCM_8 encryption is used, which is indicated by 0.
* `nonce` *(13 bytes)*: It consists of two parts. The `random` part has a length of 4 bytes that remain constant. The `counter` part is an 8-bytes counter which begins from 0 and increases each time an SPA packet is succesfully sent. One more priority byte is also added at the beginning of the sequence, which is held for QoS declaration and has always value 0x00. Thus, the overall nonce length is `DTLS_CCM_NONCE_SIZE + 1 = 13 bytes`.
The three above fields make up the additional data field for the AES-CCM encryption. They are used during encryption, for the calculation of the `mac` field calculation. However, these fields are not encrypted themselves. The payload is completed by the following keys:
* `service` *(2 bytes)*: The port of the service, where the client device requires access. In our demo, the example service runs at port 5240. This particular port according to IANA can be used for UDP services and is also unassigned, hence appropriate for our demonstrating purposes. This is the only encrypted field of the payload.
* `mac (message authentication code)` *(8 bytes)*: It is produced during the encryption by the secret key and the additional data. Its inclusion in the packet encryption for authentication adds integrity. For our implementation 8 bytes length has been selected, however lengths from 4 to 16 bytes are also supported.


## Installation requirements
* **OS:** Ubuntu 20.04
* sqlite3
    ```
    sudo apt update && sudo apt upgrade -y
    sudo apt install sqlite3
    sudo apt install libsqlite3-dev
    sudo apt install sqlitebrowser
    ```
* atd service (for firewall rules timeout)
    ```
    sudo apt install at
    sudo service atd start
    ```
* [contiki-ng](https://github.com/GeoParm/contiki-ng)
* [tinydtls](https://github.com/GeoParm/tinydtls)

## Execution instrucions

The computer running the `app_server` is considered as an isolated network resource. The example service listens for incoming packets at the port 5240 which is initially filtered by firewall. `Gateway-Controller` also runs, expecting UDP-SPA packets at port 5678, which remains the only unfiltered port.

Two devices [LAUNCHPAD-CC2650](https://www.ti.com/tool/LAUNCHXL-CC2650) have been used. One is used as the service client (IH of SDP). This device requires authentication and authorization, before being able to access the protected *app_server* service. The second one is used as *border-router*,  and it is connected to our computer through serial interface.

### UFW Setup
In order to simulate the SDP-protected network, UFW is used. It is set up using the following commands:
```
# Install and activate UFW
sudo apt install ufw
sudo ufw enable

# Edit UFW configuration and enable rules for IPv6 addresses.
sudo vi /etc/default/ufw
IPv6=yes

# Deny all incoming connections and allow outgoing
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow incoming connections at port 5678
sudo ufw allow 5678/udp
```
## Run

1. Clone [contiki-ng](https://github.com/GeoParm/contiki-ng)
2. Copy or clone the current repo in the `examples` directory of contiki.
3. Navigate to the `gateway_controller` directory through terminal.
4. Run `make TARGET=native`
5. Run gateway controller with elevated priviledges: `sudo ./gateway_controller.native 5678`
6. Run app\_server in another terminal: `./app_server.native .native 5240`
7. Configure `border-router` as described [here](https://github.com/contiki-ng/contiki-ng/wiki/Tutorial:-RPL-border-router).

## Demo explanation 
Initially, the client device attempts to send to `app\_server` a UDP packet with payload message *"hello1"* to port 5240. If, after a 30-second timeout, no message received acknowledgment has been received from the server, the packet is retransmitted. If the packet is retransmitted 3 times, then an UDP-SPA packet is generated and transmitted to `Gateway-Controller` at port 5678.

`Gateway-Controller` reads the `id_mote` field from the additional data of the incoming message, which for our example is hardcoded to be `0xd6b0`. Then, it searches the key in `auth_devices.db`. If the lookup is successful, it retrieves from the DB the corresponding encryption/decryption secret key and decrypts the service field (`5240 / 0x7814`). Then, the following command will be executed:
```
ufw allow from fd00::212:4b00:1204:d6b0 to any port 5240
```
Thus, the client device will be able to communicate with the app\_server. One more feature implemented is that the rule is not persistent, but times out after a delay that has been configured at 2 minutes. This is implemented by using the command:
```
Delete ufw allow from fd00::212:4b00:1204:d6b0 to any port 5240 | at now + 2 min
```
In case of failure of decrypting an SPA packet by `Gateway_Controller`, the process of generating and transmitting the SPA packet is repeated.
As soon as the message *"hello1"* is acknowledged, the process of generating and transmitting the SPA packet is terminated.