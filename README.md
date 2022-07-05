The present project is a demonstration of an authentication and authorization mechanism of IoT devices using the Single Packet Authorization (SPA) technique. The SPA technique is used for device identity authentication, curently implemented by fwknop software for Cloud Security Alliance's SDP networks.
The idea around IoT-SPA, is that the IoT device produces and sends to the gateway a single UDP encrypted packet, the credentials to which are part of the packet payload. The sender’s identity check is done based on this packet. If the SPA packet is successfully authenticated, the Gateway will open a port in the server’s firewall, so that the client can create a safe and encrypted connection to the service demanded.
During the designing and implementation of the packet, contractions in processing speed, memory and energy consumption the Internet of Things introduces were taken into consideration. The use of an encryption algorithm AES-CCM ensured Authentication, Integrity and Confidentiality of the SPA packet.

The project consists of a Low-Resources device, running contiki-ng, and an application server, called `Gateway-Controller` which runs on a computations-capable device.

More details about the present project will be provided at the near future.

## Execution instrucions

TBA


## Project dependencies and other libraries used

* contiki-ng
* tinydtls

