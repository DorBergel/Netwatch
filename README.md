# NetWatch

**NetWatch** is a real-time network monitoring CLI tool written in C, using raw sockets to capture and analyze live traffic on a specified network interface. It features protocol parsing, flow statistics, and a terminal UI with ncurses support.

---

## Features

* Capture network packets via **raw sockets** (`AF_PACKET`, `SOCK_RAW`)
* Parse and count:

  * Ethernet
  * IP (IPv4)
  * TCP, UDP, ICMP headers
* Real-time packet counters
* Ncurses-based **dashboard** UI
* **Top Flows** section:

  * Shows IP pairs and their byte counts
  * **Top talker** in **bold**
  * **High-bandwidth flows** in **red** (over 10 MB threshold)
* Command-line filter support: `-f port 53`

---

## Build Instructions

```sh
make
```

Make sure you have:

* GCC
* ncurses development libraries

---

## Run Example

```sh
sudo ./netwatch -i enp1s0
```

Optional filter:

```sh
sudo ./netwatch -i enp1s0 -f port 53
```

---

## File Structure

```
.
├── src/
│   ├── main.c              # Entry point
│   ├── net_utils.c         # Packet capture and parsing logic
├── include/
│   └── net_utils.h         # Shared declarations
├── Makefile
├── README.md
```

---

## Notes

* Root privileges required to open raw sockets
* Tested on Linux (kernel 5+)
* Mac support not available due to `AF_PACKET` usage

---

## TODO

* Export logs to CSV/JSON
* Improve filtering (e.g., by IP, protocol)
* Support for multiple interfaces
* Cross-platform compatibility
