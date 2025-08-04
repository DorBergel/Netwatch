# NetWatch

NetWatch is a lightweight C-based network statistics monitoring tool. It captures and analyzes raw network packets to provide live statistics on protocol usage and traffic breakdown in real time.

## Features

- Captures live network traffic using raw sockets
- Tracks per-protocol statistics (TCP, UDP, ICMP, etc.)
- Logs packet data to a CSV file for later analysis
- Clean modular C code with reusable components
- Simple CLI-based dashboard

## Project Structure

```
netwatch/
├── Makefile                   # Build instructions
├── log.csv                    # Log file with captured network data
├── build/                     # Compiled object files
├── src/                       # Source files (main logic)
│   ├── main.c
│   ├── net_utils.c
│   └── cli.c
├── include/                   # Header files
│   ├── net_utils.h
│   └── cli.h
```

## Requirements

- GCC compiler
- Linux-based system with raw socket access (sudo required)

## Build Instructions

To compile the project:

```bash
make
```

This will build the object files and produce an executable called `netwatch`.

## Run Instructions

Run the program with appropriate permissions:

```bash
sudo ./netwatch
```

Network statistics will be displayed on the terminal and logged to `log.csv`.

## Key Components

- `net_utils.c/h`: Handles raw socket setup and packet parsing
- `cli.c/h`: Manages terminal interface and dashboard output
- `main.c`: Initializes components and runs the capture loop

## Future Improvements

- Add support for more detailed packet inspection (DNS, ARP, etc.)
- Implement filtering and capture controls (e.g., interface selection)
- Enhance dashboard display using ncurses
- Export reports in structured formats (JSON, HTML)

## License

This project is released for educational and diagnostic use.

## Author

Dor Bergel  
GitHub: [https://github.com/DorBergel](https://github.com/DorBergel)
