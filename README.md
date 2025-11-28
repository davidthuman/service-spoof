# Service Spoof

Service Spoof is a Go-based honeypot tool that spoofs different web services to log and analyze attack attempts. It allows security researchers to capture scanning and exploitation attempts by mimicking popular web servers and applications.

This project is inspired by [drk1wi/portspoof](https://github.com/drk1wi/portspoof).

## Features

- **Multi-Service Support**: Spoof Apache, Nginx, WordPress, IIS, and more
- **Multi-Port Listening**: Run multiple services on different ports simultaneously
- **YAML Configuration**: Easy-to-edit configuration for services and endpoints
- **SQLite Logging**: Comprehensive request logging to SQLite database
- **Extensible Architecture**: Simple interface for adding new service types

## Quick Start

### Build

```bash
go build -o service-spoof .
```

### Run

```bash
./service-spoof
```

The service will start based on the configuration in [config.yaml](config.yaml).

### Default Ports

- **8070**: Apache 2.4
- **8090**: Nginx
- **8100**: WordPress

## Configuration

Edit [config.yaml](config.yaml) to configure services:

```yaml
version: "1.0"

database:
  path: "./data/service-spoof.db"

services:
  - name: "apache2"
    type: "apache2"
    enabled: true
    ports: [8070]
    headers:
      Server: "Apache/2.4.63 (Unix)"
    endpoints:
      - path: "/*"
        method: "*"
        status: 404
        template: "./services/apache2/404.html"
```

### Service Types

Currently supported service types:

- `apache2` - Apache HTTP Server 2.4
- `nginx` - Nginx web server
- `wordpress` - WordPress CMS
- `iis` - Microsoft IIS

### Adding New Services

1. Create a new file in `internal/service/` (e.g., `myservice.go`)
2. Implement the `Service` interface
3. Add a case in the `NewService` factory function in [internal/service/service.go](internal/service/service.go)
4. Create response templates in `services/myservice/`
5. Add configuration to [config.yaml](config.yaml)

## Database

All incoming HTTP requests are logged to SQLite database at `./data/service-spoof.db`.

### Query Examples

View all logged requests:

```bash
sqlite3 data/service-spoof.db "SELECT timestamp, source_ip, service_name, method, path, response_status FROM request_logs;"
```

Count requests per service:

```bash
sqlite3 data/service-spoof.db "SELECT service_name, COUNT(*) FROM request_logs GROUP BY service_name;"
```

Find potential attack attempts:

```bash
sqlite3 data/service-spoof.db "SELECT source_ip, COUNT(*) as attempts FROM request_logs GROUP BY source_ip ORDER BY attempts DESC;"
```

## Architecture

```
service-spoof/
├── main.go                          # Entry point
├── config.yaml                      # Configuration
├── internal/
│   ├── config/                      # Configuration loading
│   ├── database/                    # SQLite database & logging
│   ├── middleware/                  # HTTP middleware
│   ├── service/                     # Service implementations
│   └── server/                      # Multi-port server manager
└── services/                        # Response templates
```

## Security Research Use Cases

- **Honeypot Deployment**: Deploy on internet-facing servers to capture attack patterns
- **Threat Intelligence**: Analyze scanning behavior and exploit attempts
- **Attack Attribution**: Identify common attacker tactics and tools
- **Security Testing**: Test security monitoring and alerting systems

## Development

### Running Tests

```bash
go test ./...
```

### Building for Production

```bash
CGO_ENABLED=1 go build -o service-spoof .
```

Note: CGO is required for SQLite support.

## License

This project is open source. See LICENSE file for details.

## Acknowledgments

Inspired by [portspoof](https://github.com/drk1wi/portspoof) by drk1wi.
