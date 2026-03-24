# K-Jump - SSH Jump-Host Management System

K-Jump is a professional, lightweight management system for SSH connections, specifically designed for environments utilizing jump hosts. The project's primary objective is to provide a streamlined and efficient tool for rapid access to Linux servers, focusing on essential functionality rather than feature complexity. It consists of a server component for centralized credential management (Vault) and a client component for automated execution of SSH sessions.

## System Overview

The architecture is designed to minimize the exposure of sensitive data to the client. The K-Jump server acts as a central vault and jump host. When a connection is initiated, only the jump host's SSH key is briefly transmitted to the client to facilitate the secure tunnel.

### Core Components

- **K-Jump Server**: Based on the Ktor framework (CIO engine), it manages the ObjectBox database, handles authentication, and provides the API for SSH session preparation.
- **K-Jump Client**: A CLI-based tool (JAR) that interacts with the server, queries the vault, and executes local SSH processes using process handover.

## Key Features

- **Streamlined Access**: Optimized for speed and ease of use, providing a no-nonsense tool for managing Linux server connections.
- **Centralized Secure Vault**: Storage of server metadata, including IPs, ports, and usernames.
- **Robust Encryption**: All private keys are stored encrypted within the ObjectBox database and are only decrypted in memory during the connection phase.
- **Jump-Host Security**: Strategic data isolation ensures that target system keys remain on the server, with the client only handling temporary session-specific credentials.
- **Rate-Limiting**: Integrated protection against brute-force attacks on the API.
- **Client Distribution**: The server serves as the distribution point for the pre-configured client.

## Technical Specifications

- **Language**: Kotlin (JVM 21)
- **Framework**: Ktor 3.4.0
- **Database**: ObjectBox (Embedded NoSQL)
- **Engine**: CIO (Coroutine-based I/O)
- **Serialization**: Kotlinx Serialization (JSON)
- **Logging**: KLogger with Logback

## Platform Support and Constraints

- **Operating System**: Currently, the client is exclusively supported on **Linux**. It relies on the native `ssh` command and JVM's `inheritIO` for terminal interaction. While Mac and Windows support may be technically feasible, it is not within the current project scope.
- **Authentication Scope**: The system currently focuses exclusively on SSH key-based authentication (without passwords).
- **Multi-Tenancy**: The system is designed for single-user operation. For environments requiring multiple users, it is recommended to deploy multiple isolated instances of the K-Jump server.

## Installation and Configuration

### Server Deployment

1. Ensure Java 21 is installed.
2. Deploy the `fat.jar` to the target host.
3. Start the service:
   ```bash
   java -jar fat.jar
   ```
4. Default access is via port `8090`.

### Client Usage

1. Retrieve the client via the `/download` endpoint.
2. Execute the client:
   ```bash
   java -jar kj-client.jar
   ```
3. Authenticate and select the target server from the interactive CLI.

## API Overview

- `POST /auth/login`: Authentication and token issuance.
- `GET /vault`: Lists available server entries (Requires `X-API-Token`).
- `POST /vault`: Register new servers in the vault.
- `POST /prepare`: Session preparation and temporary credential provisioning.
- `GET /download`: Client binary download.

## Roadmap and Future Developments

The following features are planned for future releases to enhance the system's capabilities while maintaining its core focus on simplicity:

- **TOTP Authentication**: Integration of Time-based One-Time Passwords for enhanced login security.
- **File Transfer**: Simplified upload and download mechanisms for efficient data movement between client and target servers.

## Security Considerations

System security relies on the integrity of the jump host and the secrecy of the API tokens. It is strongly recommended to deploy the server behind a TLS-enabled reverse proxy and maintain regular backups of the `objectbox/` data directory.
