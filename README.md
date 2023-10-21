# SBOM Vulnerability Analyzer
Generate improved SBOM Vulnerability report

## Installation instructions:

### 1. Run using Docker

#### Pull images from DockerHub
```bash
docker pull justuser0129/sva
docker pull mysql
```

#### Create Network to connect MySQL container
```bash
docker create network <network-name>
```

#### Run Application and MySQL container
```bash
docker run -d --network <network-name> [--name <container-name>] -p <port>:8080 justuser0129/sva[:version]
docker run -d --network <network-name> --name mysql-container -p <port>:3306 mysql[:version]
```

### 2. Run using Docker-compose

```bash
docker compose up -d
```

## GuideLine (Example)
### GET SBOM report using OWASP Dependency-Track  

```bash
curl "{baseUrl}/api/v1/sbom?token={token}&projectId={projectId}&baseUrl={baseUrl}"
```

### GET improved SBOM report

```bash
curl "{baseUrl}/api/v1/sbom/report?token={token}&projectId={projectId}&baseUrl={baseUrl}"
```

### Architecture

