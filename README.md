# SBOMaster: A SBOM-Enhanced DevSecOps Pipeline Framework
Generate improved SBOM Vulnerability report

## Installation instructions:

### 1. Run using Docker

#### Pull images from DockerHub
```bash
docker pull justuser0129/sbomaster
docker pull mysql
```

#### Create Network to connect MySQL container
```bash
docker create network <network-name>
```

#### Run Application and MySQL container
```bash
docker run -d --network <network-name> [--name <container-name>] -p <port>:8080 justuser0129/sbomaster[:version]
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

## How to Integrate in CI/CD pipeline?
### GitHub Actions
- Generate Secret Key for pipeline
  - SBOMaster url
  - OWASP Dependency-Track url
  - OWASP Dependency-Track token
  - OWASP Dependency-Track projects' UUID

- Create yml and Integrate scripts
```yml
name: Get SBOMaster's report file
run: curl -X GET 'https://${{ secrets.SBOMASTER_URL }}/api/v1/sbom/report?token=${{ secrets.TOKEN }}&uuid=${{ secrets.UUID }}&baseurl=${{ secrets.TRACK_URL }}' | jq '.' > filename.json
``` 

## Architecture
![image](https://github.com/Juser0/SBOMaster/assets/108407945/5e29a3ab-ce42-4eb2-ba6f-443424410263)




