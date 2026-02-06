# Connect with kvasir-compose

How to connect with a kvasir server set up with docker compose.
Based on [this repository](https://gitlab.ilabt.imec.be/kvasir/kvasir-server).

## 1. Create the shared Docker network

```
docker network create sharednet
```

## 2. Update compose files

### Kvasir service

In the `kvasir` service **remove this line**:
```yaml
network_mode: host
```

Once we remove `network_mode: host`, `localhost` will point to the kvasir container itself.
Replace environment variables with **service names**:
```yaml
environment:
      - KVASIR_KG_CLICKHOUSE_HOST=clickhouse
      - KVASIR_KG_CLICKHOUSE_PORT=8123
      - KVASIR_MESSAGING_KAFKA_BOOTSTRAP_SERVERS=kafka:9092
      - KVASIR_STORAGE_S3_ENDPOINT=http://minio:9000
      - KVASIR_STORAGE_S3_REGION=us-east-1
      - KVASIR_STORAGE_S3_ACCESS_KEY_ID=kvasir
      - KVASIR_STORAGE_S3_SECRET_ACCESS_KEY=kvasirkvasir
      - KVASIR_AUTH_KEYCLOAK_URL=http://keycloak:8080
      - KVASIR_PEP_OPENFGA_URL=http://openfga:8080
```

### Kafka service

In the `kafka` service **set the following environment variable**:
```yaml
environment:
    - KAFKA_ADVERTISED_HOSTNAME=kafka
```

Update the `--advertise-kafka-addr` command:
```yaml
command:
      - --advertise-kafka-addr internal://kafka:9092
```

### 3. Attatch services to `sharednet`

Add `sharednet` to all services.

Example for `kvasir`:
```yaml
kvasir:
  image: gitlab.ilabt.imec.be:4567/kvasir/kvasir-server/monolith:0.16.1
  networks:
    - sharednet
```

Add network to `compose.yml`:
```
networks:
  sharednet:
    external: true
```

### 4. Attatch kind cluster to `shartednet`

Run:
```
docker network connect sharednet aggregator-control-plane
```

You can now reach
 - kvasir service via `http://kvasir:8080`
 - keycloak service via `http://keycloak:8080`