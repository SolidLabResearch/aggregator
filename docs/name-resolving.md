# Local DNS

During testing and development the users might want to host the UMA or resource servers locally.
Because this project uses docker this causes issues as localhost won't be resolved properly.
The solution is to use local domain names like `http://rs.local`.

## Setup
As an example we will assume the resource server is running on `http://localhost:3000`.
We will make sure that `http://rs.local` is mapped to this address.

1) Map `rs.local` to your loopback interface:

```
echo "127.0.0.1 rs.local" | sudo tee -a /etc/hosts
```

2) Add `rs.local` to the DNS of the kubernettes cluster:

In `k8s/ops/coredns-local-hosts.yaml` under hosts, add the new mapping you want to add (keep the `172.19.0.1`):
```
hosts {
  172.19.0.1 rs.local
  ...
  fallthrough
}
```