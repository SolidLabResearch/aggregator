# No authorization

The aggregator has a lot of authorization options.
To disable them one has to modify two options in the config `k8s/app/config.yaml`:
```
disable_auth: "true" # Disables authorization
allowed_registration_types: "none" # Allows only an aggreggator registration flow without authorization
```
