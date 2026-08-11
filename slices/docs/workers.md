# Add a worker node to the Slices cluster

Run these commands from the repository root. Before creating a node, choose:

- a unique node name after `create`, such as `worker4`;
- a Slices flavor appropriate for the workload, such as `xlarge`; and
- whether the node needs local storage.

Use a `worker` name and `slices/cluster/worker.yaml` for a regular worker
without an available local volume. Use a `volume-worker` name and
`slices/cluster/worker-volume.yaml` when the worker should provide a local
volume. A numeric suffix can be added to keep names unique, for example
`worker4` or `volume-worker4`.

## Create a regular worker

Replace `<node-name>`, `<image>`, and `<flavor>` with the values for the new
node:

```bash
slices bi --site-id be-gent1-bi-vm1 create <node-name> \
  --image <image> \
  --flavor <flavor> \
  --user-data slices/cluster/worker.yaml \
  -d "89d"
```

For example:

```bash
slices bi --site-id be-gent1-bi-vm1 create worker4 \
  --image image_be-gent1-bi-vm1_4jcfp572q99mtv3649rzpgbd0 \
  --flavor xlarge \
  --user-data slices/cluster/worker.yaml \
  -d "89d"
```

## Create a worker with a local volume

Use the volume-specific cloud-init file:

```bash
slices bi --site-id be-gent1-bi-vm1 create volume-worker4 \
  --image image_be-gent1-bi-vm1_4jcfp572q99mtv3649rzpgbd0 \
  --flavor xlarge \
  --user-data slices/cluster/worker-volume.yaml \
  -d "89d"
```

The image identifier may change when a new image is published. Select the
current image and the required flavor before running the command.

## Verify that the node joined

Wait for the new node to appear and reach the `Ready` state:

```bash
kubectl --context admin@aggregator-cluster get nodes -o wide
```

The Slices resource name, such as `volume-worker4`, is not necessarily the
Kubernetes node name. Use the new Talos node name shown in the `NAME` column for
subsequent Kubernetes commands.

## Label a worker with local storage

Only workers created with `worker-volume.yaml` should receive the local-storage
label. Replace `<talos-node-name>` with the name of the new storage node from
the previous command:

```bash
kubectl label node <talos-node-name> storage=local
```

For example, if the new node is named `talos-c4s-38g`:

```bash
kubectl label node talos-c4s-38g storage=local
```

Confirm both readiness and the label:

```bash
kubectl --context admin@aggregator-cluster get nodes -L storage -o wide
```
