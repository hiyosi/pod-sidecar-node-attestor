# K8s-sidecar-node-attestor

This is a PoC project.
The Attestor is **NOT** production ready.

## Motivation

Run the SPIRE Agent as a Pod Sidecar.

It'll no longer need to share UDS across Pods, no longer require users to deploy Kubernetes PodSecurityPolicy for UDS connections.
