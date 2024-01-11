# RsCNI debug plugin

`rscni-debug` is for debugging CNI plugin development.
This is based on [containernetworking/cni/plugins/cni](https://github.com/containernetworking/cni/tree/v1.0.0/plugins/debug).

## Configuration

To run `rscni-debug` as a part of CNI chaining, we have to add the following configuration in CNI configuration that is placed in `/etc/cni/net.d`.

Please refer to [netconf.json](./netconf.json) to see the complete CNI configuration.

`cniOutput` is the path to the directory for output files.

```json
{
  "type": "rscni-debug",
  "cniOutput": "/tmp/cni"
}
```

## Run

We can try to use `rscni-debug` in the kind cluster.

```console
$ # Build a rscni-debug binary
$ # Start kind cluster
$ # Copy netconf.json to the container
$ # Copy rscni-debug to the container
$ make start
cargo build --release --example rscni-debug
(snip)
    Finished release [optimized] target(s) in 5.25s
kind create cluster
Creating cluster "kind" ...
 ✓ Ensuring node image (kindest/node:v1.26.3) 🖼
 ✓ Preparing nodes 📦  
 ✓ Writing configuration 📜 
 ✓ Starting control-plane 🕹️ 
 ✓ Installing CNI 🔌 
 ✓ Installing StorageClass 💾 
Set kubectl context to "kind-kind"
You can now use your cluster with:

kubectl cluster-info --context kind-kind

Thanks for using kind! 😊
docker cp ../target/release/examples//rscni-debug kind-control-plane:/opt/cni/bin/rscni-debug
Successfully copied 5.12MB to kind-control-plane:/opt/cni/bin/rscni-debug
docker cp ./netconf.json kind-control-plane:/etc/cni/net.d/01-rscni-debug.conflist
Successfully copied 2.56kB to kind-control-plane:/etc/cni/net.d/01-rscni-debug.conflist
$ # wait for creating some pods.
$ kubectl get pod -A
kubectl get pod -A
NAMESPACE            NAME                                         READY   STATUS    RESTARTS   AGE
kube-system          coredns-787d4945fb-7xrrd                     1/1     Running   0          116s
kube-system          coredns-787d4945fb-f4dk8                     1/1     Running   0          116s
kube-system          etcd-kind-control-plane                      1/1     Running   0          2m10s
kube-system          kindnet-2djjv                                1/1     Running   0          116s
kube-system          kube-apiserver-kind-control-plane            1/1     Running   0          2m13s
kube-system          kube-controller-manager-kind-control-plane   1/1     Running   0          2m10s
kube-system          kube-proxy-m7d4m                             1/1     Running   0          116s
kube-system          kube-scheduler-kind-control-plane            1/1     Running   0          2m10s
local-path-storage   local-path-provisioner-75f5b54ffd-42pzb      1/1     Running   0          116s
$ # exec into kind-control-plane
$ docker exec -it kind-control-plane bash
$ # list /tmp/cni
root@kind-control-plane:/# ls /tmp/cni
0a6a4b09df59d64e3be5cf662808076fee664447a1c90dd05a5d5588e2cd6b5a-Add  8f45a2e34dbca276cd15b3dc137eaa4f341ed3937404dca8fb7d7dbd47a860d1-Add
0a6a4b09df59d64e3be5cf662808076fee664447a1c90dd05a5d5588e2cd6b5a-Del  dc590314c1023d6ac95eafd08d09e71eb5eba7869ed38b1bad871f69ae5498a3-Add
1b9347ea59ae481b6a9a0bb6fecd12cfcd8b4ff0a05a1a21bf7c269663f99135-Add
$ # check the CNI output
root@kind-control-plane:/# cat /tmp/cni/0a6a4b09df59d64e3be5cf662808076fee664447a1c90dd05a5d5588e2cd6b5a-Add
CNI_COMMAND: Add
CNI_CONTAINERID: 0a6a4b09df59d64e3be5cf662808076fee664447a1c90dd05a5d5588e2cd6b5a
CNI_IFNAME: eth0
CNI_NETNS: Some("/var/run/netns/cni-8e9dfbc7-eaff-12a8-925e-4b280eb12d67")
CNI_PATH: ["/opt/cni/bin"]
CNI_ARGS: Some("K8S_POD_INFRA_CONTAINER_ID=0a6a4b09df59d64e3be5cf662808076fee664447a1c90dd05a5d5588e2cd6b5a;K8S_POD_UID=b0e1fc4a-f842-4ec2-8e23-8c0c8da7b5e5;IgnoreUnknown=1;K8S_POD_NAMESPACE=kube-system;K8S_POD_NAME=coredns-787d4945fb-7xrrd"),
STDIN_DATA: {"cniVersion":"0.3.1","name":"kindnet","type":"rscni-debug","prevResult":{"interfaces":[{"name":"veth3e00fda7","mac":"de:ba:bf:29:5a:80"},{"name":"eth0","mac":"fa:6f:76:59:25:82","sandbox":"/var/run/netns/cni-8e9dfbc7-eaff-12a8-925e-4b280eb12d67"}],"ips":[{"interface":1,"address":"10.244.0.3/24","gateway":"10.244.0.1"}],"routes":[{"dst":"0.0.0.0/0"}],"dns":{}},"cniOutput":"/tmp/cni"}
--------------------
```

To clean up kind cluter, run `make stop`.
