# XDP_GTP

XDP/eBPF program (with custom loader and CLI) for gNB-UPF GTP encapsulation.

## Getting Started

### Prerequisites

- Golang >= 1.21.4 (not yet tested with prior versions)
- Linux >= 5.19.0 (not yet tested with prior versions)

### Installing

Clone the repo:

```
git clone https://github.com/Rotchamar/xdp_gtp
```

Build main executable:

```
go build
```

## Deployment & Usage

The executable file `/golang/xdp_gtp` will be used to start the application. 
XDP_GTP includes several flags to adapt to different scenarios, information on these is accessible through the `-h` flag:

```
Usage of ./xdp_gtp:
  -c value
        A,B,C -> A: Client IP addr | B: TEID | C: UPF IP addr
  -i string
        A,B -> A: Interface where XDP client-facing program is to be attached | B: Interface where XDP UPF-facing program is to be attached 
        (if not supplied, both will be attached to the same interface) (default "enp0s3")
  -m string
        XDP attach mode (generic|driver|offload) (default "generic")
```

### Example: XDP_GTP basic deployment

In this scenario, we will deploy two clients in different networks that are to communicate with each other through a dummy 5G network (AGF to UPF).
For simplicity's sake, the control plane will be disregarded and, therefore, not implemented.
The resulting architecture is as follows:

![Sample Deployment](/docs/sample_deployment_architecture.png)

#### Step 1: Configure default gateway in Clients A and B

- Client A:
```
sudo ip route add default via 10.0.1.1
```

- Client B:
```
sudo ip route add default via 10.0.2.1
```

#### Step 2: Start XDP_GTP in AGF/UPF A and B

- AGF/UPF A:
```
sudo ./golang/xdp_gtp -i eth0,eth1 -c 10.0.1.10,1,10.0.100.20
```

- AGF/UPF B:
```
sudo ./golang/xdp_gtp -i eth0,eth1 -c 10.0.2.10,1,10.0.100.10
```

If VMs 2 and 3's support XDP in driver or hardware offload mode, use `-m driver` or `-m offload` for better performance.

#### Step 4: Test the scenario

Use tools such as ping or iperf to test the conectivity between Clients A and B and benchmark the performance.

## Modifying the XDP/eBPF program

Taking into consideration the ease of use of this application, the pre-compiled eBPF bytecode and generated Go helper 
functions are provided in the repository, removing the need for users to compile and generate these elements by themselves.
To provide more advanced users the possibility of making changes to the XDP/eBPF code, the following instructions 
for Ubuntu 22.04LTS are presented.

### Install dependencies

```
sudo apt install clang llvm libelf-dev libbpf-dev libc6-dev-i386
```

### Compiling the XDP/eBPF program and generating Go helpers

This step makes use of Cilium's `bpf2go` program which is called with `go generate`.

```
cd ./golang
go generate
```


## Authors

* **Roberto Chamorro** - *Initial work* - [Rotchamar](https://github.com/Rotchamar)

See also the list of [contributors](https://github.com/Rotchamar/xdp_gtp/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
