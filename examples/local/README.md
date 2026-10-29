# Local example

Applies circuit-hardening to a throwaway Rocky Linux 10 container with systemd. You need Conn3x and Podman.

Some of the kernel parameters the circuit sets, such as `kernel.kptr_restrict`, belong to the whole kernel rather than the container, so the host container runs privileged, which is simplest with rootful Podman. In a container those parameters land in the kernel of the Podman machine or the Linux host you run it on. On a Mac, use the Podman machine's root connection. On Linux, use `sudo podman`:

```sh
export CONTAINER_CONNECTION=podman-machine-default-root   # macOS
export PODMAN="sudo podman"                               # Linux
./up.sh
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` To look at the result:

```sh
ssh -p 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1 'sshd -T | grep -iE "^(ciphers|macs|kexalgorithms)"; modprobe -n -v cramfs'
```

`up.sh` listens on `127.0.0.1:2222`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINERFILE` to test another distro, such as one of the images in Conn3x's `test/images`, which CI uses.

`./down.sh` removes the container, its volumes, the key and the state.
