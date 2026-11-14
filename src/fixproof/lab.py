"""Build lab images and drive one host into a state (containers, no VMs)."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

import yaml

from .evidence import resolve

REPO = Path(__file__).resolve().parents[2]
LAB = REPO / "lab"
MEM = "384m"           # every lab host container
PROXY = os.environ.get("HTTPS_PROXY", "http://127.0.0.1:44125")
CA = os.environ.get("FIXPROOF_PROXY_CA", "/root/.ccr/ca-bundle.crt")


def load_images() -> dict:
    return yaml.safe_load((LAB / "images.yml").read_text())


def load_hosts() -> dict:
    return yaml.safe_load((LAB / "hosts.yml").read_text())


def sh(args: list[str], check=True, timeout=1800, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout, **kw)


def ubuntu_tag(distro: str) -> str:
    return f"fixproof/{distro}:s0"


def build_ubuntu(distro: str) -> str:
    cfg = load_images()
    spec = cfg["ubuntu"][distro]
    ctx = LAB / "ubuntu"
    shutil.copy(CA, ctx / "proxy-ca.crt")  # build-time only: apt reaches the archive through the lab proxy
    args = ["docker", "build", "--network", "host", "--memory", "1g", "-t", ubuntu_tag(distro),
            "--build-arg", f"https_proxy={PROXY}", "--build-arg", f"BASE={spec['base']}",
            "--build-arg", f"RELEASE={spec['release']}", "--build-arg", f"FIXED_SNAPSHOT={cfg['fixed_snapshot']}",
            "--build-arg", f"PACKAGES={spec['packages']}", "--build-arg", f"KERNEL_PACKAGE={spec['kernel_package']}",
            str(ctx)]
    p = subprocess.run(args, capture_output=True, text=True, timeout=3600)
    (ctx / "proxy-ca.crt").unlink(missing_ok=True)
    if p.returncode:
        raise RuntimeError(p.stderr[-3000:])
    return ubuntu_tag(distro)


def image_digest(ref: str) -> dict:
    out = sh(["docker", "image", "inspect", ref, "--format", "{{json .}}"]).stdout
    d = json.loads(out)
    return {"ref": ref, "id": d["Id"], "repo_digests": d.get("RepoDigests", []), "created": d.get("Created")}


# ------------------------------------------------------------------ host lifecycle

class Host:
    """One lab host: a container brought into a state by a list of steps."""

    def __init__(self, distro: str, state: str, repeat: int):
        self.distro, self.state, self.repeat = distro, state, repeat
        self.name = f"fp-h-{distro}-{state}-r{repeat}".replace(".", "")
        self.cfg = load_images()
        self.official = distro in self.cfg["official"]
        hosts = load_hosts()
        self.recipe = (hosts["official_states"] if self.official else hosts["ubuntu_states"])[state]
        self.log: list[dict] = []

    @property
    def image(self) -> str:
        if not self.official:
            return ubuntu_tag(self.distro)
        return self.cfg["official"][self.distro][self.recipe["image"]]

    def start(self):
        sh(["docker", "rm", "-f", self.name], check=False)
        sh(["docker", "run", "-d", "--name", self.name, "--hostname", "lab", "--memory", MEM,
            "--network", "none", "--cap-add", "SYS_PTRACE", "--entrypoint", "sleep", self.image, "infinity"])
        if not self.official:  # the repo's copy of the state scripts is authoritative
            sh(["docker", "cp", f"{LAB / 'ubuntu/files'}/.", f"{self.name}:/opt/fixproof-lab/"])
            self.exec("chmod +x /opt/fixproof-lab/*.sh")
        self._record("start", self.image, 0, "")

    def stop(self):
        sh(["docker", "rm", "-f", self.name], check=False)

    def exec(self, cmd: str, timeout=900) -> tuple[int, str]:
        p = subprocess.run(["docker", "exec", self.name, "sh", "-c", cmd], capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout + p.stderr

    def _record(self, step, detail, rc, out):
        self.log.append({"step": step, "detail": detail, "rc": rc, "t": round(time.time(), 2), "output": out[-4000:]})

    def run_step(self, step: str):
        if step == "collect-before":
            return  # handled by the runner
        if step == "start-procs":
            rc, out = self.exec(self._procs_cmd())
        elif step == "reboot":
            p = sh(["docker", "restart", "-t", "1", self.name], check=False)
            rc, out = p.returncode, p.stdout + p.stderr
        elif step == "overlay":
            new = self.cfg["official"][self.distro]["new"]
            stats = overlay(self.name, new)
            rc, out = 0, json.dumps(stats)
        else:
            rc, out = self.exec(f"/opt/fixproof-lab/{step}.sh")
        self._record(step, "", rc, out)
        if rc:
            raise RuntimeError(f"{self.name}: step {step} failed: {out[-1500:]}")
        time.sleep(1)

    def _procs_cmd(self) -> str:
        kind = self.cfg["official"][self.distro]["procs"]
        if kind == "nginx":
            return "nginx && sleep 1"
        if kind == "python-tls":
            return ("nohup python3 -c 'import ssl, time; ctx = ssl.create_default_context(); time.sleep(10**9)' "
                    ">/dev/null 2>&1 & sleep 1")
        return "true"  # holder: PID 1 (sleep) already maps libc and the loader


# ------------------------------------------------------------------ overlay update

SKIP = ("dev/", "proc/", "sys/", "run/", "tmp/", "etc/hostname", "etc/hosts", "etc/resolv.conf", "etc/mtab",
        ".dockerenv")


def overlay(container: str, new_image: str) -> dict:
    """Write every file of ``new_image`` that differs over the running container, by rename.

    dpkg, rpm and apk all unpack a new file next to the old one and rename it into place, so a
    process that mapped the old file keeps the old inode (it shows as "(deleted)"). This does the
    same for the whole image, package databases included, which leaves the host in the state an
    in-place upgrade to the newer image's package set would leave it in, minus maintainer scripts.
    """
    pid1 = sh(["docker", "inspect", "-f", "{{.State.Pid}}", container]).stdout.strip()
    root = f"/proc/{pid1}/root"
    tmpname = f"fp-overlay-{os.getpid()}"
    sh(["docker", "rm", "-f", tmpname], check=False)
    sh(["docker", "create", "--name", tmpname, new_image, "true"])
    stats = {"replaced": 0, "same": 0, "new": 0, "symlinks": 0, "skipped": 0, "replaced_paths": []}
    try:
        proc = subprocess.Popen(["docker", "export", tmpname], stdout=subprocess.PIPE)
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            for m in tar:
                name = m.name.lstrip("./")
                if not name or name.startswith(SKIP):
                    stats["skipped"] += 1
                    continue
                parent = resolve(root, "/" + posixpath.dirname(name))
                dest = os.path.join(parent, posixpath.basename(name))
                if m.isdir():
                    if not os.path.lexists(dest):
                        os.makedirs(dest, exist_ok=True)
                        os.chmod(dest, m.mode)
                    continue
                os.makedirs(parent, exist_ok=True)
                tmp = os.path.join(parent, f".fpnew.{posixpath.basename(name)}")
                if m.issym():
                    if os.path.islink(dest) and os.readlink(dest) == m.linkname:
                        stats["same"] += 1
                        continue
                    if os.path.isdir(dest) and not os.path.islink(dest):
                        stats["skipped"] += 1
                        continue
                    if os.path.lexists(tmp):
                        os.unlink(tmp)
                    os.symlink(m.linkname, tmp)
                    os.replace(tmp, dest)
                    stats["symlinks"] += 1
                    continue
                if not (m.isfile() or m.islnk()):
                    stats["skipped"] += 1
                    continue
                f = tar.extractfile(m) if m.isfile() else None
                if f is None:  # hard link inside the stream: copy from the already written target
                    src = os.path.join(resolve(root, "/" + posixpath.dirname(m.linkname)), posixpath.basename(m.linkname))
                    data = Path(src).read_bytes()
                else:
                    data = f.read()
                if os.path.isfile(dest) and not os.path.islink(dest):
                    with open(dest, "rb") as old:
                        if hashlib.sha256(old.read()).digest() == hashlib.sha256(data).digest():
                            stats["same"] += 1
                            continue
                    stats["replaced"] += 1
                    stats["replaced_paths"].append("/" + name)
                else:
                    stats["new"] += 1
                with open(tmp, "wb") as out:
                    out.write(data)
                os.chown(tmp, m.uid, m.gid)
                os.chmod(tmp, m.mode)
                os.replace(tmp, dest)
        proc.wait()
    finally:
        sh(["docker", "rm", "-f", tmpname], check=False)
    return stats
