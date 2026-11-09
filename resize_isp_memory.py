#!/usr/bin/env python3
"""Set 5120 MiB for ISP VMs 10101,10201,...,11601 on the local Proxmox node.
Default: plan only. --apply: change memory; never stop/start/delete a VM.
Running guests may require a full shutdown and start to use the new memory.
Python 3.9+, standard library only.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

VMIDS = tuple(range(10101, 11602, 100))
TARGET = 5120


class Error(RuntimeError):
    pass


def run(*args):
    p = subprocess.run(list(map(str, args)), stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, timeout=120)
    if p.returncode:
        raise Error(p.stderr.strip() or p.stdout.strip() or "Command failed")
    return p.stdout.strip()


def api(path, *args):
    return json.loads(run("pvesh", "get", path, *args, "--output-format", "json"))


def pending_changes(rows):
    return {row["key"]: row for row in rows
            if "pending" in row or int(row.get("delete", 0)) != 0}


def validate(vmid, cfg, pending):
    if vmid not in VMIDS:
        raise Error(f"{vmid}: VMID is outside the fixed ISP list")
    if not re.search(r"(?:^|[-_])ISP$", cfg.get("name", ""), re.I):
        raise Error(f"{vmid}: VM name is not ISP")
    if cfg.get("lock") or cfg.get("template"):
        raise Error(f"{vmid}: VM is locked or is a template")
    if int(cfg.get("memory", 0)) not in (4096, TARGET):
        raise Error(f"{vmid}: expected 4096 or 5120 MiB; refusing another value")
    if int(cfg.get("balloon", 0)) != 0:
        raise Error(f"{vmid}: ballooning is enabled; expected migrated ISP with balloon=0")
    changes = pending_changes(pending)
    if changes and not (
        set(changes) == {"memory"}
        and not int(changes["memory"].get("delete", 0))
        and int(changes["memory"].get("pending", 0)) == TARGET
    ):
        raise Error(f"{vmid}: unrelated pending changes; no changes made to this VM")
    return int(cfg.get("memory", 0)) != TARGET and not changes


def gather():
    node = Path("/etc/pve/local").resolve(strict=True).name
    resources = api("/cluster/resources", "--type", "vm")
    owners = {int(row["vmid"]): row for row in resources}
    plans = []
    for vmid in VMIDS:
        row = owners.get(vmid)
        if not row or row.get("type") != "qemu" or row.get("node") != node:
            raise Error(f"{vmid}: QEMU VM is missing or belongs to another node")
        path = f"/nodes/{node}/qemu/{vmid}"
        cfg = api(path + "/config", "--current", "1")
        pending = api(path + "/pending")
        change = validate(vmid, cfg, pending)
        plans.append({"vmid": vmid, "path": path, "config": cfg,
                      "pending": pending, "change": change})
    return plans


def apply(plans):
    # Recheck every target before the first write.
    for plan in plans:
        cfg = api(plan["path"] + "/config", "--current", "1")
        pending = api(plan["path"] + "/pending")
        if cfg != plan["config"] or pending_changes(pending) != pending_changes(plan["pending"]):
            raise Error(f'{plan["vmid"]}: configuration changed since preflight')
        validate(plan["vmid"], cfg, pending)
    directory = Path("/root/isp-memory-5g")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    log = directory / (stamp + ".json")
    with os.fdopen(os.open(str(log), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        json.dump(plans, f, indent=2)
    print(f"Original settings: {log}")
    for plan in plans:
        vmid, path = plan["vmid"], plan["path"]
        if not plan["change"]:
            print(f"{vmid}: already 5120 MiB or already queued; skipped")
            continue
        cfg = api(path + "/config", "--current", "1")
        pending = api(path + "/pending")
        if cfg != plan["config"] or pending_changes(pending) != pending_changes(plan["pending"]):
            raise Error(f"{vmid}: configuration changed; stopped. Earlier VMs may already be updated")
        validate(vmid, cfg, pending)
        args = ["qm", "set", str(vmid), "--memory", str(TARGET)]
        if cfg.get("digest"):
            args += ["--digest", cfg["digest"]]
        run(*args)
        effective = api(path + "/config")
        if int(effective.get("memory", 0)) != TARGET:
            raise Error(f"{vmid}: cannot verify target memory; inspect this VM")
        # Memory is the only option passed to qm set.
        for key, value in cfg.items():
            if key not in ("digest", "memory") and effective.get(key) != value:
                raise Error(f"{vmid}: unexpected change in {key}; inspect this VM")
        current = api(path + "/config", "--current", "1")
        suffix = "configured" if int(current.get("memory", 0)) == TARGET else "queued; needs full shutdown and start"
        print(f"{vmid}: 5120 MiB {suffix}")
    print("Done. No VMs were stopped, started or deleted. Running guests may need a full shutdown and start.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Apply the memory increase")
    args = parser.parse_args()
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise Error("Run as root on the Proxmox node owning all 16 ISP VMs")
    for tool in ("qm", "pvesh"):
        if not shutil.which(tool):
            raise Error("Required command missing: " + tool)
    plans = gather()
    for plan in plans:
        print(f'{plan["vmid"]}: {plan["config"].get("name")} memory={plan["config"]["memory"]} -> 5120 MiB'
              + ("" if plan["change"] else " (already configured/queued)"))
    extra = sum(TARGET - int(p["config"]["memory"]) for p in plans)
    print(f"Additional guest memory at full allocation: {extra} MiB")
    if args.apply:
        apply(plans)
    else:
        print("Plan only. Add --apply to change memory.")


if __name__ == "__main__":
    try:
        main()
    except (Error, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        sys.exit(1)
