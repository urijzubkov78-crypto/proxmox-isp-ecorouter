"""Independent behavioral tests: no Proxmox, network, credentials or GitHub calls."""
import copy
import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "migrate_isp.py"
SPEC = importlib.util.spec_from_file_location("migrate_isp_under_test", MODULE_PATH)
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)

def config_a():
    return {
        "name": "ISP",
        "protection": "1",
        "boot": "order=scsi0;net0",
        "memory": "512",
        "cores": "1",
        "cpu": "host",
        "agent": "1",
        "machine": "pc-i440fx-7.0",
        "serial0": "socket",
        "tablet": "0",
        "scsihw": "virtio-scsi-single",
        "scsi0": "local:10101/vm-10101-disk-0.qcow2,size=20G",
        "sata0": "ssd:10101/vm-10101-disk-1.qcow2,size=1G",
        "ide2": "none,media=cdrom",
        "net0": "virtio=02:AA:BB:00:00:01,bridge=vmbr0,firewall=1,tag=77,mtu=1400,rate=9.5,queues=2",
        "net1": "virtio=02:AA:BB:00:00:02,bridge=vmbr1001",
        "net2": "virtio=02:AA:BB:00:00:03,bridge=vmbr1002",
        "digest": "old-digest",
    }

def config_b():
    result = config_a()
    result["net3"] = result.pop("net2")
    result["net2"] = result.pop("net1")
    result["net1"] = result.pop("net0")
    result["net0"] = "vmxnet3=1C:87:76:40:12:34,bridge=vmbr0,link_down=1"
    return result

def mac_factory():
    values = iter("1C:87:76:40:00:%02X" % n for n in range(1, 20))
    return lambda: next(values)

def nic_options(value):
    tokens = value.split(",")
    result = {}
    for token in tokens:
        key, sep, val = token.partition("=")
        result[key] = val if sep else True
    return result

class ConfigAndPlanningTests(unittest.TestCase):
    def test_parser_preserves_values_with_equals_and_ignores_blank_lines(self):
        parsed = m.parse_config("name: ISP\n\nprotection: 1\nnet0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0\n")
        self.assertEqual(parsed["name"], "ISP")
        self.assertEqual(parsed["protection"], "1")
        self.assertEqual(parsed["net0"], "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0")

    def test_fingerprint_is_order_independent_and_ignores_only_digest(self):
        first = config_a()
        second = dict(reversed(list(first.items())))
        second["digest"] = "different-digest"
        self.assertEqual(m.fingerprint(first), m.fingerprint(second))
        second["memory"] = "1024"
        self.assertNotEqual(m.fingerprint(first), m.fingerprint(second))

    def test_three_port_isp_preserves_wan_attributes_and_bridge_roles(self):
        before = config_a()
        output = m.build_networks(before, mac_factory=mac_factory())
        self.assertEqual(set(output), {"net0", "net1", "net2", "net3"})
        self.assertEqual(nic_options(output["net0"])["link_down"], "1")
        self.assertEqual(nic_options(output["net0"])["bridge"], "vmbr0")
        wan = nic_options(output["net1"])
        for key, value in {"bridge": "vmbr0", "firewall": "1", "tag": "77", "mtu": "1400", "rate": "9.5", "queues": "2"}.items():
            self.assertEqual(wan[key], value, key)
        self.assertNotEqual(wan.get("link_down"), "1")
        self.assertEqual(nic_options(output["net2"])["bridge"], "vmbr1001")
        self.assertEqual(nic_options(output["net3"])["bridge"], "vmbr1002")
        macs = [nic_options(output[key])["vmxnet3"] for key in sorted(output)]
        self.assertEqual(len(set(macs)), 4)
        self.assertTrue(all(mac.upper().startswith("1C:87:76:40:") for mac in macs))
        self.assertEqual(before, config_a(), "planning must not mutate input")

    def test_existing_disabled_management_nic_is_not_used_as_wan(self):
        output = m.build_networks(config_b(), mac_factory=mac_factory())
        self.assertEqual(nic_options(output["net1"])["tag"], "77")
        self.assertEqual(nic_options(output["net2"])["bridge"], "vmbr1001")
        self.assertEqual(nic_options(output["net3"])["bridge"], "vmbr1002")
        self.assertEqual(nic_options(output["net0"])["link_down"], "1")

    def test_explicit_network_mapping_preserves_vlan_trunks(self):
        cfg = config_a()
        cfg["net0"], cfg["net1"] = cfg["net1"], cfg["net0"] + ",trunks=10;20;30"
        output = m.build_networks(cfg, mac_factory=mac_factory(), override={"wan": "net1", "hq": "net0", "br": "net2"})
        self.assertEqual(nic_options(output["net1"])["trunks"], "10;20;30")

    def test_ambiguous_extra_nic_is_rejected(self):
        cfg = config_a()
        cfg["net4"] = "virtio=02:AA:BB:00:00:04,bridge=vmbr9999"
        with self.assertRaises(m.Error):
            m.build_networks(cfg, mac_factory=mac_factory())

    def test_plan_keeps_protection_and_disks_and_uses_free_ide_slot(self):
        cfg = config_a()
        cfg["ide0"] = "local:10101/vm-10101-cloudinit.qcow2,media=cdrom"
        cfg["ide1"] = "local:iso/installation.iso,media=cdrom"
        plan = m.build_plan(10101, cfg, "stopped", "local", mac_factory=mac_factory())
        self.assertEqual(plan["ide_slot"], "ide3")
        self.assertEqual(plan["new_config"]["boot"], "order=ide3")
        self.assertEqual(plan["original_config"], cfg)
        self.assertEqual(str(plan["protection"]), "1")
        self.assertNotIn("protection", plan["new_config"])
        self.assertNotIn("scsi0", plan["new_config"])
        self.assertNotIn("sata0", plan["new_config"])
        self.assertEqual(int(plan["new_config"]["memory"]), 4096)
        self.assertEqual(int(plan["new_config"]["cores"]), 2)
        self.assertEqual(str(plan["new_config"]["agent"]), "0")

    def test_plan_refuses_non_isp_vm(self):
        cfg = config_a()
        cfg["name"] = "HQ-SRV"
        with self.assertRaises(m.Error):
            m.build_plan(10103, cfg, "stopped", "local", mac_factory=mac_factory())

    def test_plan_refuses_locked_vm(self):
        cfg = config_a()
        cfg["lock"] = "snapshot"
        with self.assertRaises(m.Error):
            m.build_plan(10101, cfg, "stopped", "local", mac_factory=mac_factory())

    def test_plan_refuses_when_all_ide_slots_are_occupied(self):
        cfg = config_a()
        for n in range(4):
            cfg["ide%d" % n] = "none,media=cdrom"
        with self.assertRaises(m.Error):
            m.build_plan(10101, cfg, "stopped", "local", mac_factory=mac_factory())

    def test_old_disks_must_remain_on_original_slots_and_same_volumes(self):
        before = config_a()
        good = copy.deepcopy(before)
        good["ide0"] = "local:10101/vm-10101-disk-2.qcow2,size=6G"
        self.assertIsNone(m.verify_old_disks(before, good))
        for key in ("scsi0", "sata0"):
            with self.subTest(key=key, change="missing"):
                bad = copy.deepcopy(good)
                del bad[key]
                with self.assertRaises(m.Error):
                    m.verify_old_disks(before, bad)
            with self.subTest(key=key, change="replaced"):
                bad = copy.deepcopy(good)
                bad[key] = "local:10101/not-the-original.qcow2,size=20G"
                with self.assertRaises(m.Error):
                    m.verify_old_disks(before, bad)



    def test_explicit_mapping_outside_supported_indices_is_rejected(self):
        cfg = config_a()
        cfg["net4"] = cfg.pop("net0")
        with self.assertRaises(m.Error):
            m.build_plan(10101, cfg, "stopped", "local", mac_factory=mac_factory(),
                         override={"wan": "net4", "hq": "net1", "br": "net2"})

class FakePVE:
    """In-memory PVE boundary. Any unrecognised command fails closed."""
    def __init__(self, cfg, config_dir, status="stopped"):
        import json
        self.cfg = copy.deepcopy(cfg)
        self.config_dir = Path(config_dir)
        self.power = status
        self.calls = []
        self.ha = []
        self.replication = []
        self.pending_rows = []
        self.storage_avail = 10**12
        self.fail_shutdown = False
        self.fail_import = False
        self.import_creates_volume_before_failure = True
        self.import_count = 0
        self.snapshot_tail = "\n[Start]\nname: ISP\nscsi0: local:10101/vm-10101-disk-0.qcow2,size=20G\n"
        self.sync_file()

    def sync_file(self):
        self.config_dir.mkdir(parents=True, exist_ok=True)
        raw = "\n".join("%s: %s" % (key, value) for key, value in self.cfg.items()) + "\n"
        (self.config_dir / "10101.conf").write_text(raw + self.snapshot_tail, encoding="utf-8")

    def count(self, *prefix):
        return sum(tuple(call[:len(prefix)]) == tuple(prefix) for call in self.calls)

    def __call__(self, *args, **kwargs):
        import json
        import socket
        args = tuple(str(arg) for arg in args)
        self.calls.append(args)
        if args[:2] == ("qm", "config"):
            return "\n".join("%s: %s" % item for item in self.cfg.items()) + "\n"
        if args[:2] == ("qm", "status"):
            return "status: " + self.power + "\n"
        if args[:2] == ("qm", "shutdown"):
            if self.fail_shutdown:
                raise m.Error("mock: graceful shutdown failed")
            self.power = "stopped"
            return ""
        if args[:2] in (("qm", "importdisk"), ("qm", "disk")):
            self.import_count += 1
            if not self.fail_import or self.import_creates_volume_before_failure:
                self.cfg["unused0"] = "local:10101/vm-10101-disk-9.qcow2"
                self.sync_file()
            if self.fail_import:
                raise m.Error("mock: import result lost")
            return "Successfully imported disk as 'unused0:local:10101/vm-10101-disk-9.qcow2'\n"
        if args[:2] == ("qm", "set"):
            self._set(args[3:])
            self.sync_file()
            return ""
        if args[:2] == ("qm", "pending"):
            return ""
        if args[:2] == ("pvesh", "get"):
            endpoint = args[2]
            if endpoint.endswith("/qemu/10101/pending"):
                return json.dumps(self.pending_rows)
            if endpoint == "/cluster/ha/resources":
                return json.dumps(self.ha)
            if endpoint == "/cluster/replication":
                return json.dumps(self.replication)
            if endpoint == "/cluster/resources":
                return json.dumps([{"vmid": 10101, "name": self.cfg["name"], "node": socket.gethostname().split(".")[0], "type": "qemu", "pool": "DE_09.02.06-2025_stand_A-1"}])
            if endpoint == "/storage/local":
                return json.dumps({"storage": "local", "type": "dir", "content": "images", "path": "/var/lib/vz"})
            if endpoint.endswith("/storage/local/status"):
                return json.dumps({"active": 1, "enabled": 1, "avail": self.storage_avail, "total": 2 * 10**12, "used": 10**12, "type": "dir", "content": "images"})
            if endpoint.endswith("/storage"):
                return json.dumps([{"storage": "local", "type": "dir", "active": 1, "enabled": 1, "avail": 10**12, "content": "images"}])
        if args[:2] == ("qemu-img", "info"):
            return json.dumps({"format": "qcow2", "virtual-size": 6 * 1024**3})
        if args[:2] == ("qemu-img", "check"):
            return ""
        raise AssertionError("Unexpected external command: %r" % (args,))

    def _set(self, args):
        iterator = iter(args)
        for option in iterator:
            if not option.startswith("--"):
                raise AssertionError("Unrecognised qm set option: " + option)
            key = option[2:]
            value = next(iterator)
            if key == "delete":
                for item in value.split(","):
                    if item == "protection" or item.startswith(("ide", "scsi", "sata", "virtio", "unused")):
                        raise AssertionError("Forbidden disk/protection deletion: " + item)
                    self.cfg.pop(item, None)
            else:
                if key == "protection" and value != "1":
                    raise AssertionError("Protection must never be disabled")
                self.cfg[key] = value
                if key.startswith(("ide", "scsi", "sata", "virtio")):
                    volume = value.split(",")[0]
                    for unused in list(self.cfg):
                        if unused.startswith("unused") and self.cfg[unused].split(",")[0] == volume:
                            del self.cfg[unused]

class MigrationBehaviorTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.fake = FakePVE(config_a(), self.base / "qemu")
        self.migrator = m.Migrator(runner=self.fake, work=self.base / "work", config_dir=self.base / "qemu")
        self.image = self.base / "EcoRouter.qcow2"
        self.image.write_bytes(b"synthetic-image-only-used-with-fake-runner")
        self.image_info = {"format": "qcow2", "virtual-size": 6 * 1024**3}
        self.storage = {"storage": "local", "type": "dir", "avail": 10**12}
        self.plan = m.build_plan(10101, self.fake.cfg, "stopped", self.storage, mac_factory=mac_factory())

    def apply(self):
        return self.migrator.apply(self.plan, self.image, self.image_info)

    def assert_safe_original_disks(self):
        m.verify_old_disks(self.plan["original_config"], self.fake.cfg)
        self.assertEqual(str(self.fake.cfg["protection"]), "1")

    def test_apply_changes_only_isp_hardware_and_retains_old_attached_disks(self):
        state = self.apply()
        self.assertEqual(state["stage"], "complete")
        self.assert_safe_original_disks()
        self.assertEqual(self.fake.import_count, 1)
        self.assertEqual(self.fake.power, "stopped")
        self.assertEqual(self.fake.cfg["boot"], "order=" + self.plan["ide_slot"])
        self.assertEqual(set(key for key in self.fake.cfg if key.startswith("net")), {"net0", "net1", "net2", "net3"})
        self.assertEqual((self.base / "qemu" / "10101.conf").read_text(encoding="utf-8").split("[Start]", 1)[1], self.fake.snapshot_tail.split("[Start]", 1)[1])
        for call in self.fake.calls:
            if call[:2] in (("qm", "config"), ("qm", "status"), ("qm", "set"), ("qm", "shutdown"), ("qm", "importdisk")):
                self.assertEqual(call[2], "10101", "no other VM may be modified")

    def test_repeated_apply_is_idempotent(self):
        first = self.apply()
        mutations_before = self.fake.count("qm", "set")
        second = self.apply()
        self.assertEqual(first["stage"], "complete")
        self.assertEqual(second["stage"], "complete")
        self.assertEqual(self.fake.import_count, 1)
        self.assertEqual(self.fake.count("qm", "set"), mutations_before)
        self.assert_safe_original_disks()

    def test_drift_since_plan_aborts_before_shutdown_or_import(self):
        self.fake.cfg["memory"] = "1024"
        self.fake.sync_file()
        with self.assertRaises(m.Error):
            self.apply()
        self.assertEqual(self.fake.import_count, 0)
        self.assertEqual(self.fake.count("qm", "set"), 0)
        self.assertEqual(self.fake.count("qm", "shutdown"), 0)

    def test_failed_shutdown_does_not_import_or_modify_configuration(self):
        self.fake.power = "running"
        self.plan = m.build_plan(10101, self.fake.cfg, "running", self.storage, mac_factory=mac_factory())
        self.fake.fail_shutdown = True
        with self.assertRaises(m.Error):
            self.apply()
        self.assertEqual(self.fake.import_count, 0)
        self.assertEqual(self.fake.count("qm", "set"), 0)
        self.assertEqual(self.fake.cfg, self.plan["original_config"])

    def test_unknown_import_outcome_never_triggers_second_import(self):
        self.fake.fail_import = True
        with self.assertRaises(m.Error):
            self.apply()
        try:
            self.apply()
        except m.Error:
            pass
        self.assertEqual(self.fake.import_count, 1)
        self.assert_safe_original_disks()

    def test_import_without_observable_result_is_not_retried(self):
        self.fake.fail_import = True
        self.fake.import_creates_volume_before_failure = False
        with self.assertRaises(m.Error):
            self.apply()
        with self.assertRaises(m.Error):
            self.apply()
        self.assertEqual(self.fake.import_count, 1)
        self.assert_safe_original_disks()

    def test_rollback_restores_original_boot_networks_and_hardware_without_disk_deletion(self):
        self.apply()
        imported_volume = self.fake.cfg[self.plan["ide_slot"]]
        state = self.migrator.rollback(10101)
        self.assertEqual(state["stage"], "rolled_back")
        original = self.plan["original_config"]
        for key in ("boot", "cpu", "cores", "memory", "machine", "agent", "serial0", "tablet", "net0", "net1", "net2"):
            self.assertEqual(self.fake.cfg.get(key), original.get(key), key)
        self.assertNotIn("net3", self.fake.cfg)
        self.assertEqual(self.fake.cfg[self.plan["ide_slot"]], imported_volume)
        self.assert_safe_original_disks()

    def test_verify_applied_detects_changed_hardware_or_old_disk(self):
        state = self.apply()
        for key, value in (("memory", "512"), ("scsi0", "local:10101/wrong.qcow2,size=20G"), ("protection", "0")):
            bad = copy.deepcopy(self.fake.cfg)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(m.Error):
                m.verify_applied(state, bad)

    def test_preflight_refuses_ha_managed_isp(self):
        self.fake.ha = [{"sid": "vm:10101", "state": "started"}]
        with self.assertRaises(m.Error):
            self.migrator.preflight(10101, storage="local")
        self.assertEqual(self.fake.import_count, 0)
        self.assertEqual(self.fake.count("qm", "set"), 0)

    def test_preflight_refuses_replicated_isp(self):
        self.fake.replication = [{"guest": 10101, "id": "10101-0"}]
        with self.assertRaises(m.Error):
            self.migrator.preflight(10101, storage="local")
        self.assertEqual(self.fake.import_count, 0)
        self.assertEqual(self.fake.count("qm", "set"), 0)


    def test_semantic_nic_canonicalization_is_accepted(self):
        state = self.apply()
        cfg = copy.deepcopy(self.fake.cfg)
        for key in ("net0", "net1", "net2", "net3"):
            parts = cfg[key].split(",")
            cfg[key] = ",".join([parts[0].lower()] + list(reversed(parts[1:])))
        self.assertIsNone(m.verify_applied(state, cfg))

    def test_unknown_saved_stage_aborts_before_mutation(self):
        self.migrator.save(dict(self.plan, version=1, stage="unknown-stage"))
        with self.assertRaises(m.Error):
            self.apply()
        self.assertEqual(self.fake.import_count, 0)
        self.assertEqual(self.fake.count("qm", "set"), 0)
        self.assertEqual(self.fake.count("qm", "shutdown"), 0)

    def test_resume_with_different_image_metadata_aborts_before_import(self):
        self.fake.power = "running"
        self.plan = m.build_plan(10101, self.fake.cfg, "running", self.storage, mac_factory=mac_factory())
        self.fake.fail_shutdown = True
        with self.assertRaises(m.Error):
            self.apply()
        shutdowns = self.fake.count("qm", "shutdown")
        self.fake.fail_shutdown = False
        changed_image = dict(self.image_info, sha256="f" * 64)
        with self.assertRaises(m.Error):
            self.migrator.apply(self.plan, self.image, changed_image)
        self.assertEqual(self.fake.import_count, 0)
        self.assertEqual(self.fake.count("qm", "set"), 0)
        self.assertEqual(self.fake.count("qm", "shutdown"), shutdowns)


    def test_pending_changes_abort_before_shutdown_or_import(self):
        self.fake.power = "running"
        self.fake.pending_rows = [{"key": "memory", "value": 512, "pending": 1024}]
        with self.assertRaises(m.Error):
            self.apply()
        self.assertEqual(self.fake.count("qm", "shutdown"), 0)
        self.assertEqual(self.fake.import_count, 0)
        self.assertEqual(self.fake.count("qm", "set"), 0)

    def test_existing_other_vm_mac_collision_aborts_before_import(self):
        duplicate_mac = nic_options(self.plan["new_config"]["net1"])["vmxnet3"]
        other = self.base / "qemu" / "10102.conf"
        other.write_text("name: HQ-RTR\nnet0: vmxnet3=" + duplicate_mac + ",bridge=vmbr0\n", encoding="utf-8")
        with self.assertRaises(m.Error):
            self.apply()
        self.assertEqual(self.fake.import_count, 0)
        self.assertEqual(self.fake.count("qm", "set"), 0)
        self.assert_safe_original_disks()

    def test_storage_capacity_is_refreshed_before_import(self):
        self.fake.storage_avail = 0
        with self.assertRaises(m.Error):
            self.apply()
        self.assertEqual(self.fake.import_count, 0)
        self.assertEqual(self.fake.count("qm", "set"), 0)


    def prepare_saved_state_before_import(self):
        self.fake.power = "running"
        self.plan = m.build_plan(10101, self.fake.cfg, "running", self.storage, mac_factory=mac_factory())
        self.fake.fail_shutdown = True
        with self.assertRaises(m.Error):
            self.apply()
        self.fake.fail_shutdown = False
        self.fake.calls.clear()
        return self.migrator.load(10101)

    def assert_no_vm_mutations(self):
        self.assertEqual(self.fake.count("qm", "shutdown"), 0)
        self.assertEqual(self.fake.count("qm", "importdisk"), 0)
        self.assertEqual(self.fake.count("qm", "set"), 0)

    def test_tampered_state_cannot_disable_protection(self):
        state = self.prepare_saved_state_before_import()
        state["new_config"]["protection"] = "0"
        self.migrator.save(state)
        with self.assertRaises(m.Error):
            self.apply()
        self.assert_no_vm_mutations()
        self.assert_safe_original_disks()

    def test_tampered_state_cannot_request_disk_deletion(self):
        state = self.prepare_saved_state_before_import()
        state["new_config"]["delete"] = "scsi0"
        self.migrator.save(state)
        with self.assertRaises(m.Error):
            self.apply()
        self.assert_no_vm_mutations()
        self.assert_safe_original_disks()

    def test_tampered_state_cannot_replace_original_disk_slot(self):
        state = self.prepare_saved_state_before_import()
        state["ide_slot"] = "scsi0"
        self.migrator.save(state)
        with self.assertRaises(m.Error):
            self.apply()
        self.assert_no_vm_mutations()
        self.assert_safe_original_disks()

    def test_resume_refuses_current_vm_renamed_non_isp(self):
        self.apply()
        self.fake.cfg["name"] = "HQ-SRV"
        self.fake.sync_file()
        self.fake.calls.clear()
        with self.assertRaises(m.Error):
            self.apply()
        self.assert_no_vm_mutations()

    def test_rollback_refuses_renamed_non_isp_after_import(self):
        self.fake.fail_import = True
        with self.assertRaises(m.Error):
            self.apply()
        self.fake.fail_import = False
        self.fake.cfg["name"] = "HQ-SRV"
        self.fake.power = "running"
        self.fake.sync_file()
        self.fake.calls.clear()
        with self.assertRaises(m.Error):
            self.migrator.rollback(10101)
        self.assert_no_vm_mutations()



if __name__ == "__main__":
    unittest.main()

