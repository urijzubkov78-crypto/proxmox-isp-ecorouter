import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("resize", Path(__file__).resolve().parents[1] / "resize_isp_memory.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MemoryTests(unittest.TestCase):
    def cfg(self, memory=4096):
        return {"name": "HQ-ISP", "memory": memory, "balloon": 0,
                "protection": 1, "scsi0": "local:old-disk", "net0": "vmxnet3=AA:BB:CC:DD:EE:FF", "digest": "abc"}

    def test_exact_sixteen_targets(self):
        self.assertEqual(m.VMIDS, tuple(10101 + 100 * i for i in range(16)))

    def test_refuses_non_isp_and_unexpected_memory(self):
        for change in ({"name": "HQ-SRV"}, {"memory": 8192}, {"memory": 2048},
                       {"lock": "backup"}, {"balloon": 1024}, {"template": 1}):
            with self.subTest(change=change), self.assertRaises(m.Error):
                m.validate(10101, dict(self.cfg(), **change), [])
        with self.assertRaises(m.Error):
            m.validate(10102, self.cfg(), [])

    def test_pending_memory_is_idempotent_but_other_pending_is_refused(self):
        self.assertFalse(m.validate(10101, self.cfg(),
                         [{"key": "memory", "value": 4096, "pending": 5120}]))
        self.assertFalse(m.validate(10101, self.cfg(5120), []))
        for pending in ([{"key": "net0", "pending": "changed"}],
                        [{"key": "memory", "pending": 6144}],
                        [{"key": "memory", "delete": 1}]):
            with self.subTest(pending=pending), self.assertRaises(m.Error):
                m.validate(10101, self.cfg(), pending)

    def test_missing_target_prevents_gather(self):
        with patch.object(m, "Path") as path, patch.object(m, "api", return_value=[]):
            path.return_value.resolve.return_value.name = "pve"
            with self.assertRaises(m.Error):
                m.gather()

    def test_all_targets_receive_only_memory_without_stop_delete_or_protection(self):
        plans = [{"vmid": v, "path": f"/nodes/pve/qemu/{v}", "config": self.cfg(),
                  "pending": [], "change": True} for v in m.VMIDS]
        queued, commands = set(), []
        def api(path, *args):
            vmid = int(path.split("/")[4])
            if path.endswith("/pending"):
                return [{"key": "memory", "value": 4096, "pending": 5120}] if vmid in queued else []
            cfg = self.cfg()
            if not args and vmid in queued:
                cfg["memory"] = 5120
            return cfg
        def run(*args):
            commands.append(args)
            queued.add(int(args[2]))
            return ""
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, "Path", side_effect=lambda _: Path(tmp)), \
             patch.object(m, "api", side_effect=api), patch.object(m, "run", side_effect=run):
            m.apply(copy.deepcopy(plans))
            self.assertEqual(len(list(Path(tmp).glob("*.json"))), 1)
        self.assertEqual(commands, [("qm", "set", str(v), "--memory", "5120", "--digest", "abc")
                                    for v in m.VMIDS])

    def test_drift_aborts_before_any_write(self):
        plan = {"vmid": 10101, "path": "/nodes/pve/qemu/10101", "config": self.cfg(),
                "pending": [], "change": True}
        def api(path, *args):
            return [] if path.endswith("/pending") else dict(self.cfg(), name="HQ-SRV")
        with patch.object(m, "api", side_effect=api), patch.object(m, "run") as run:
            with self.assertRaises(m.Error):
                m.apply([plan])
            run.assert_not_called()

    def test_already_configured_skips_set(self):
        plan = {"vmid": 10101, "path": "/nodes/pve/qemu/10101", "config": self.cfg(5120),
                "pending": [], "change": False}
        def api(path, *args):
            return [] if path.endswith("/pending") else self.cfg(5120)
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, "Path", side_effect=lambda _: Path(tmp)), \
             patch.object(m, "api", side_effect=api), patch.object(m, "run") as run:
            m.apply([plan])
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
