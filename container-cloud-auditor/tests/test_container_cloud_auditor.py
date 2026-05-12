import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "container-cloud-auditor" / "scripts" / "analyze_container_cloud.py"


def load_module():
    spec = importlib.util.spec_from_file_location("analyze_container_cloud", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ContainerCloudAuditorTests(unittest.TestCase):
    def test_detects_privileged_compose_service_and_open_k8s_service(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "docker-compose.yml").write_text(
                "services:\n  app:\n    image: demo:latest\n    privileged: true\n",
                encoding="utf-8",
            )
            (root / "service.yaml").write_text(
                "apiVersion: v1\nkind: Service\nspec:\n  type: LoadBalancer\n",
                encoding="utf-8",
            )
            result = module.analyze_path(root)

        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("Privileged container enabled", titles)
        self.assertIn("Externally exposed Kubernetes service", titles)
        self.assertEqual(result["skill"], "container-cloud-auditor")


if __name__ == "__main__":
    unittest.main()
