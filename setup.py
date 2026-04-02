import os
import sys
from setuptools import find_packages, setup
from setuptools.command.sdist import sdist
import shutil

files_copy = {
    "RoutingDirectorMCP.py": "RoutingDirectorMCP.py",
    "utils/lm_calls/paragon/constants.py": "utils/lm_calls/paragon/constants.py",
    "mcp_setup/requirements.txt": "requirements.txt",
    "mcp_setup/setup.py": "setup.py",
    "mcp_setup/README.md": "README.md",
}

version = "v2.8.0"

class CustomBuildCommand(sdist):
    def run(self):
        dist_name = self.distribution.get_fullname()
        for src, dest in files_copy.items():
            dest = os.path.join(dist_name, dest)
            print("----", src, dest)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy(src, dest)
        # Run the standard install
        super().run()

def get_requirements():
    """
    Get list of requirements by reading requirements
    """
    reqs = []
    with open('requirements.txt') as fob:
        for line in fob.readlines():
            line = line.strip()
            if line and \
                    not line.startswith('#') and \
                    not line.startswith('--'):
                reqs.append(line)
    return reqs

setup(
    name="RoutingDirectorMCP",
    version=version,
    package_dir={'': './'},
    install_requires=get_requirements(),
    packages=[
        "utils.lm_calls.tools",
        "utils.lm_calls.tools.assets",
        "utils.lm_calls.tools.ems",
        "utils.lm_calls.tools.observability",
        "utils.lm_calls.tools.network_optimization",
        "utils.lm_calls.tools.trust",
        "utils.lm_calls.tools.active_assurance",
        "utils.lm_calls.tools.routing_intelligence",
        "utils.mcp",
        "utils.lm_calls.connection",
    ],
    cmdclass={
        'sdist': CustomBuildCommand,
    },
    package_data={
        '': ['*.txt'],
    },
)
