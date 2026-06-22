import pathlib
import sys

_here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_here))                     # for _mock_bridge
sys.path.insert(0, str(_here.parent / "src"))      # for espilon_probe (editable install also works)
