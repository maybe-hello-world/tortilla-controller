__all__ = ['SCVMM']

from controller import config
from controller.connectors.SCVMM import SCVMMConnector
from controller.connectors.Connector import Connector
from typing import Mapping

modules: Mapping[str, Connector] = {
    "scvmm": SCVMMConnector(config.SCVMM_URL)
}
