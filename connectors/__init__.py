__all__ = ['SCVMM']

import config
import connectors.SCVMM
from connectors.Connector import Connector
from typing import Mapping

modules: Mapping[str, Connector] = {
	"scvmm": connectors.SCVMM.SCVMMConnector(config.SCVMM_URL)
}
