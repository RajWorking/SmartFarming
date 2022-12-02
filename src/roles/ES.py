import random
from fastecdsa import keys, curve

from src.config import *
from src.utils import *


class ES:
    """
    This class contains code for Edge Server
    """

    def __init__(self, id, keypair):
        """
        id: (RID, TID)
        keypair: (priv_key, pub_key)
        gateways: [RIDg]
        """
        self.RID, self.TID, self.gateways = id
        self.priv_key, self.pub_key = keypair
