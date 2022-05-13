from binascii import hexlify
from termcolor import colored
from bplib.bp import BpGroup, G2Elem
from numpy.polynomial.polynomial import *
from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
from hashlib import sha256
import numpy as np


# ==================================================
# polynomial utilities
# ==================================================



# ==================================================
# Setup parameters:
# ==================================================

## this class generates bilinear pairing BG

class GenParameters:

    def __init__(self):
        self.e = BpGroup()
        self.g1, self. g2 = self.e.gen1(), self.e.gen2()
        self.Order = self.e.order()

    # getter methods
    def get_e(self):
        return self.e

    def get_Order(self):
        return self.Order

    def get_g1(self):
        return self.g1

    def get_g2(self):
        return self.g2



def ec_sum(list):
    """ sum EC points list """
    ret = list[0]
    for i in range(1, len(list)):
        ret = ret + list[i]
    return ret


def product_GT(list_GT):
    """ pairing product equations of a list """
    ret_GT = list_GT[0]
    for i in range(1, len(list_GT)):
        ret_GT = ret_GT * (list_GT[i])
    return ret_GT

# ==================================================
# Attribute Representation:
# ==================================================

def convert_mess_to_bn(messages):
    if isinstance(messages, set) or isinstance(messages, list)  == False:
        print(colored('message type is not correct', 'green'))
    else:
        try:
            Conver_message = list(map(lambda item: Bn.from_binary(str.encode(item)), messages))
        except:
            print(colored('insert all messages as string', 'green'))
    return Conver_message




# ==================================================
# Trapdoor (pedersen) commitment
# ==================================================
def pedersen_setup(group):
   """ generate an pedersen parameters with a Trapdoor d (only used in POK) """
   g = group.gen1()
   o = group.order()
   group =group
   d = o.random()
   h = d * g
   trapdoor = d
   pp_pedersen = (group, g, o, h)
   return (pp_pedersen, trapdoor)


def pedersen_committ(pp_pedersen, m):
    """ commit/encrypts the values of a message (g^m) """
    (G, g, o, h ) = pp_pedersen
    r = o.random()
    pedersen_commit = r * h + m * g
    pedersen_open = (r, m)
    return (pedersen_commit, pedersen_open)

def pedersen_dec(pp_pedersen, pedersen_open, pedersen_commit):
    """ decrypts/decommit the message """
    (G, g, o, h) = pp_pedersen
    (r, m) = pedersen_open
    c2 = r * h + m * g
    if c2== pedersen_commit:
        return True
    else: return False

