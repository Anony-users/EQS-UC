from bplib.bp import BpGroup
from core.set_commit import SetCommitment, CrossSetCommitment
import pytest

set_str = ["age = 30", "name = Alice ", "driver license = 12"]
set_str2 = ["Gender = male", "componey = XX ", "driver license type = B"]

subset_str_1 = ["age = 30", "name = Alice "]
subset_str_2 = ["Gender = male", "componey = XX "]


def setup_module(module):
    print("__________Setup__test set commitment___________")
    global sc_obj
    global pp
    global cssc_obj
    BG = BpGroup()
    sc_obj = SetCommitment(BG, 5)
    cssc_obj = CrossSetCommitment(BG, 5)
    pp, alpha = sc_obj.setup_create_pp()

def test_commit_and_open():
    (Commitment, O) = sc_obj.commit_set(param_sc=pp, mess_set_str=set_str)
    assert(sc_obj.open_set(pp, Commitment, O, set_str)), ValueError("set is not match with commit and opening info")

def test_open_verify_subset():
    (Commitment, O) = sc_obj.commit_set(param_sc=pp, mess_set_str=set_str)
    witness = sc_obj.open_subset(pp, set_str, O, subset_str_1)
    assert sc_obj.verify_subset(pp, Commitment, subset_str_1, witness), "subset is not match with witness"


def test_aggregate_verify_cross():
    C1, O1 = cssc_obj.commit_set(pp, set_str)
    C2, O2 = cssc_obj.commit_set(pp, set_str2)

    ## create a witness for a subset -> W
    W1 = cssc_obj.open_subset(pp, set_str, O1, subset_str_1)
    W2 = cssc_obj.open_subset(pp, set_str2, O2, subset_str_2)

    ## aggegate all witness for a subset is correct-> proof
    proof = cssc_obj.aggregate_cross(witness_vector=[W1, W2], commit_vector=[C1, C2])

    ## verification aggegated witneesees
    assert( cssc_obj.verify_cross(pp, commit_vector=[C1, C2],
                                  subsets_vector_str=[subset_str_1, subset_str_2], proof=proof)), ValueError("verification aggegated witneesees fails")
