from bplib.bp import BpGroup
from core.dac import dac_setup, dac_user_keygen, dac_nym_gen, dac_root_cred, delegator, delegatee, proof_attributes, \
    verify_proof
from core.zkp import ZKP_Schnorr_FS
import pytest


message1_str = ["age = 30", "name = Alice ", "driver license = 12"]
message2_str = ["genther = male", "componey = XX ", "driver license type = B"]
Attr_vector=[message1_str, message2_str]
SubList1_str = ["age = 30", "name = Alice "]
SubList2_str = ["genther = male", "componey = XX "]

def setup_module(module):
    print("__________Setup___Test DAC ________")
    global EQ_Sign
    global pp
    global pp_dac, sk_ca
    global BG
    BG = BpGroup()
    nizkp = ZKP_Schnorr_FS(BG)
    (pp_dac, sk_ca, proof_vk, vk_stm, proof_alpha, alpha_stm) = dac_setup(BG,5, 10)
    (pp_sign, sign_scheme, sc_scheme, vk_ca, zkp_scheme, pp_zkp, pp_nizkp) = pp_dac

    assert (nizkp.non_interact_verify(pp_nizkp, vk_stm, proof_vk))
    assert (nizkp.non_interact_verify(pp_nizkp, alpha_stm, proof_alpha))

def test_root_cred():
    (pp_sign, sign_scheme, sc_scheme, vk_ca, zkp_scheme, pp_zkp, pp_nizkp) = pp_dac
    (G, g, o, h) = pp_zkp

    (usk, upk) = dac_user_keygen(pp_dac)
    #(psym, psi, chi) = dac_psyngen(pp_dac, upk)

    # create a proof for nym (challenge is created by verifier)
    (pedersen_commit, pedersen_open) = zkp_scheme.announce()
    (open_randomness, announce_randomnes, announce_element) = pedersen_open
    state = ['schnorr', g, h, pedersen_commit.__hash__()]
    challenge = zkp_scheme.challenge(state)
    response = zkp_scheme.response(challenge, announce_randomnes, stm=upk, secret_wit=usk)
    proof_nym_u = (challenge, pedersen_open, pedersen_commit, upk, response)

    # create a root credential
    cred = dac_root_cred(pp_dac, Attr_vector=[message1_str, message2_str], sk = sk_ca, nym_u = upk, k_prime = 3, proof_nym_u = proof_nym_u)
    (sigma, update_key, commitment_vector, opening_vector) = cred

    # check the correctness of root credential
    assert (sign_scheme.verify(pp_sign, vk_ca, upk, commitment_vector, sigma)), ValueError("signature/credential is not correct")


def test_issuing():
    (pp_sign, sign_scheme, sc_scheme, vk_ca, zkp_scheme, pp_zkp, pp_nizkp) = pp_dac
    (G, g, o, h) = pp_zkp
    (usk, upk) = dac_user_keygen(pp_dac)

    # create a proof of nym_u and root credential
    (pedersen_commit, pedersen_open) = zkp_scheme.announce()
    (open_randomness, announce_randomnes, announce_element) = pedersen_open
    state = ['schnorr', g, h, pedersen_commit.__hash__()]
    challenge = zkp_scheme.challenge(state)
    response = zkp_scheme.response(challenge, announce_randomnes, stm=upk, secret_wit=usk)
    proof_nym_u = (challenge, pedersen_open, pedersen_commit, upk, response)
    cred = dac_root_cred(pp_dac, Attr_vector=[message1_str, message2_str], sk = sk_ca, nym_u = upk, k_prime = 3, proof_nym_u = proof_nym_u)

    ## issuing/delegating a credential of user U to a user R ------------------------------------------------
    sub_mess_str = ["Insurance = 2 ", "Car type = BMW"]
    Attr_vector.append(sub_mess_str)

    # generate key pair of user R
    (usk_R, upk_R) = dac_user_keygen(pp_dac)

    # generate a nym for the upk_R and corresoing secret key foir nym
    (nym_R, psi, chi) = dac_nym_gen(pp_dac, upk_R)
    usk_R= psi*(usk_R + chi)

    # create a proof for upk_R or nym_R
    (pedersen_commit, pedersen_open) = zkp_scheme.announce()
    (open_randomness, announce_randomnes, announce_element) = pedersen_open
    state = ['schnorr', g, h, pedersen_commit.__hash__()]
    challenge = zkp_scheme.challenge(state)
    response = zkp_scheme.response(challenge, announce_randomnes, stm=nym_R, secret_wit= usk_R)
    proof_nym_R = (challenge, pedersen_open, pedersen_commit, nym_R, response)

    # create a credential for new nym
    cred_R_U = delegator(pp_dac, cred, sub_mess_str, l=3, sk_u=usk, proof_nym=proof_nym_R)
    (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi) = delegatee(pp_dac, cred_R_U, sub_mess_str, usk_R, nym_R)

    # check the correctness of credential
    assert (sign_scheme.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, sigma_prime)), ValueError("signature/credential is not correct")


def test_proof_cred():
    (pp_sign, sign_scheme, sc_scheme, vk_ca, zkp_scheme, pp_zkp, pp_nizkp) = pp_dac
    (G, g, o, h) = pp_zkp
    (usk, upk) = dac_user_keygen(pp_dac)

    # create a proof
    (pedersen_commit, pedersen_open) = zkp_scheme.announce()
    (open_randomness, announce_randomnes, announce_element) = pedersen_open
    state = ['schnorr', g, h, pedersen_commit.__hash__()]
    challenge = zkp_scheme.challenge(state)
    response = zkp_scheme.response(challenge, announce_randomnes, stm=upk, secret_wit=usk)
    proof_nym_u = (challenge, pedersen_open, pedersen_commit, upk, response)

    # generate a credential
    cred = dac_root_cred(pp_dac, Attr_vector=Attr_vector, sk = sk_ca, nym_u = upk, k_prime = None, proof_nym_u = proof_nym_u)
    # prepare a proof
    D = [SubList1_str, SubList2_str]
    proof = proof_attributes(pp_dac, nym_R = upk, aux_R = usk, cred_R = cred, Attr=Attr_vector, D = D)

    # check a proof
    assert (verify_proof(pp_dac, proof, D))

