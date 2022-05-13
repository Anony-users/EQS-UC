"""
This is implementation of delegatable anonymous credential using SPSQE-UC signatures and set commitment.
See  the following for the details
- (Submitted) Constant-Size, Efficient, Delegatable Ano nymous Credentials through SPSEQ-UC, by Mir et al.,
@Author: ...
"""

from core.set_commit import CrossSetCommitment
from core.spseq_uc import EQC_Sign
from core.zkp import ZKP_Schnorr_FS, Damgard_Transfor


def dac_setup(group,t, l_message):
    """
    :param group: bilinear group BpGroup
    :param t: max cardinality
    :return: public parameters including sign and set comment and zkp, and onject of SC and sign anf zkp schemes
    """
    # create objects of underlines schemes
    sign_scheme = EQC_Sign(group,t)
    sc_scheme = CrossSetCommitment(group,t)
    nizkp = ZKP_Schnorr_FS(group)
    zkp_scheme = Damgard_Transfor(group)

    # create public parameters and signing pair keys
    pp_sign, alpha = sign_scheme.setup()
    (sk_ca, vk_ca) = sign_scheme.sign_keygen(pp_sign, l_message = l_message)
    pp_zkp = zkp_scheme.setup(group)
    pp_nizkp = nizkp.setup()
    (G, g, o) = pp_nizkp

    "create proof of vk and alpha trpdoor -> vk_stm and alpha_stm are the statements need to be proved "
    X_0 = vk_ca.pop(0)
    vk_stm = vk_ca.copy()
    proof_vk = nizkp.non_interact_prove(pp_nizkp, stm=vk_stm, secret_wit=sk_ca)
    alpha_stm  = alpha * g
    proof_alpha = nizkp.non_interact_prove(pp_nizkp, stm=alpha_stm, secret_wit=alpha)
    vk_ca.insert(0, X_0)
    pp_dac = (pp_sign, sign_scheme, sc_scheme, vk_ca, zkp_scheme, pp_zkp, pp_nizkp)
    return (pp_dac, sk_ca, proof_vk, vk_stm, proof_alpha, alpha_stm)


def dac_user_keygen(pp_dac):
    """
    :param pp_dac:  public parameters
    :return: user key pair
    """
    (pp_sign, sign_obj, sc_obj, vk, zkp_obj, pp_zkp, pp_nizkp) = pp_dac
    (usk, upk) = sign_obj.user_keygen(pp_sign)
    return (usk, upk)

def dac_nym_gen(pp_dac, upk):
    """
    :param pp_dac:  public parameters
    :param upk: user public key ( or pseudonym)
    :return: a new pseudonym and auxiliary information
    """
    (pp_sign, sign_obj, sc_obj, vk, zkp_obj, pp_zkp, pp_nizkp) = pp_dac
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign

    psi, chi = order.random(), order.random()
    nym = sign_obj.rndmz_pk(pp_sign, upk, psi, chi)
    return (nym, psi, chi)

def dac_root_cred(pp_dac, Attr_vector, sk, nym_u, k_prime, proof_nym_u):
    """
    :param pp_dac: public parameters
    :param Attr_vector: attribute vector
    :param sk: signing key sk_ca in papre
    :param nym_u: pseudonym of user who gets credential
    :param k_prime:  index need for update key uk
    :param proof_nym_u: proof of pseudonym that  is coorect
    :return: a root credential
    """
    (pp_sign, sign_obj, sc_obj, vk, zkp_obj, pp_zkp, pp_nizkp) = pp_dac
    challenge, pedersen_open, pedersen_commit, stm, response = proof_nym_u

    if zkp_obj.verify(challenge, pedersen_open, pedersen_commit, stm, response) == True:
        if k_prime!= None:
            (sigma, update_key, commitment_vector, opening_vector) = sign_obj.sign(pp_sign, nym_u, sk, Attr_vector,k_prime)
            cred = (sigma, update_key, commitment_vector, opening_vector)
            return cred
        else:
            (sigma, commitment_vector, opening_vector) = sign_obj.sign(pp_sign, nym_u, sk, Attr_vector)
            cred = (sigma, commitment_vector, opening_vector)
            return cred
    else:
        raise ValueError ("proof of nym is not valid ")

def proof_attributes(pp_dac, nym_R, aux_R, cred_R, Attr, D):
    """
    :param pp_dac:public parameters
    :param nym_R: pseudonym of user who wants to prove credentials to verifiers
    :param aux_R: auxiliary information related to pseudonym
    :param cred_R: credential of pseudonym R that is needed to prove
    :param Attr: attributes vector in credential R
    :param D: subset of attributes (selective disclose)
    :return: a proof of credential that is a credential P
    """
    (pp_sign, sign_obj, sc_obj, vk, zkp_obj, pp_zkp, pp_nizkp) = pp_dac
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign
    (G, g, o, h) = pp_zkp

    mu, psi = order.random(), order.random()
    (sigma, commitment_vector, opening_vector) = cred_R
    (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi) = sign_obj.change_rep\
        (pp_sign, vk, nym_R, commitment_vector, opening_vector, sigma, mu, psi, B=False, update_key=None)

    # create an announcement
    (pedersen_commit, pedersen_open) = zkp_obj.announce()
    (open_randomness, announce_randomnes, announce_element) = pedersen_open

    # get s challenge
    state = ['schnorr', g, h, pedersen_commit.__hash__()]
    challenge = zkp_obj.challenge(state)

    # prover creates a respoonse (or proof)
    response = zkp_obj.response(challenge, announce_randomnes, stm=nym_P,
                                   secret_wit= (aux_R +  chi) *psi)

    proof_nym_p = (challenge, pedersen_open, pedersen_commit, nym_P, response)

    Witness = [sc_obj.open_subset(pp_sign, Attr[i], rndmz_opening_vector[i], D[i]) for i in range(len(D))]
    list_C = [rndmz_commitment_vector[i] for i in range(len(D))]

    Witness_pi = sc_obj.aggregate_cross(Witness,list_C)
    proof = (sigma_prime, rndmz_commitment_vector, nym_P, Witness_pi, proof_nym_p)
    return proof

def verify_proof(pp_dac, proof, D):
    """
    :param pp_dac:public parameters
    :param proof: a proof of credential satisfied subset attributes D
    :param D: subset attributes
    :return: 0/1
    """
    (pp_sign, sign_obj, sc_obj, vk, zkp_obj, pp_zkp, pp_nizkp) = pp_dac

    (sigma_prime, rndmz_commitment_vector, nym_P, Witness_pi, proof_nym_p) = proof
    list_C = [rndmz_commitment_vector[i] for i in range(len(D))]
    (challenge, pedersen_open, pedersen_commit, nym_P, response) = proof_nym_p

    if sc_obj.verify_cross(pp_sign, list_C, D, Witness_pi) and \
            zkp_obj.verify(challenge, pedersen_open, pedersen_commit, nym_P, response) and sign_obj.verify(pp_sign, vk, nym_P, rndmz_commitment_vector,
                                                                        sigma_prime) == True:
        return True
    else:
        return False


"""
This is the delgation phase or the issuing credential protocol in the paper between delegator and delegatee 
"""

def delegator(pp_dac, cred_u, A_l, l, sk_u, proof_nym):
    """
    :param pp_dac: public parameters
    :param cred_u: delegator u credential
    :param A_l: additional attributes set can be added into credential
    :param l: index of message set
    :param sk_u: secret key of credential holder
    :param proof_nym: check proof of nym
    :return: delegatable credential cred_R for a user R
    """

    (pp_sign, sign_obj, sc_obj, vk, zkp_obj, pp_zkp, pp_nizkp) = pp_dac
    challenge, pedersen_open, pedersen_commit, stm, response = proof_nym

    # check the proof
    assert zkp_obj.verify(challenge, pedersen_open, pedersen_commit, stm, response)

    (sigma, update_key, commitment_vector, opening_vector) = cred_u
    (Sigma_tilde, Commitment_L, Opening_L, Commitment_vector_new, Opening_vector_new) =sign_obj.change_rel(pp_sign, A_l, l, sigma,
    commitment_vector, opening_vector,update_key)

    sigma_orpha = sign_obj.send_convert_sig(vk, sk_u, Sigma_tilde)
    cred_R = (sigma_orpha, Commitment_L, Opening_L, Commitment_vector_new, Opening_vector_new)
    return cred_R


def delegatee(pp_dac, cred, A_l, sk_R, nym_R):
    """
    :param pp_dac: public parameters
    :param cred: credential got from delegator
    :param A_l: additional attributes set can be added into credential
    :param sk_R: secret key of delegatee R
    :param nym_R: c of delegatee nym_R
    :return: a final credential R for nym_R
    """
    (pp_sign, sign_obj, sc_obj, vk, zkp_obj, pp_zkp, pp_nizkp) = pp_dac
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign
    (sigma_orpha, Commitment_L, Opening_L, Commitment_vector_new, Opening_vector_new) = cred
    sigma_change = sign_obj.receive_convert_sig(vk, sk_R, sigma_orpha)

    mu, psi = order.random(), order.random()
    (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi) = sign_obj.change_rep \
        (pp_sign, vk, nym_R, Commitment_vector_new, Opening_vector_new, sigma_change, mu, psi, B=False, update_key=None)
    cred_R = (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi)
    return cred_R


