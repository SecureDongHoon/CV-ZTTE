// Phase 0 feasibility smoke test: OpenFHE CKKS (spec §36) + genuine multiparty
// threshold decryption (spec §41).
//
//   Part 1 (single party): context/key setup -> encrypt -> homomorphic
//     add & multiply (evaluate) -> decrypt -> check approximate correctness.
//   Part 2 (multiparty): party A KeyGen, party B MultipartyKeyGen extends A's
//     public key to a JOINT public key; encrypt under the joint key; each party
//     produces a partial decryption (Lead/Main); fusion of BOTH partials yields
//     the correct plaintext. This exercises the real OpenFHE threshold API.
//
// Exit nonzero (fail closed) on any deviation. This is a functionality smoke
// only; the "one share cannot decrypt" adversarial assertion belongs to the
// Phase 15/18 suites.
#include "openfhe.h"
#include <iostream>
#include <cmath>
#include <vector>

using namespace lbcrypto;

static int fail(const std::string& m) {
    std::cerr << "[openfhe] FAIL: " << m << std::endl;
    return 1;
}

int main() {
    // --- CKKS context ---
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(2);
    params.SetScalingModSize(50);
    params.SetBatchSize(8);
    // Default security is HEStd_128_classic (documented; demo profile may relax).
    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(MULTIPARTY);
    std::cout << "[openfhe] ring dim = " << cc->GetRingDimension() << std::endl;

    std::vector<double> a = {1.0, 2.0, 3.0, 4.0};
    std::vector<double> b = {10.0, 20.0, 30.0, 40.0};

    // ---------- Part 1: single-party enc/eval/dec ----------
    {
        auto kp = cc->KeyGen();
        cc->EvalMultKeyGen(kp.secretKey);
        auto pa = cc->MakeCKKSPackedPlaintext(a);
        auto pb = cc->MakeCKKSPackedPlaintext(b);
        auto ca = cc->Encrypt(kp.publicKey, pa);
        auto cb = cc->Encrypt(kp.publicKey, pb);

        auto cadd = cc->EvalAdd(ca, cb);
        auto cmul = cc->EvalMult(ca, cb);

        Plaintext radd, rmul;
        cc->Decrypt(kp.secretKey, cadd, &radd);
        cc->Decrypt(kp.secretKey, cmul, &rmul);
        radd->SetLength(4);
        rmul->SetLength(4);

        auto va = radd->GetRealPackedValue();
        auto vm = rmul->GetRealPackedValue();
        for (size_t i = 0; i < 4; ++i) {
            if (std::abs(va[i] - (a[i] + b[i])) > 1e-2) return fail("add mismatch");
            if (std::abs(vm[i] - (a[i] * b[i])) > 1e-1) return fail("mult mismatch");
        }
        std::cout << "[openfhe] PASS single-party enc/add/mult/dec" << std::endl;
    }

    // ---------- Part 2: multiparty (threshold) joint key + fusion decrypt ----------
    {
        auto kp1 = cc->KeyGen();                              // Party A
        auto kp2 = cc->MultipartyKeyGen(kp1.publicKey);      // Party B extends A
        // Joint public key is kp2.publicKey (a function of both secrets).
        auto pa = cc->MakeCKKSPackedPlaintext(a);
        auto pb = cc->MakeCKKSPackedPlaintext(b);
        auto ca = cc->Encrypt(kp2.publicKey, pa);
        auto cb = cc->Encrypt(kp2.publicKey, pb);
        auto csum = cc->EvalAdd(ca, cb);                     // SUM_V1-style aggregate

        // Each party contributes a partial decryption; neither alone suffices.
        auto partialA = cc->MultipartyDecryptLead({csum}, kp1.secretKey);
        auto partialB = cc->MultipartyDecryptMain({csum}, kp2.secretKey);

        Plaintext fused;
        std::vector<Ciphertext<DCRTPoly>> partials = {partialA[0], partialB[0]};
        cc->MultipartyDecryptFusion(partials, &fused);
        fused->SetLength(4);
        auto vf = fused->GetRealPackedValue();
        for (size_t i = 0; i < 4; ++i) {
            if (std::abs(vf[i] - (a[i] + b[i])) > 1e-2) return fail("multiparty fusion mismatch");
        }
        std::cout << "[openfhe] PASS 2-party threshold joint-key + fusion decrypt" << std::endl;
    }

    std::cout << "[openfhe] SMOKE OK (CKKS + multiparty)" << std::endl;
    return 0;
}
