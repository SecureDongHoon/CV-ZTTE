// CV-ZTTE native FHE broker (spec §36, §37, §40).
//
// A narrow, single-purpose C++ executable over OpenFHE CKKS. It performs the
// mathematical FHE operations only — context/key setup, encrypt, evaluate an
// allowlisted program, and decrypt — driven entirely by the CV-ZTTE control
// plane. It makes NO authorization decision: the Python control plane runs
// identity/policy/authorization/containment/token checks and only then invokes
// this binary. The broker never emits plaintext except on an explicit `decrypt`
// command (a separate high-risk action, §42), and it never prints key material.
//
// Crypto parameters come from the FHE Context Registry (§37) via argv — an agent
// cannot supply them. Artifacts are serialized to a context directory; the
// caller (Python) computes and pins content hashes over those bytes (§38).
//
// Commands (argv):
//   gen-context <ctx_dir> <depth> <scale_mod_size> <batch_size> [ring_dim]
//   encrypt     <ctx_dir> <out_ct> <v0,v1,...>
//   evaluate    <ctx_dir> <program> <out_ct> <in_ct...> [--weights w0,w1,...] [--count N]
//   decrypt     <ctx_dir> <in_ct> <length>
//
// Threshold / multiparty commands (spec §41, §42). This is a genuine OpenFHE
// N-of-N interactive protocol: EVERY configured party is required to decrypt.
// It is NOT a t-of-n threshold (see docs/THRESHOLD_FHE.md). No directory ever
// holds a reconstructed full secret key: each party's secret share stays in its
// own <share_dir>; the shared <ctx_dir> holds only public material (context,
// joint public key, joint eval-sum keys).
//   mp-gen-context   <ctx_dir> <depth> <scale_mod_size> <batch_size> [ring_dim]
//   mp-keygen-lead   <ctx_dir> <share_dir> <out_pub> <out_evalsum>
//   mp-keygen-join   <ctx_dir> <share_dir> <prev_pub> <prev_evalsum> <out_pub> <out_evalsum>
//   mp-install-public<ctx_dir> <final_pub> <final_evalsum>
//   mp-decrypt-lead  <ctx_dir> <share_dir> <in_ct> <out_partial>
//   mp-decrypt-main  <ctx_dir> <share_dir> <in_ct> <out_partial>
//   mp-decrypt-fuse  <ctx_dir> <length> <partial...>
//
// Programs (§39): SUM_V1, AVERAGE_V1, WEIGHTED_SCORE_V1.
//
// Output: a single-line JSON object on stdout. Errors: JSON {"error":"..."} on
// stderr + non-zero exit (fail-closed; the control plane maps this to DENY).

#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace lbcrypto;

namespace {

const std::string CTX_FILE = "/context.bin";
const std::string PUB_FILE = "/key-pub.bin";
const std::string SEC_FILE = "/key-sec.bin";
const std::string MULT_FILE = "/eval-mult.bin";
const std::string SUM_FILE = "/eval-sum.bin";
// Per-party secret share file (threshold mode). Lives ONLY in a party's own
// share directory and is never combined or copied into the shared context dir.
const std::string SHARE_FILE = "/share-sec.bin";

[[noreturn]] void fail(const std::string& msg) {
    std::cerr << "{\"error\":\"" << msg << "\"}" << std::endl;
    std::exit(2);
}

std::vector<double> parse_doubles(const std::string& csv) {
    std::vector<double> out;
    std::stringstream ss(csv);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        if (!tok.empty()) out.push_back(std::stod(tok));
    }
    return out;
}

CryptoContext<DCRTPoly> load_context(const std::string& dir) {
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(dir + CTX_FILE, cc, SerType::BINARY))
        fail("failed to load context");
    return cc;
}

template <typename T>
T load(const std::string& path, const std::string& what) {
    T obj;
    if (!Serial::DeserializeFromFile(path, obj, SerType::BINARY))
        fail("failed to load " + what);
    return obj;
}

// ---- commands ------------------------------------------------------------

int gen_context(int argc, char** argv) {
    if (argc < 6) fail("gen-context requires <ctx_dir> <depth> <scale_mod_size> <batch_size> [ring_dim]");
    std::string dir = argv[2];
    uint32_t depth = std::stoul(argv[3]);
    uint32_t scaleMod = std::stoul(argv[4]);
    uint32_t batch = std::stoul(argv[5]);
    uint32_t ring = (argc >= 7) ? std::stoul(argv[6]) : 0;

    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(depth);
    params.SetScalingModSize(scaleMod);
    params.SetBatchSize(batch);
    if (ring > 0) params.SetRingDim(ring);
    params.SetSecurityLevel(HEStd_128_classic);

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    if (!Serial::SerializeToFile(dir + CTX_FILE, cc, SerType::BINARY))
        fail("cannot serialize context");
    if (!Serial::SerializeToFile(dir + PUB_FILE, keys.publicKey, SerType::BINARY))
        fail("cannot serialize public key");
    if (!Serial::SerializeToFile(dir + SEC_FILE, keys.secretKey, SerType::BINARY))
        fail("cannot serialize secret key");

    std::ofstream mult(dir + MULT_FILE, std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalMultKey(mult, SerType::BINARY)) fail("cannot serialize eval-mult key");
    mult.close();
    std::ofstream sum(dir + SUM_FILE, std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalSumKey(sum, SerType::BINARY)) fail("cannot serialize eval-sum key");
    sum.close();

    std::cout << "{\"ring_dimension\":" << cc->GetRingDimension()
              << ",\"batch_size\":" << batch << "}" << std::endl;
    return 0;
}

int encrypt(int argc, char** argv) {
    if (argc < 5) fail("encrypt requires <ctx_dir> <out_ct> <values>");
    std::string dir = argv[2];
    std::string out = argv[3];
    auto values = parse_doubles(argv[4]);
    if (values.empty()) fail("no values to encrypt");

    auto cc = load_context(dir);
    auto pk = load<PublicKey<DCRTPoly>>(dir + PUB_FILE, "public key");
    auto pt = cc->MakeCKKSPackedPlaintext(values);
    auto ct = cc->Encrypt(pk, pt);
    if (!Serial::SerializeToFile(out, ct, SerType::BINARY)) fail("cannot serialize ciphertext");

    std::cout << "{\"slots\":" << values.size() << "}" << std::endl;
    return 0;
}

int evaluate(int argc, char** argv) {
    if (argc < 6) fail("evaluate requires <ctx_dir> <program> <out_ct> <in_ct...>");
    std::string dir = argv[2];
    std::string program = argv[3];
    std::string out = argv[4];

    std::vector<std::string> inputs;
    std::vector<double> weights;
    uint32_t count = 0;
    for (int i = 5; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--weights" && i + 1 < argc) { weights = parse_doubles(argv[++i]); }
        else if (a == "--count" && i + 1 < argc) { count = std::stoul(argv[++i]); }
        else inputs.push_back(a);
    }
    if (inputs.empty()) fail("no input ciphertexts");

    auto cc = load_context(dir);
    // Restore context-level evaluation keys. The eval-mult (relinearization)
    // key is only needed for ciphertext x ciphertext products; none of the
    // allowlisted programs use one (WEIGHTED_SCORE_V1 multiplies by a plaintext
    // weight vector), so it is optional and absent in threshold contexts.
    std::ifstream mult(dir + MULT_FILE, std::ios::in | std::ios::binary);
    if (mult.is_open() && !cc->DeserializeEvalMultKey(mult, SerType::BINARY))
        fail("cannot load eval-mult key");
    std::ifstream sum(dir + SUM_FILE, std::ios::in | std::ios::binary);
    if (!sum.is_open() || !cc->DeserializeEvalSumKey(sum, SerType::BINARY))
        fail("cannot load eval-sum key");

    std::vector<Ciphertext<DCRTPoly>> cts;
    for (auto& p : inputs) cts.push_back(load<Ciphertext<DCRTPoly>>(p, "ciphertext"));

    Ciphertext<DCRTPoly> result;
    uint32_t batch = cc->GetEncodingParams()->GetBatchSize();

    if (program == "SUM_V1") {
        // Sum all elements of the (single) input vector into slot 0.
        result = cc->EvalSum(cts[0], batch);
    } else if (program == "AVERAGE_V1") {
        if (count == 0) fail("AVERAGE_V1 requires --count N (element count)");
        auto s = cc->EvalSum(cts[0], batch);
        result = cc->EvalMult(s, 1.0 / static_cast<double>(count));
    } else if (program == "WEIGHTED_SCORE_V1") {
        if (weights.empty()) fail("WEIGHTED_SCORE_V1 requires --weights");
        auto wpt = cc->MakeCKKSPackedPlaintext(weights);
        auto prod = cc->EvalMult(cts[0], wpt);
        result = cc->EvalSum(prod, batch);
    } else {
        fail("unknown or unsupported program: " + program);
    }

    if (!Serial::SerializeToFile(out, result, SerType::BINARY)) fail("cannot serialize result");
    std::cout << "{\"program\":\"" << program << "\"}" << std::endl;
    return 0;
}

int decrypt(int argc, char** argv) {
    if (argc < 5) fail("decrypt requires <ctx_dir> <in_ct> <length>");
    std::string dir = argv[2];
    std::string in = argv[3];
    uint32_t length = std::stoul(argv[4]);

    auto cc = load_context(dir);
    auto sk = load<PrivateKey<DCRTPoly>>(dir + SEC_FILE, "secret key");
    auto ct = load<Ciphertext<DCRTPoly>>(in, "ciphertext");

    Plaintext pt;
    cc->Decrypt(sk, ct, &pt);
    pt->SetLength(length);
    auto values = pt->GetRealPackedValue();

    std::cout << "{\"values\":[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << values[i];
    }
    std::cout << "]}" << std::endl;
    return 0;
}

// ---- threshold / multiparty (spec §41, §42) -----------------------------
//
// N-of-N interactive protocol. Key generation chains three parties:
//   A: KeyGen                     -> secret share s_a, public key, eval-sum(A)
//   B: MultipartyKeyGen(pub_A)    -> s_b, joint pub(A+B), joint eval-sum(A+B)
//   C: MultipartyKeyGen(pub_AB)   -> s_c, joint pub(A+B+C), joint eval-sum(all)
// Only the joint public key + joint eval-sum keys are installed into the shared
// context; each secret share stays in its own party directory. Decryption needs
// a partial from EVERY party, fused together. No eval-mult key is generated:
// the allowlisted programs never multiply ciphertext by ciphertext.

using EvalSumMap = std::map<uint32_t, EvalKey<DCRTPoly>>;

void save_evalsum_map(const std::string& path, const std::shared_ptr<EvalSumMap>& m) {
    std::ofstream os(path, std::ios::out | std::ios::binary);
    if (!os.is_open()) fail("cannot open eval-sum map for write");
    Serial::Serialize(*m, os, SerType::BINARY);
    os.close();
}

std::shared_ptr<EvalSumMap> load_evalsum_map(const std::string& path) {
    std::ifstream is(path, std::ios::in | std::ios::binary);
    if (!is.is_open()) fail("cannot open eval-sum map for read");
    auto m = std::make_shared<EvalSumMap>();
    Serial::Deserialize(*m, is, SerType::BINARY);
    is.close();
    return m;
}

CryptoContext<DCRTPoly> load_mp_context(const std::string& dir) {
    auto cc = load_context(dir);
    // MULTIPARTY must be enabled on the deserialized context before any
    // Multiparty*/MultiEvalSum* call.
    cc->Enable(MULTIPARTY);
    return cc;
}

int mp_gen_context(int argc, char** argv) {
    if (argc < 6) fail("mp-gen-context requires <ctx_dir> <depth> <scale_mod_size> <batch_size> [ring_dim]");
    std::string dir = argv[2];
    uint32_t depth = std::stoul(argv[3]);
    uint32_t scaleMod = std::stoul(argv[4]);
    uint32_t batch = std::stoul(argv[5]);
    uint32_t ring = (argc >= 7) ? std::stoul(argv[6]) : 0;

    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(depth);
    params.SetScalingModSize(scaleMod);
    params.SetBatchSize(batch);
    if (ring > 0) params.SetRingDim(ring);
    params.SetSecurityLevel(HEStd_128_classic);

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    if (!Serial::SerializeToFile(dir + CTX_FILE, cc, SerType::BINARY))
        fail("cannot serialize context");

    std::cout << "{\"ring_dimension\":" << cc->GetRingDimension()
              << ",\"batch_size\":" << batch << "}" << std::endl;
    return 0;
}

int mp_keygen_lead(int argc, char** argv) {
    if (argc < 6) fail("mp-keygen-lead requires <ctx_dir> <share_dir> <out_pub> <out_evalsum>");
    std::string dir = argv[2];
    std::string share_dir = argv[3];
    std::string out_pub = argv[4];
    std::string out_evalsum = argv[5];

    auto cc = load_mp_context(dir);
    auto kp = cc->KeyGen();
    if (!kp.good()) fail("lead key generation failed");

    cc->EvalSumKeyGen(kp.secretKey);
    auto es = std::make_shared<EvalSumMap>(cc->GetEvalSumKeyMap(kp.secretKey->GetKeyTag()));

    // Secret share stays with party A only.
    if (!Serial::SerializeToFile(share_dir + SHARE_FILE, kp.secretKey, SerType::BINARY))
        fail("cannot serialize secret share");
    if (!Serial::SerializeToFile(out_pub, kp.publicKey, SerType::BINARY))
        fail("cannot serialize public key");
    save_evalsum_map(out_evalsum, es);

    std::cout << "{\"party\":\"lead\",\"key_tag\":\"" << kp.publicKey->GetKeyTag() << "\"}" << std::endl;
    return 0;
}

int mp_keygen_join(int argc, char** argv) {
    if (argc < 8) fail("mp-keygen-join requires <ctx_dir> <share_dir> <prev_pub> <prev_evalsum> <out_pub> <out_evalsum>");
    std::string dir = argv[2];
    std::string share_dir = argv[3];
    std::string prev_pub = argv[4];
    std::string prev_evalsum = argv[5];
    std::string out_pub = argv[6];
    std::string out_evalsum = argv[7];

    auto cc = load_mp_context(dir);
    auto prevPub = load<PublicKey<DCRTPoly>>(prev_pub, "previous public key");
    auto prevEs = load_evalsum_map(prev_evalsum);

    auto kp = cc->MultipartyKeyGen(prevPub);
    if (!kp.good()) fail("join key generation failed");

    const std::string tag = kp.publicKey->GetKeyTag();
    auto esThis = cc->MultiEvalSumKeyGen(kp.secretKey, prevEs, tag);
    auto esJoin = cc->MultiAddEvalSumKeys(prevEs, esThis, tag);

    // Secret share stays with this party only.
    if (!Serial::SerializeToFile(share_dir + SHARE_FILE, kp.secretKey, SerType::BINARY))
        fail("cannot serialize secret share");
    if (!Serial::SerializeToFile(out_pub, kp.publicKey, SerType::BINARY))
        fail("cannot serialize joint public key");
    save_evalsum_map(out_evalsum, esJoin);

    std::cout << "{\"party\":\"join\",\"key_tag\":\"" << tag << "\"}" << std::endl;
    return 0;
}

int mp_install_public(int argc, char** argv) {
    if (argc < 5) fail("mp-install-public requires <ctx_dir> <final_pub> <final_evalsum>");
    std::string dir = argv[2];
    std::string final_pub = argv[3];
    std::string final_evalsum = argv[4];

    auto cc = load_mp_context(dir);
    auto pub = load<PublicKey<DCRTPoly>>(final_pub, "final joint public key");
    auto es = load_evalsum_map(final_evalsum);

    // Install joint public key for encryption and joint eval-sum keys for
    // evaluation. No secret key is written to the shared context dir.
    if (!Serial::SerializeToFile(dir + PUB_FILE, pub, SerType::BINARY))
        fail("cannot serialize joint public key");
    cc->InsertEvalSumKey(es);
    std::ofstream sum(dir + SUM_FILE, std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalSumKey(sum, SerType::BINARY)) fail("cannot serialize joint eval-sum key");
    sum.close();

    std::cout << "{\"installed\":true}" << std::endl;
    return 0;
}

int mp_decrypt_lead(int argc, char** argv) {
    if (argc < 6) fail("mp-decrypt-lead requires <ctx_dir> <share_dir> <in_ct> <out_partial>");
    std::string dir = argv[2];
    std::string share_dir = argv[3];
    std::string in = argv[4];
    std::string out = argv[5];

    auto cc = load_mp_context(dir);
    auto sk = load<PrivateKey<DCRTPoly>>(share_dir + SHARE_FILE, "secret share");
    auto ct = load<Ciphertext<DCRTPoly>>(in, "ciphertext");

    auto partial = cc->MultipartyDecryptLead({ct}, sk);
    if (!Serial::SerializeToFile(out, partial[0], SerType::BINARY)) fail("cannot serialize partial");

    std::cout << "{\"partial\":\"lead\"}" << std::endl;
    return 0;
}

int mp_decrypt_main(int argc, char** argv) {
    if (argc < 6) fail("mp-decrypt-main requires <ctx_dir> <share_dir> <in_ct> <out_partial>");
    std::string dir = argv[2];
    std::string share_dir = argv[3];
    std::string in = argv[4];
    std::string out = argv[5];

    auto cc = load_mp_context(dir);
    auto sk = load<PrivateKey<DCRTPoly>>(share_dir + SHARE_FILE, "secret share");
    auto ct = load<Ciphertext<DCRTPoly>>(in, "ciphertext");

    auto partial = cc->MultipartyDecryptMain({ct}, sk);
    if (!Serial::SerializeToFile(out, partial[0], SerType::BINARY)) fail("cannot serialize partial");

    std::cout << "{\"partial\":\"main\"}" << std::endl;
    return 0;
}

int mp_decrypt_fuse(int argc, char** argv) {
    if (argc < 5) fail("mp-decrypt-fuse requires <ctx_dir> <length> <partial...>");
    std::string dir = argv[2];
    uint32_t length = std::stoul(argv[3]);

    auto cc = load_mp_context(dir);
    std::vector<Ciphertext<DCRTPoly>> partials;
    for (int i = 4; i < argc; ++i) partials.push_back(load<Ciphertext<DCRTPoly>>(argv[i], "partial"));
    if (partials.empty()) fail("no partial decryptions provided");

    Plaintext pt;
    cc->MultipartyDecryptFusion(partials, &pt);
    pt->SetLength(length);
    auto values = pt->GetRealPackedValue();

    std::cout << "{\"values\":[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << values[i];
    }
    std::cout << "],\"parties\":" << partials.size() << "}" << std::endl;
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) fail("usage: fhe_broker <gen-context|encrypt|evaluate|decrypt|"
                       "mp-gen-context|mp-keygen-lead|mp-keygen-join|mp-install-public|"
                       "mp-decrypt-lead|mp-decrypt-main|mp-decrypt-fuse> ...");
    std::string cmd = argv[1];
    try {
        if (cmd == "gen-context") return gen_context(argc, argv);
        if (cmd == "encrypt") return encrypt(argc, argv);
        if (cmd == "evaluate") return evaluate(argc, argv);
        if (cmd == "decrypt") return decrypt(argc, argv);
        if (cmd == "mp-gen-context") return mp_gen_context(argc, argv);
        if (cmd == "mp-keygen-lead") return mp_keygen_lead(argc, argv);
        if (cmd == "mp-keygen-join") return mp_keygen_join(argc, argv);
        if (cmd == "mp-install-public") return mp_install_public(argc, argv);
        if (cmd == "mp-decrypt-lead") return mp_decrypt_lead(argc, argv);
        if (cmd == "mp-decrypt-main") return mp_decrypt_main(argc, argv);
        if (cmd == "mp-decrypt-fuse") return mp_decrypt_fuse(argc, argv);
        fail("unknown command: " + cmd);
    } catch (const std::exception& e) {
        fail(std::string("exception: ") + e.what());
    }
    return 0;
}
