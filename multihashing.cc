#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    // Main Imports
#include "algorithms/main/allium/allium.h"
#include "algorithms/main/blake/blake.h"
#include "algorithms/main/blake/blake2s.h"
#include "algorithms/main/c11/c11.h"
#include "algorithms/main/curvehash/curvehash.h"
#include "algorithms/main/equihash/equihash.h"
#include "algorithms/main/fugue/fugue.h"
#include "algorithms/main/ghostrider/ghostrider.h"
#include "algorithms/main/groestl/groestl.h"
#include "algorithms/main/keccak/keccak.h"
#include "algorithms/main/lyra2re/lyra2re.h"
#include "algorithms/main/minotaur/minotaur.h"
#include "algorithms/main/neoscrypt/neoscrypt.h"
#include "algorithms/main/nist5/nist5.h"
#include "algorithms/main/quark/quark.h"
#include "algorithms/main/qubit/qubit.h"
#include "algorithms/main/scrypt/scrypt.h"
#include "algorithms/main/sha256d/sha256d.h"
#include "algorithms/main/sha512256d/sha512256d.h"
#include "algorithms/main/skein/skein.h"
#include "algorithms/main/verthash/verthash.h"
#include "algorithms/main/x11/x11.h"
#include "algorithms/main/x13/x13.h"
#include "algorithms/main/x15/x15.h"
#include "algorithms/main/x16r/x16r.h"
#include "algorithms/main/x16rt/x16rt.h"
#include "algorithms/main/x17/x17.h"

// ProgPow Imports
#include "algorithms/main/evrprogpow/evrprogpow.h"
#include "algorithms/main/evrprogpow/evrprogpow.hpp"
#include "algorithms/main/evrprogpow/evrprogpow_progpow.hpp"
#include "algorithms/main/firopow/firopow.h"
#include "algorithms/main/firopow/firopow.hpp"
#include "algorithms/main/firopow/firopow_progpow.hpp"
#include "algorithms/main/kawpow/kawpow.h"
#include "algorithms/main/kawpow/kawpow.hpp"
#include "algorithms/main/kawpow/kawpow_progpow.hpp"
#include "algorithms/main/meowpow/meowpow.h"
#include "algorithms/main/meowpow/meowpow.hpp"
#include "algorithms/main/meowpow/meowpow_progpow.hpp"

// Common Imports
#include "algorithms/main/common/ethash/helpers.hpp"

#include "algorithms/main/secp256k1/include/secp256k1.h"
#include "algorithms/main/secp256k1/include/secp256k1_ecdh.h"
#include "algorithms/main/secp256k1/include/secp256k1_preallocated.h"
#include "algorithms/main/secp256k1/include/secp256k1_schnorrsig.h"
}

#include "src/boolberry.h"

using namespace node;
using namespace Nan;
using namespace v8;

#define SET_BUFFER_RETURN(x, len) \
    info.GetReturnValue().Set(Nan::CopyBuffer(x, len).ToLocalChecked());

#define SET_BOOLEAN_RETURN(x) \
    info.GetReturnValue().Set(Nan::To<Boolean>(x).ToChecked());

#define RETURN_EXCEPT(msg) \
    return Nan::ThrowError(msg)

#define DECLARE_FUNC(x) \
    NAN_METHOD(x)

#define DECLARE_CALLBACK(name, hash, output_len) \
    DECLARE_FUNC(name) { \
 \
    if (info.Length() < 1) \
        RETURN_EXCEPT("You must provide one argument."); \
 \
    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked(); \
 \
    if(!Buffer::HasInstance(target)) \
        RETURN_EXCEPT("Argument should be a buffer object."); \
 \
    char * input = Buffer::Data(target); \
    char output[32]; \
 \
    uint32_t input_len = Buffer::Length(target); \
 \
    hash(input, output, input_len); \
 \
    SET_BUFFER_RETURN(output, output_len); \
}
DECLARE_CALLBACK(allium, allium_hash, 32);
DECLARE_CALLBACK(blake, blake_hash, 32);
DECLARE_CALLBACK(blake, blake2s_hash, 32);
DECLARE_CALLBACK(c11, c11_hash, 32);
DECLARE_CALLBACK(curvehash, curve_hash, 32);
DECLARE_CALLBACK(equihash, equi_hash, 32);
DECLARE_CALLBACK(fugue, fugue_hash, 32);
DECLARE_CALLBACK(ghostrider, ghostrider_hash, 32);
DECLARE_CALLBACK(groestl, groestl_hash, 32);
DECLARE_CALLBACK(keccak, keccak_hash, 32);
DECLARE_CALLBACK(lyra2re, lyra2re_hash, 32);
DECLARE_CALLBACK(minotaur, minotaur_hash, 32);
DECLARE_CALLBACK(neoscrypt, neoscrypt_hash, 32);
DECLARE_CALLBACK(nist5, nist5_hash, 32);
DECLARE_CALLBACK(quark, quark_hash, 32);
DECLARE_CALLBACK(qubit, qubit_hash, 32);
DECLARE_CALLBACK(scrypt, scrypt_hash, 32);
DECLARE_CALLBACK(sha256d, sha256d_hash, 32);
DECLARE_CALLBACK(sha512256d, sha512256d_hash, 32);
DECLARE_CALLBACK(skein, skein_hash, 32);
DECLARE_CALLBACK(verthash, verthash_hash, 32);
DECLARE_CALLBACK(verthash, vert_hash, 32);
DECLARE_CALLBACK(x11, x11_hash, 32);
DECLARE_CALLBACK(x13, x13_hash, 32);
DECLARE_CALLBACK(x15, x15_hash, 32);
DECLARE_CALLBACK(x16r, x16r_hash, 32);
DECLARE_CALLBACK(x16rt, x16rt_hash, 32);
DECLARE_CALLBACK(x17, x17_hash, 32);

// ProgPow Imports
DECLARE_CALLBACK(evrprogpow, evrprogpow_hash, 32);
DECLARE_CALLBACK(firopow, firopow_hash, 32);
DECLARE_CALLBACK(progpow, progpow_hash, 32);
DECLARE_CALLBACK(kawpow, kawpow_hash, 32);
DECLARE_CALLBACK(meowpow, meowpow_hash, 32);
 

DECLARE_FUNC(scrypt) {
   if (info.Length() < 3)
       RETURN_EXCEPT("You must provide buffer to hash, N value, and R value");

   Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");

   unsigned int nValue = Nan::To<uint32_t>(info[1]).ToChecked();
   unsigned int rValue = Nan::To<uint32_t>(info[2]).ToChecked();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(neoscrypt) {
   if (info.Length() < 2)
       RETURN_EXCEPT("You must provide two arguments");

   Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");

   uint32_t profile = Nan::To<uint32_t>(info[1]).ToChecked();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   if (input_len < 80)
      RETURN_EXCEPT("Argument must be longer than 80 bytes");
   neoscrypt(input, output, profile);

   SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(scryptn) {
   if (info.Length() < 2)
       RETURN_EXCEPT("You must provide buffer to hash and N factor.");

   Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");

   unsigned int nFactor = Nan::To<uint32_t>(info[1]).ToChecked();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now

   SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(scryptjane) {
    if (info.Length() < 5)
        RETURN_EXCEPT("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("First should be a buffer object.");

    int timestamp = Nan::To<int32_t>(info[1]).ToChecked();
    int nChainStartTime = Nan::To<int32_t>(info[2]).ToChecked();
    int nMin = Nan::To<int32_t>(info[3]).ToChecked();
    int nMax = Nan::To<int32_t>(info[4]).ToChecked();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(cryptonight) {
    bool fast = false;
    uint32_t cn_variant = 0;
    uint64_t height = 0;

    if (info.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");

    if (info.Length() >= 2) {
        if(info[1]->IsBoolean())
            fast = Nan::To<bool>(info[1]).ToChecked();
        else if(info[1]->IsUint32())
            cn_variant = Nan::To<uint32_t>(info[1]).ToChecked();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }

    if ((cn_variant == 4) && (info.Length() < 3)) {
        RETURN_EXCEPT("You must provide Argument 3 (block height) for Cryptonight variant 4");
    }

    if (info.Length() >= 3) {
        if(info[2]->IsUint32())
            height = Nan::To<uint32_t>(info[2]).ToChecked();
        else
            RETURN_EXCEPT("Argument 3 should be uint32_t");
    }

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else {
        if ((cn_variant == 1) && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1");
        cryptonight_hash(input, output, input_len, cn_variant, height);
    }
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(cryptonightfast) {
    bool fast = false;
    uint32_t cn_variant = 0;

    if (info.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");

    if (info.Length() >= 2) {
        if(info[1]->IsBoolean())
            fast = Nan::To<bool>(info[1]).ToChecked();
        else if(info[1]->IsUint32())
            cn_variant = Nan::To<uint32_t>(info[1]).ToChecked();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonightfast_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonightfast_hash(input, output, input_len, cn_variant);
    }
    SET_BUFFER_RETURN(output, 32);
}
DECLARE_FUNC(boolberry) {
    if (info.Length() < 2)
        RETURN_EXCEPT("You must provide two arguments.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    Local<Object> target_spad = Nan::To<Object>(info[1]).ToLocalChecked();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(target_spad))
        RETURN_EXCEPT("Argument 2 should be a buffer object.");

    if(info.Length() >= 3) {
        if(info[2]->IsUint32())
            height = Nan::To<uint32_t>(info[2]).ToChecked();
        else
            RETURN_EXCEPT("Argument 3 should be an unsigned integer.");
    }

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

    SET_BUFFER_RETURN(output, 32);
}

NAN_MODULE_INIT(init) {

NAN_EXPORT(target, allium);
NAN_EXPORT(target, blake);
NAN_EXPORT(target, blake);
NAN_EXPORT(target, c11);
NAN_EXPORT(target, curvehash);
NAN_EXPORT(target, equihash);
NAN_EXPORT(target, fugue);
NAN_EXPORT(target, ghostrider);
NAN_EXPORT(target, groestl);
NAN_EXPORT(target, keccak);
NAN_EXPORT(target, lyra2re);
NAN_EXPORT(target, minotaur);
NAN_EXPORT(target, neoscrypt);
NAN_EXPORT(target, nist5);
NAN_EXPORT(target, quark);
NAN_EXPORT(target, qubit);
NAN_EXPORT(target, scrypt);
NAN_EXPORT(target, sha256d);
NAN_EXPORT(target, sha512256d);
NAN_EXPORT(target, skein);
NAN_EXPORT(target, verthash);
NAN_EXPORT(target, verthash);
NAN_EXPORT(target, x11);
NAN_EXPORT(target, x13);
NAN_EXPORT(target, x15);
NAN_EXPORT(target, x16r);
NAN_EXPORT(target, x16rt);
NAN_EXPORT(target, x17);

// ProgPow Imports
NAN_EXPORT(target, evrprogpow);
NAN_EXPORT(target, firopow);
NAN_EXPORT(target, progpow);
NAN_EXPORT(target, kawpow);
NAN_EXPORT(target, meowpow);
	
}

NAN_MODULE_WORKER_ENABLED(multihashing, init);
