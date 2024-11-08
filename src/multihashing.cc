#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    #include "bcrypt.h"
    #include "blake.h"
    #include "c11.h"
    #include "cryptonight.h"
    #include "cryptonight_fast.h"
    #include "fresh.h"
    #include "fugue.h"
	#include "flex/flex.h",
    #include "groestl.h"
    #include "hefty1.h"
    #include "keccak.h"
    #include "lbry.h"
    #include "lyra2.h"
    #include "lyra2re.h"
    #include "lyra2z.h"
    #include "nist5.h"
    #include "quark.h"
    #include "qubit.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "sha1.h"
    #include "sha256d.h"
    #include "shavite3.h"
    #include "skein.h"
    #include "sponge.h"
    #include "x11.h"
    #include "x13.h"
    #include "x15.h"
    #include "x16r.h"
    #include "x16rv2.h"
    #include "neoscrypt.h"
    #include "crypto/argon2/argon2.h"
    #include "crypto/yescrypt/yescrypt.h"
	#include "allium/allium.h"
#include "blake/blake.h"
#include "blake/blake2s.h"
#include "c11/c11.h"
#include "curvehash/curvehash.h"
#include "equihash/equihash.h"
#include "fugue/fugue.h"
#include "ghostrider/ghostrider.h"
#include "groestl/groestl.h"
#include "keccak/keccak.h"
#include "lyra2re/lyra2re.h"
#include "minotaur/minotaur.h"
#include "neoscrypt/neoscrypt.h"
#include "nist5/nist5.h"
#include "quark/quark.h"
#include "qubit/qubit.h"
#include "scrypt/scrypt.h"
#include "sha256d/sha256d.h"
#include "sha512256d/sha512256d.h"
#include "skein/skein.h"
#include "verthash/verthash.h"
#include "x11/x11.h"
#include "x13/x13.h"
#include "x15/x15.h"
#include "x16r/x16r.h"
#include "x16rt/x16rt.h"
#include "x17/x17.h"

// ProgPow Imports
#include "evrprogpow/evrprogpow.h"
#include "evrprogpow/evrprogpow.hpp"
#include "evrprogpow/evrprogpow_progpow.hpp"
#include "firopow/firopow.h"
#include "firopow/firopow.hpp"
#include "firopow/firopow_progpow.hpp"
#include "kawpow/kawpow.h"
#include "kawpow/kawpow.hpp"
#include "kawpow/kawpow_progpow.hpp"
#include "meowpow/meowpow.h"
#include "meowpow/meowpow.hpp"
#include "meowpow/meowpow_progpow.hpp"

// Common Imports
#include "common/ethash/helpers.hpp"

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"
#include "secp256k1/include/secp256k1_preallocated.h"
#include "secp256k1/include/secp256k1_schnorrsig.h"
}

#include "boolberry.h"

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
    DECLARE_FUNC(x)

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

 DECLARE_CALLBACK(bcrypt, bcrypt_hash, 32);
 DECLARE_CALLBACK(blake, blake_hash, 32);
 DECLARE_CALLBACK(c11, c11_hash, 32);
 DECLARE_CALLBACK(fresh, fresh_hash, 32);
 DECLARE_CALLBACK(fugue, fugue_hash, 32);
 DECLARE_CALLBACK(flex, flex_hash, 32);
 DECLARE_CALLBACK(groestl, groestl_hash, 32);
 DECLARE_CALLBACK(groestlmyriad, groestlmyriad_hash, 32);
 DECLARE_CALLBACK(hefty1, hefty1_hash, 32);
 DECLARE_CALLBACK(keccak, keccak_hash, 32);
 DECLARE_CALLBACK(lbry, lbry_hash, 32);
 DECLARE_CALLBACK(lyra2re, lyra2re_hash, 32);
 DECLARE_CALLBACK(lyra2rev2, lyra2rev2_hash, 32);
 DECLARE_CALLBACK(lyra2rev3, lyra2rev3_hash, 32);
 DECLARE_CALLBACK(lyra2z, lyra2z_hash, 32);
 DECLARE_CALLBACK(nist5, nist5_hash, 32);
 DECLARE_CALLBACK(quark, quark_hash, 32);
 DECLARE_CALLBACK(qubit, qubit_hash, 32);
 DECLARE_CALLBACK(sha1, sha1_hash, 32);
 DECLARE_CALLBACK(sha256d, sha256d_hash, 32);
 DECLARE_CALLBACK(shavite3, shavite3_hash, 32);
 DECLARE_CALLBACK(skein, skein_hash, 32);
 DECLARE_CALLBACK(x11, x11_hash, 32);
 DECLARE_CALLBACK(x13, x13_hash, 32);
 DECLARE_CALLBACK(x15, x15_hash, 32);
 DECLARE_CALLBACK(x16r, x16r_hash, 32);
 DECLARE_CALLBACK(x16rv2, x16rv2_hash, 32);
 DECLARE_CALLBACK(yescrypt, yescrypt_hash, 32);

DECLARE_FUNC(argon2d) {
    if (info.Length() < 4)
        RETURN_EXCEPT("You must provide buffer to hash, T value, M value, and P value");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");

    unsigned int tValue = Nan::To<uint32_t>(info[1]).ToChecked();
    unsigned int mValue = Nan::To<uint32_t>(info[2]).ToChecked();
    unsigned int pValue = Nan::To<uint32_t>(info[3]).ToChecked();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    argon2d_hash_raw(tValue, mValue, pValue, input, input_len, input, input_len, output, 32);

    SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(argon2i) {
    if (info.Length() < 4)
        RETURN_EXCEPT("You must provide buffer to hash, T value, M value, and P value");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");

    unsigned int tValue = Nan::To<uint32_t>(info[1]).ToChecked();
    unsigned int mValue = Nan::To<uint32_t>(info[2]).ToChecked();
    unsigned int pValue = Nan::To<uint32_t>(info[3]).ToChecked();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    argon2i_hash_raw(tValue, mValue, pValue, input, input_len, input, input_len, output, 32);

    SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(argon2id) {

    if (info.Length() < 4)
        RETURN_EXCEPT("You must provide buffer to hash, T value, M value, and P value");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");

    unsigned int tValue = Nan::To<uint32_t>(info[1]).ToChecked();
    unsigned int mValue = Nan::To<uint32_t>(info[2]).ToChecked();
    unsigned int pValue = Nan::To<uint32_t>(info[3]).ToChecked();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    argon2id_hash_raw(tValue, mValue, pValue, input, input_len, input, input_len, output, 32);

    SET_BUFFER_RETURN(output, 32);
}
// Allium Algorithm
DECLARE_FUNC(allium) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  allium_hash(input, output);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Blake Algorithm
DECLARE_FUNC(blake) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  blake_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Blake Algorithm
DECLARE_FUNC(blake2s) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  blake2s_hash(input, output);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// C11 Algorithm
DECLARE_FUNC(c11) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  c11_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// CurveHash Algorithm
DECLARE_FUNC(curvehash) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  curve_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Equihash Algorithm
DECLARE_FUNC(equihash) {

  // Handle Main Scope
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  // Check Arguments for Errors [1]
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");
  if (!info[3]->IsInt32() || !info[4]->IsInt32())
    return THROW_ERROR_EXCEPTION("The fourth and fifth parameters should be equihash parameters (n, k)");

  // Define Passed Parameters
  Isolate *argsIsolate = info.GetIsolate();
  Local<Context> context = argsIsolate->GetCurrentContext();
  Local<Object> header = info[0]->ToObject(context).ToLocalChecked();
  Local<Object> solution = info[1]->ToObject(context).ToLocalChecked();

  // Check Arguments for Errors [2]
  if (!Buffer::HasInstance(header) || !Buffer::HasInstance(solution))
    return THROW_ERROR_EXCEPTION("The first two arguments should be buffer objects");
  if (!info[2]->IsString())
    return THROW_ERROR_EXCEPTION("The third argument should be the personalization string");

  // Header Length !== 140
  const char *hdr = Buffer::Data(header);
  if (Buffer::Length(header) != 140) {
    info.GetReturnValue().Set(false);
    return;
  }

  // Process Passed Parameters
  const char *soln = Buffer::Data(solution);
  vector<unsigned char> vecSolution(soln, soln + Buffer::Length(solution));
  Nan::Utf8String str(info[2]);
  const char* personalizationString = ToCString(str);
  unsigned int N = info[3].As<Uint32>()->Value();
  unsigned int K = info[4].As<Uint32>()->Value();

  // Hash Input Data and Check if Valid Solution
  bool isValid;
  crypto_generichash_blake2b_state state;
  EhInitialiseState(N, K, state, personalizationString);
  crypto_generichash_blake2b_update(&state, (const unsigned char*)hdr, 140);
  EhIsValidSolution(N, K, state, vecSolution, isValid);
  info.GetReturnValue().Set(isValid);
}

// Evrprogpow Algorithm
DECLARE_FUNC(evrprogpow) {

  // Check Arguments for Errors
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");

  // Process/Define Passed Parameters [1]
  const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
  int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  const ethash::hash256* mix_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
  ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

  // Process/Define Passed Parameters [2]
  static evrprogpow_main::epoch_context_ptr context{nullptr, nullptr};
  const auto epoch_number = evrprogpow_main::get_epoch_number(block_height);
  if (!context || context->epoch_number != epoch_number)
      context = evrprogpow_main::create_epoch_context(epoch_number);

  // Hash Input Data and Check if Valid Solution
  bool is_valid = evrprogpow_progpow::verify(*context, block_height, header_hash_ptr, *mix_hash_ptr, *nonce64_ptr, hash_out_ptr);
  if (is_valid) info.GetReturnValue().Set(Nan::True());
  else info.GetReturnValue().Set(Nan::False());
}

// Firopow Algorithm
DECLARE_FUNC(firopow) {

  // Check Arguments for Errors
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");

  // Process/Define Passed Parameters [1]
  const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
  int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  const ethash::hash256* mix_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
  ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

  // Process/Define Passed Parameters [2]
  static firopow_main::epoch_context_ptr context{nullptr, nullptr};
  const auto epoch_number = firopow_main::get_epoch_number(block_height);
  if (!context || context->epoch_number != epoch_number)
      context = firopow_main::create_epoch_context(epoch_number);

  // Hash Input Data and Check if Valid Solution
  bool is_valid = firopow_progpow::verify(*context, block_height, header_hash_ptr, *mix_hash_ptr, *nonce64_ptr, hash_out_ptr);
  if (is_valid) info.GetReturnValue().Set(Nan::True());
  else info.GetReturnValue().Set(Nan::False());
}

// Fugue Algorithm
DECLARE_FUNC(fugue) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  fugue_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Ghostrider Algorithm
DECLARE_FUNC(ghostrider) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  ghostrider_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Groestl Algorithm
DECLARE_FUNC(groestl) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  groestl_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Groestl Myriad Algorithm
DECLARE_FUNC(groestlmyriad) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  groestlmyriad_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Kawpow Algorithm
DECLARE_FUNC(kawpow) {

  // Check Arguments for Errors
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");

  // Process/Define Passed Parameters [1]
  const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
  int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  const ethash::hash256* mix_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
  ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

  // Process/Define Passed Parameters [2]
  static kawpow_main::epoch_context_ptr context{nullptr, nullptr};
  const auto epoch_number = kawpow_main::get_epoch_number(block_height);
  if (!context || context->epoch_number != epoch_number)
      context = kawpow_main::create_epoch_context(epoch_number);

  // Hash Input Data and Check if Valid Solution
  bool is_valid = kawpow_progpow::verify(*context, block_height, header_hash_ptr, *mix_hash_ptr, *nonce64_ptr, hash_out_ptr);
  if (is_valid) info.GetReturnValue().Set(Nan::True());
  else info.GetReturnValue().Set(Nan::False());
}

// Keccak Algorithm
DECLARE_FUNC(keccak) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  keccak_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Lyra2re Algorithm
DECLARE_FUNC(lyra2re) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide exactly one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  lyra2re_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Meowpow Algorithm
DECLARE_FUNC(meowpow) {

  // Check Arguments for Errors
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");

  // Process/Define Passed Parameters [1]
  const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
  int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  const ethash::hash256* mix_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
  ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

  // Process/Define Passed Parameters [2]
  static meowpow_main::epoch_context_ptr context{nullptr, nullptr};
  const auto epoch_number = meowpow_main::get_epoch_number(block_height);
  if (!context || context->epoch_number != epoch_number)
      context = meowpow_main::create_epoch_context(epoch_number);

  // Hash Input Data and Check if Valid Solution
  bool is_valid = meowpow_progpow::verify(*context, block_height, header_hash_ptr, *mix_hash_ptr, *nonce64_ptr, hash_out_ptr);
  if (is_valid) info.GetReturnValue().Set(Nan::True());
  else info.GetReturnValue().Set(Nan::False());
}

// Minotaur Algorithm
DECLARE_FUNC(minotaur) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  minotaur_hash(input, output, input_len, false);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// MinotaurX Algorithm
DECLARE_FUNC(minotaurx) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  minotaur_hash(input, output, input_len, true);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Neoscrypt Algorithm
DECLARE_FUNC(neoscrypt) {

  // Check Arguments for Errors
  if (info.Length() < 2)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  int profile = info[1]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  char output[32];

  // Hash Input Data and Return Output
  neoscrypt_hash(input, output, profile);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());

}

// Nist5 Algorithm
DECLARE_FUNC(nist5) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  nist5_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Quark Algorithm
DECLARE_FUNC(quark) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  quark_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Qubit Algorithm
DECLARE_FUNC(qubit) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  qubit_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Scrypt Algorithm
DECLARE_FUNC(scrypt) {

  // Handle Main Scope
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  // Check Arguments for Errors [1]
  if (info.Length() < 3)
    return THROW_ERROR_EXCEPTION("You must provide an input buffer, as well as an nValue and rValue.");
  if (!info[1]->IsInt32() || !info[2]->IsInt32())
    return THROW_ERROR_EXCEPTION("The first and second parameters should be scrypt parameters (n, r)");

  // Define Passed Parameters
  Isolate *argsIsolate = info.GetIsolate();
  Local<Context> context = argsIsolate->GetCurrentContext();
  Local<Object> header = info[0]->ToObject(context).ToLocalChecked();
  unsigned int N = info[1].As<Uint32>()->Value();
  unsigned int R = info[2].As<Uint32>()->Value();

  // Check Arguments for Errors [2]
  if (!Buffer::HasInstance(header))
    return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(header);
  uint32_t input_len = Buffer::Length(header);
  char output[32];

  // Hash Input Data and Return Output
  scrypt_N_R_1_256(input, output, N, R, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Sha256d Algorithm
DECLARE_FUNC(sha256d) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  sha256d_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Sha512256d Algorithm
DECLARE_FUNC(sha512256d) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t nonce = info[1]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  char output[32];

  // Hash Input Data and Return Output
  sha512256d_hash(input, output, nonce);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Skein Algorithm
DECLARE_FUNC(skein) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  skein_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Verthash Algorithm
DECLARE_FUNC(verthash) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  verthash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X11 Algorithm
DECLARE_FUNC(x11) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x11_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X13 Algorithm
DECLARE_FUNC(x13) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x13_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X15 Algorithm
DECLARE_FUNC(x15) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x15_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}



// X16rt Algorithm
DECLARE_FUNC(x16rt) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x16rt_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X17 Algorithm
DECLARE_FUNC(x17) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x17_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}
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
    NAN_EXPORT(target, argon2d);
    NAN_EXPORT(target, argon2i);
    NAN_EXPORT(target, argon2id);
    NAN_EXPORT(target, bcrypt);
    NAN_EXPORT(target, blake);
    NAN_EXPORT(target, boolberry);
    NAN_EXPORT(target, c11);
    NAN_EXPORT(target, cryptonight);
    NAN_EXPORT(target, cryptonightfast);
    NAN_EXPORT(target, fresh);
    NAN_EXPORT(target, fugue);
	NAN_EXPORT(target, flex);
    NAN_EXPORT(target, groestl);
    NAN_EXPORT(target, groestlmyriad);
    NAN_EXPORT(target, hefty1);
    NAN_EXPORT(target, keccak);
    NAN_EXPORT(target, lbry);
    NAN_EXPORT(target, lyra2re);
    NAN_EXPORT(target, lyra2rev2);
    NAN_EXPORT(target, lyra2rev3);
    NAN_EXPORT(target, lyra2z);
    NAN_EXPORT(target, nist5);
    NAN_EXPORT(target, quark);
    NAN_EXPORT(target, qubit);
    NAN_EXPORT(target, scrypt);
    NAN_EXPORT(target, scryptjane);
    NAN_EXPORT(target, scryptn);
    NAN_EXPORT(target, sha1);
    NAN_EXPORT(target, sha256d);
    NAN_EXPORT(target, shavite3);
    NAN_EXPORT(target, skein);
    NAN_EXPORT(target, x11);
    NAN_EXPORT(target, x13);
    NAN_EXPORT(target, x15);
    NAN_EXPORT(target, x16r);
    NAN_EXPORT(target, x16rv2);
    NAN_EXPORT(target, neoscrypt);
    NAN_EXPORT(target, yescrypt);
	NAN_EXPORT(target,"allium");
  NAN_EXPORT(target,"blake2s");
  NAN_EXPORT(target,"c11");
  NAN_EXPORT(target,"curvehash");
  NAN_EXPORT(target,"equihash");
  NAN_EXPORT(target,"evrprogpow");
  NAN_EXPORT(target,"firopow");
  NAN_EXPORT(target,"ghostrider");
  NAN_EXPORT(target,"kawpow");
  NAN_EXPORT(target,"meowpow");
  NAN_EXPORT(target,"minotaur");
  NAN_EXPORT(target,"minotaurx");
  NAN_EXPORT(target,"nist5");
  NAN_EXPORT(target,"scrypt");
  NAN_EXPORT(target,"sha512256d");
  NAN_EXPORT(target,"verthash");
  NAN_EXPORT(target,"x16rt");
  NAN_EXPORT(target,"x17");
}

NAN_MODULE_WORKER_ENABLED(multihashing, init);
