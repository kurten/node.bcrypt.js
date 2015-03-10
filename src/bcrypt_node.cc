#include <node.h>
#include <node_buffer.h>
#include <string>
#include <cstring>
#include <vector>
#include <stdlib.h> // atoi

#include "node_blf.h"

#define NODE_LESS_THAN (!(NODE_VERSION_AT_LEAST(0, 5, 4)))

using namespace v8;
using namespace node;

namespace {

bool ValidateSalt(const char* salt) {

    if (!salt || *salt != '$') {
        return false;
    }

    // discard $
    salt++;

    if (*salt > BCRYPT_VERSION) {
        return false;
    }

    if (salt[1] != '$') {
        switch (salt[1]) {
        case 'a':
            salt++;
            break;
        default:
            return false;
        }
    }

    // discard version + $
    salt += 2;

    if (salt[2] != '$') {
        return false;
    }

    int n = atoi(salt);
    if (n > 31 || n < 0) {
        return false;
    }

    if (((uint8_t)1 << (uint8_t)n) < BCRYPT_MINROUNDS) {
        return false;
    }

    salt += 3;
    if (strlen(salt) * 3 / 4 < BCRYPT_MAXSALT) {
        return false;
    }

    return true;
}

/* SALT GENERATION */

void GenerateSalt(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 2) {
        isolate->ThrowException(Exception::TypeError(
                String::NewFromUtf8(isolate, "2 arguments expected")));
        return;
    }

    if (!node::Buffer::HasInstance(args[1]) || node::Buffer::Length(args[1].As<Object>()) != 16) {
        isolate->ThrowException(Exception::TypeError(
                String::NewFromUtf8(isolate, "Second argument must be a 16 byte Buffer")));
        return;
    }

    const ssize_t rounds = args[0]->Int32Value();
    u_int8_t* seed = (u_int8_t*)node::Buffer::Data(args[1].As<Object>());
    char salt[_SALT_LEN];
    bcrypt_gensalt(rounds, seed, salt);

    Local<String> obj = String::NewFromUtf8(isolate, salt);
    args.GetReturnValue().Set(obj);
}

void Encrypt(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    
    if (args.Length() < 2) {
        isolate->ThrowException(Exception::TypeError(
                String::NewFromUtf8(isolate, "2 arguments expected")));
        return;
    }

    String::Utf8Value data(args[0]->ToString());
    String::Utf8Value salt(args[1]->ToString());

    if (!(ValidateSalt(*salt))) {
        isolate->ThrowException(Exception::TypeError(
                String::NewFromUtf8(isolate, "Invalid salt. Salt must be in the form of: $Vers$log2(NumRounds)$saltvalue")));
        return;
    }

    char bcrypted[_PASSWORD_LEN];
    bcrypt(*data, *salt, bcrypted);

    Local<String> obj = String::NewFromUtf8(isolate, bcrypted);
    args.GetReturnValue().Set(obj);
}

/* COMPARATOR */

inline bool CompareStrings(const char* s1, const char* s2) {

    bool eq = true;
    int s1_len = strlen(s1);
    int s2_len = strlen(s2);

    if (s1_len != s2_len) {
        eq = false;
    }

    const int max_len = (s2_len < s1_len) ? s1_len : s2_len;

    // to prevent timing attacks, should check entire string
    // don't exit after found to be false
    for (int i = 0; i < max_len; ++i) {
        if (s1_len >= i && s2_len >= i && s1[i] != s2[i]) {
            eq = false;
        }
    }

    return eq;
}

void Compare(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 2) {
        isolate->ThrowException(Exception::TypeError(
                String::NewFromUtf8(isolate, "2 arguments expected")));
        return;
    }

    String::Utf8Value pw(args[0]->ToString());
    String::Utf8Value hash(args[1]->ToString());

    char bcrypted[_PASSWORD_LEN];
    bool eq = false;
    if (ValidateSalt(*hash)) {
        bcrypt(*pw, *hash, bcrypted);

        eq = CompareStrings(bcrypted, *hash);
    }
    Local<Boolean> obj = Boolean::New(isolate, eq);
    args.GetReturnValue().Set(obj);
}

void GetRounds(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 1) {
        isolate->ThrowException(Exception::TypeError(
                String::NewFromUtf8(isolate, "1 arguments expected")));
        return;
    }

    String::Utf8Value hash(args[0]->ToString());
    u_int32_t rounds;
    if (!(rounds = bcrypt_get_rounds(*hash))) {
        isolate->ThrowException(Exception::TypeError(
                String::NewFromUtf8(isolate, "invalid hash provided")));
        return;
    }

    Local<Number> num = Number::New(isolate, rounds);
    args.GetReturnValue().Set(num);
}

} // anonymous namespace

// bind the bcrypt module
extern "C" void init(Handle<Object> target) {
        NODE_SET_METHOD(target, "getRounds", GetRounds);
        NODE_SET_METHOD(target, "genSalt", GenerateSalt);
        NODE_SET_METHOD(target, "encrypt", Encrypt);
        NODE_SET_METHOD(target, "compare", Compare);
};

NODE_MODULE(bcrypt_lib, init);