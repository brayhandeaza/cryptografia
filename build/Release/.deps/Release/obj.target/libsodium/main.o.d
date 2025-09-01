cmd_Release/obj.target/libsodium/main.o := c++ -o Release/obj.target/libsodium/main.o ../main.cpp '-DNODE_GYP_MODULE_NAME=libsodium' '-DUSING_UV_SHARED=1' '-DUSING_V8_SHARED=1' '-DV8_DEPRECATION_WARNINGS=1' '-D_GLIBCXX_USE_CXX11_ABI=1' '-D_DARWIN_USE_64_BIT_INODE=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DNAPI_DISABLE_CPP_EXCEPTIONS=0' '-DBUILDING_NODE_EXTENSION' -I/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node -I/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/src -I/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/deps/openssl/config -I/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/deps/openssl/openssl/include -I/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/deps/uv/include -I/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/deps/zlib -I/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/deps/v8/include -I../node_modules/node-addon-api -I/opt/homebrew/Cellar/libsodium/1.0.20/include -I/opt/homebrew/opt/openssl/include/openssl  -O3 -gdwarf-2 -fno-strict-aliasing -mmacosx-version-min=11.0 -arch arm64 -Wall -Wendif-labels -W -Wno-unused-parameter -std=gnu++17 -stdlib=libc++ -fno-rtti -MMD -MF ./Release/.deps/Release/obj.target/libsodium/main.o.d.raw   -c
Release/obj.target/libsodium/main.o: ../main.cpp \
  ../node_modules/node-addon-api/napi.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/node_api.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/js_native_api.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/js_native_api_types.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/node_api_types.h \
  ../node_modules/node-addon-api/napi-inl.h \
  ../node_modules/node-addon-api/napi-inl.deprecated.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/version.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/export.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/core.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_aead_aegis128l.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_aead_aegis256.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_aead_aes256gcm.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_aead_chacha20poly1305.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_aead_xchacha20poly1305.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_auth.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_auth_hmacsha512256.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_auth_hmacsha512.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_hash_sha512.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_auth_hmacsha256.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_hash_sha256.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_box.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_box_curve25519xsalsa20poly1305.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_xsalsa20.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_hchacha20.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_hsalsa20.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_salsa20.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_salsa2012.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_salsa208.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_generichash.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_generichash_blake2b.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_hash.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_kdf.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_kdf_blake2b.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_kdf_hkdf_sha256.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_kdf_hkdf_sha512.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_kx.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_onetimeauth.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_onetimeauth_poly1305.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_pwhash.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_pwhash_argon2i.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_pwhash_argon2id.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_scalarmult.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_scalarmult_curve25519.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_secretbox.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_secretbox_xsalsa20poly1305.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_secretstream_xchacha20poly1305.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_chacha20.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_shorthash.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_shorthash_siphash24.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_sign.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_sign_ed25519.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_salsa20.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_verify_16.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_verify_32.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_verify_64.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/randombytes.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/randombytes_internal_random.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/randombytes_sysrandom.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/runtime.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/utils.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_box_curve25519xchacha20poly1305.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_xchacha20.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_ed25519.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_ristretto255.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_pwhash_scryptsalsa208sha256.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_scalarmult_ed25519.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_scalarmult_ristretto255.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_secretbox_xchacha20poly1305.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_salsa2012.h \
  /opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_salsa208.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/evp.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/macros.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/opensslconf.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/configuration.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./configuration_asm.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/configuration.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/opensslv.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./opensslv_asm.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/opensslv.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/types.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/e_os2.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/safestack.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./safestack_asm.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/safestack.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/stack.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/core.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/core_dispatch.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/symhacks.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/bio.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./bio_asm.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/bio.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/crypto.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./crypto_asm.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/crypto.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/cryptoerr.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/cryptoerr_legacy.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/bioerr.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/evperr.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/params.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/bn.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/bnerr.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/objects.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/obj_mac.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/asn1.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./asn1_asm.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/asn1.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/asn1err.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/objectserr.h \
  .././include/AES.h .././include/Utils.h .././include/ECC.h \
  .././include/HASH.h \
  /Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/provider.h
../main.cpp:
../node_modules/node-addon-api/napi.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/node_api.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/js_native_api.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/js_native_api_types.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/node_api_types.h:
../node_modules/node-addon-api/napi-inl.h:
../node_modules/node-addon-api/napi-inl.deprecated.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/version.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/export.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/core.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_aead_aegis128l.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_aead_aegis256.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_aead_aes256gcm.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_aead_chacha20poly1305.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_aead_xchacha20poly1305.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_auth.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_auth_hmacsha512256.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_auth_hmacsha512.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_hash_sha512.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_auth_hmacsha256.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_hash_sha256.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_box.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_xsalsa20.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_hchacha20.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_hsalsa20.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_salsa20.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_salsa2012.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_salsa208.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_generichash.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_generichash_blake2b.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_hash.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_kdf.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_kdf_blake2b.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_kdf_hkdf_sha256.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_kdf_hkdf_sha512.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_kx.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_onetimeauth.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_onetimeauth_poly1305.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_pwhash.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_pwhash_argon2i.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_pwhash_argon2id.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_scalarmult.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_scalarmult_curve25519.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_secretbox.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_secretbox_xsalsa20poly1305.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_secretstream_xchacha20poly1305.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_chacha20.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_shorthash.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_shorthash_siphash24.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_sign.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_sign_ed25519.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_salsa20.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_verify_16.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_verify_32.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_verify_64.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/randombytes.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/randombytes_internal_random.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/randombytes_sysrandom.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/runtime.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/utils.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_box_curve25519xchacha20poly1305.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_xchacha20.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_ed25519.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_core_ristretto255.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_scalarmult_ed25519.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_scalarmult_ristretto255.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_secretbox_xchacha20poly1305.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_salsa2012.h:
/opt/homebrew/Cellar/libsodium/1.0.20/include/sodium/crypto_stream_salsa208.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/evp.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/macros.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/opensslconf.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/configuration.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./configuration_asm.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/configuration.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/opensslv.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./opensslv_asm.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/opensslv.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/types.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/e_os2.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/safestack.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./safestack_asm.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/safestack.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/stack.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/core.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/core_dispatch.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/symhacks.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/bio.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./bio_asm.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/bio.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/crypto.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./crypto_asm.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/crypto.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/cryptoerr.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/cryptoerr_legacy.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/bioerr.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/evperr.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/params.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/bn.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/bnerr.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/objects.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/obj_mac.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/asn1.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/./asn1_asm.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/././archs/darwin64-arm64-cc/asm/include/openssl/asn1.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/asn1err.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/objectserr.h:
.././include/AES.h:
.././include/Utils.h:
.././include/ECC.h:
.././include/HASH.h:
/Users/brayhandeaza/Library/Caches/node-gyp/22.14.0/include/node/openssl/provider.h:
