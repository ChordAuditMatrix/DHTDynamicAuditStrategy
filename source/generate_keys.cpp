/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file generate_keys.cpp
 * @brief Implementation of key generation for DHTDynamic strategy
 * @details Generates the DHTDynamic user key pair using SM9BLS crypto layer
 *          for the file ID signing key, and curve primitives for the DHT-specific
 *          block tag key.
 *
 *          The DHTDynamic scheme uses two BLS key pairs:
 *
 *          1. File ID signing key (via SM9BLS):
 *             - Private: sk (= SM9BLS ks)
 *             - Public:  pk = Ppubs = [sk]·P₂
 *             - Used for: σ_id = [sk]·curveHash(fileID)
 *
 *          2. Block tag signing key (DHT-specific, direct generation):
 *             - Private: a ∈ Z_q* (BLS signing scalar)
 *             - Public:  g = [r]·P₂ (random G₂ generator), y = [a]·g
 *             - Binding: u = [r']·P₁ (random G₁ point for data commitment)
 *             - Used for: σ_i = [a]·(H(v_i‖t_i) + m_i·u)
 *
 *          Key generation steps:
 *          1. Generate file ID key pair via SM9BLS: (sk, pk)
 *          2. Generate random BLS signing scalar: a ∈ Z_q*
 *          3. Generate random G₂ generator: g = [r] · P₂
 *          4. Compute signing commitment:  y = [a] · g
 *          5. Generate proof binding point: u = [r'] · P₁
 *
 *          The public params contain: {pk, g, y, u}
 *          The private params contain: {sk, a}
 *
 * @author Dylan Liu
 * @version 3.0.0
 * @date 2026-07-11
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/strategy.h"
#include "DHTDynamicAuditStrategy/request_ext.h"
#include "DHTDynamicAuditStrategy/params.h"
#include "DHTDynamicAuditStrategy/common.h"

#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/algorithm.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/requests.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/keys/key_pair.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/keys/public_key.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/keys/private_key.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/data.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/points.h"

#include <cstring>

namespace CAMatrix::Audit::Strategies {

using namespace DHTDynamic;

CAMatrix::Audit::Messages::GenerateKeysResult
DHTDynamicAuditStrategy::generateKeys(
    const CAMatrix::Audit::Messages::GenerateKeysRequest& input)
{
    CAMatrix::Audit::Messages::GenerateKeysResult result;

    // Validate request extension type
    auto ext = std::dynamic_pointer_cast<DHTDynamicKeyGenRequestExt>(input.ext);
    if (!ext) {
        result.ok = false;
        result.reason = "DHTDynamicKeyGenRequestExt required";
        return result;
    }

    // ── Part A: File ID signing key via SM9BLS ──
    // Generate (sk, pk) = (ks, Ppubs) using SM9BLS crypto layer.
    // This is a standard SM9 BLS key pair: σ_id = [sk]·curveHash(fileID)
    auto keyPairPtr = algorithm_->generateKey(
        ::CAMatrix::Crypto::SM9BLS::SM9BLSKeyPairRequest());
    if (!keyPairPtr) {
        result.ok = false;
        result.reason = "SM9BLS key generation failed for file ID key";
        return result;
    }

    auto keyPair = std::dynamic_pointer_cast<::CAMatrix::Crypto::SM9BLS::SM9BLSKeyPair>(keyPairPtr);
    if (!keyPair) {
        result.ok = false;
        result.reason = "Invalid key pair type returned from SM9BLS";
        return result;
    }

    auto privKey = std::dynamic_pointer_cast<::CAMatrix::Crypto::SM9BLS::SM9BLSPrivateKey>(keyPair->privateKeyPtr);
    auto pubKey = std::dynamic_pointer_cast<::CAMatrix::Crypto::SM9BLS::SM9BLSPublicKey>(keyPair->publicKeyPtr);
    if (!privKey || !pubKey) {
        result.ok = false;
        result.reason = "Invalid public/private key type from SM9BLS";
        return result;
    }

    // Extract sk and pk from SM9BLS key pair
    ::CAMatrix::Crypto::SM9BLS::SM9CryptoData sk = privKey->ks;
    ::CAMatrix::Crypto::SM9BLS::G2Point pk = pubKey->ppubs;

    // ── Part B: Block tag signing key (DHT-specific) ──
    // Generate (a, g, y, u) directly using curve primitives.
    // These are DHT-specific because g is a random G₂ generator (not P₂),
    // and u is a random G₁ point for data commitment.

    // Step 1: Generate random BLS signing scalar a ∈ Z_q*
    ::CAMatrix::Crypto::SM9BLS::SM9CryptoData a;
    do {
        auto randomBytes = algorithm_->generateRandom(a.size());
        if (randomBytes.size() != a.size()) {
            result.ok = false;
            result.reason = "DHTDynamic: random scalar a generation failed";
            return result;
        }
        std::memcpy(a.data(), randomBytes.data(), a.size());
    } while (a.isZero());

    // Step 2: Generate random G₂ generator: g = [r] · P₂
    ::CAMatrix::Crypto::SM9BLS::SM9CryptoData r;
    do {
        auto randomBytes = algorithm_->generateRandom(r.size());
        if (randomBytes.size() != r.size()) {
            result.ok = false;
            result.reason = "DHTDynamic: random r generation failed";
            return result;
        }
        std::memcpy(r.data(), randomBytes.data(), r.size());
    } while (r.isZero());
    auto g = ::CAMatrix::Crypto::SM9BLS::G2Point::fromScalar(r);

    // Step 3: Compute y = [a] · g (BLS public key with random generator)
    auto yPtr = std::static_pointer_cast<::CAMatrix::Crypto::SM9BLS::G2Point>(g * a);
    auto y = *yPtr;

    // Step 4: Generate proof binding point: u = [r'] · P₁
    ::CAMatrix::Crypto::SM9BLS::SM9CryptoData rPrime;
    do {
        auto randomBytes = algorithm_->generateRandom(rPrime.size());
        if (randomBytes.size() != rPrime.size()) {
            result.ok = false;
            result.reason = "DHTDynamic: random r' generation failed";
            return result;
        }
        std::memcpy(rPrime.data(), randomBytes.data(), rPrime.size());
    } while (rPrime.isZero());
    auto uPtr = std::static_pointer_cast<::CAMatrix::Crypto::SM9BLS::G1Point>(
        ::CAMatrix::Crypto::SM9BLS::G1Point::generator() * rPrime);
    auto u = *uPtr;

    // ── Assemble DHTDynamic params ──
    // Public params: {pk, g, y, u}
    auto userPubParams = std::make_shared<DHTDynamicPublicParams>();
    userPubParams->pk = pk;
    userPubParams->g  = g;
    userPubParams->y  = y;
    userPubParams->u  = u;

    // Private params: {sk, a}
    auto userPrivParams = std::make_shared<DHTDynamicPrivateParams>();
    userPrivParams->sk = sk;
    userPrivParams->a  = a;

    result.ok = true;
    result.reason = "DHTDynamic key pair generated";
    result.publicParams = userPubParams;
    result.privateParams = userPrivParams;
    return result;
}

} // namespace CAMatrix::Audit::Strategies
