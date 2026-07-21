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
 * @file initialize_algorithm.cpp
 * @brief Implementation of algorithm initialization for DHTDynamic strategy
 * @details DHTDynamic does not generate keys in this stage (unlike SM9Static
 *          which generates a KGC master key). Algorithm initialization is a
 *          no-op that returns empty DHTDynamicAlgoPublicParams and
 *          DHTDynamicAlgoPrivateParams placeholder instances.
 *
 *          Key generation is deferred to the generateKeys stage because
 *          DHTDynamic uses random key generation (no KGC/master key derivation).
 *
 *          The placeholder params must be non-null because:
 *          1. AlgorithmProfile constructor validates publicParams != nullptr
 *          2. MongoDB persistence layer requires non-null params
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-08
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/strategy.h"
#include "DHTDynamicAuditStrategy/request_ext.h"
#include "DHTDynamicAuditStrategy/params.h"

namespace CAMatrix::Audit::Strategies {

using namespace DHTDynamic;

CAMatrix::Audit::Messages::InitializeAlgorithmResult
DHTDynamicAuditStrategy::initializeAlgorithm(
    const CAMatrix::Audit::Messages::InitializeAlgorithmRequest& input)
{
    CAMatrix::Audit::Messages::InitializeAlgorithmResult result;

    // Validate request extension type
    auto ext = std::dynamic_pointer_cast<DHTDynamicAlgoInitRequestExt>(input.ext);
    if (!ext) {
        result.ok = false;
        result.reason = "DHTDynamicAlgoInitRequestExt required";
        return result;
    }

    // DHTDynamic does not generate keys in this stage.
    // Unlike SM9Static (which creates a KGC master key here), DHTDynamic
    // defers key generation to the generateKeys stage because keys are
    // randomly generated without KGC/master key derivation.
    //
    // Return non-null placeholder instances to satisfy:
    // - AlgorithmProfile constructor (validates publicParams != nullptr)
    // - MongoDB persistence layer (requires non-null params)
    result.ok = true;
    result.reason = "DHTDynamic algorithm initialized (no key generation — keys are generated in generateKeys stage)";
    result.publicParams = std::make_shared<DHTDynamicAlgoPublicParams>();
    result.privateParams = std::make_shared<DHTDynamicAlgoPrivateParams>();
    return result;
}

} // namespace CAMatrix::Audit::Strategies
