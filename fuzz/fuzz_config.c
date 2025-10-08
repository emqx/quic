/*--------------------------------------------------------------------
Copyright (c) 2024 EMQ Technologies Co., Ltd. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-------------------------------------------------------------------*/

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <msquic.h>

// Fuzzing target for QUIC configuration handling
// This tests msquic library's configuration parsing and parameter setting

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Initialize QUIC library
    const QUIC_API_TABLE* MsQuic = NULL;
    QUIC_REGISTRATION_CONFIG RegConfig = { "fuzz", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    HQUIC Registration = NULL;
    
    if (Size < 4 || Size > 1024) {
        return 0;
    }
    
    // Initialize the QUIC library
    if (QUIC_FAILED(MsQuicOpen2(&MsQuic))) {
        return 0;
    }
    
    // Create a registration
    if (QUIC_FAILED(MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        MsQuicClose(MsQuic);
        return 0;
    }
    
    // Test configuration with fuzzer input
    QUIC_SETTINGS Settings = {0};
    Settings.IsSet.IdleTimeoutMs = TRUE;
    Settings.IdleTimeoutMs = (Data[0] << 8) | Data[1];
    
    if (Size >= 4) {
        Settings.IsSet.MaxBytesPerKey = TRUE;
        Settings.MaxBytesPerKey = ((uint64_t)Data[2] << 8) | Data[3];
    }
    
    if (Size >= 6) {
        Settings.IsSet.ServerResumptionLevel = TRUE;
        Settings.ServerResumptionLevel = Data[4] % 3; // Valid values: 0, 1, 2
    }
    
    if (Size >= 8) {
        Settings.IsSet.PeerBidiStreamCount = TRUE;
        Settings.PeerBidiStreamCount = (Data[6] << 8) | Data[7];
    }
    
    // Apply settings to a configuration
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    
    HQUIC Configuration = NULL;
    QUIC_BUFFER Alpn = { sizeof("fuzz") - 1, (uint8_t*)"fuzz" };
    
    if (QUIC_SUCCEEDED(MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        // Load credentials
        MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig);
        
        // Clean up configuration
        MsQuic->ConfigurationClose(Configuration);
    }
    
    // Clean up
    MsQuic->RegistrationClose(Registration);
    MsQuicClose(MsQuic);
    
    return 0;
}
