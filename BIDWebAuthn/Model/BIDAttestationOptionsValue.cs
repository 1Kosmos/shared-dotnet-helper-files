/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
namespace BIDHelpers.BIDWebAuthn.Model
{
    public class BIDAttestationOptionsValue
    {
        public string dns;
        public string username;
        public string displayName;
        public string attestation;
        public BIDAuthenticatorSelectionValue authenticatorSelection;
        public string communityId;
        public string tenantId;
    }
}
