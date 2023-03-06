
/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
using System.Collections.Generic;

namespace BIDHelpers.BIDWebAuthn.Model
{
    public class BIDAttestationOptionsResponse
    {
        public BIDAttestationUserData user;
        public string attestation;
        public IList<BIDPubKeyCredParam> pubKeyCredParams;
        public int timeout;
        public BIDAuthenticatorSelectionValue authenticatorSelection;
        public string challenge;
        public IList<IDictionary<string, object>> excludeCredentials;
        public string status;
        public string errorMessage;
        public string data;

    }
}
