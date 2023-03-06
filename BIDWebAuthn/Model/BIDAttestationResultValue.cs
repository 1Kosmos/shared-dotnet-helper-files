/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

namespace BIDHelpers.BIDWebAuthn.Model
{
    public class BIDAttestationResultValue
    {
        public string rawId;
        public BIDAttestationResultResponseValue response;
        public string authenticatorAttachment;
        public object getClientExtensionResults;
        public string id;
        public string type;
        public string dns;
    }
}
