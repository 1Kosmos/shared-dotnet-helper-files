/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

namespace BIDHelpers.BIDAccessCodes.Model
{
    public class BIDAccessCodeResponse
    {
        public int ttl_seconds;
        public string type;
        public bool phoneRequired;
        public string uuid;
        public int ttl;
        public string tenantId;
        public int createdTime;
        public string id;
        public string communityId;
        public BIDAccessCodePayloadData accesscodepayload;
        public string data;
        public string publickey;
        public string status;
        public int statusCode;
        public string message;
    }
}
