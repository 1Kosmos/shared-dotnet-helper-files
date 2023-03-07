
/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

namespace BIDHelpers.BIDTenant.Model
{
    public class BIDCommunityInfo
    {
        public BIDCommunityInfoTenant tenant;
        public BIDCommunityInfoCommunity community;
        public string message;
        public bool status = true;
    }
    public class BIDCommunityInfoTenant
    {
        public string dns;
        public string communityName;
        public string id;
        public string tenanttype;
        public string tenanttag;
        public string name;
    }
    public class BIDCommunityInfoCommunity
    {
        public string id;
        public string tenantid;
        public string name;
        public string publicKey;
    }
}
