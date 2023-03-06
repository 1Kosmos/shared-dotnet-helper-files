/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

namespace BIDHelpers.BIDTenant.Model
{
    public class BIDTenantInfo
    {
        public string dns;
        public string communityName;
        public string licenseKey;
        public string id;
        public string tenanttype;
        public string tenanttag;
        public string name;
        public string tenantId;
        public string communityId;

        public BIDTenantInfo(string dns, string communityName, string licenseKey)
        {
            this.dns = dns;
            this.communityName = communityName;
            this.licenseKey = licenseKey;
        }
    }
}
