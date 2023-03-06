/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

using BIDHelpers.BIDECDSA.Model;
using BIDHelpers.BIDSessions.Model;
using BIDHelpers.BIDTenant.Model;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;

namespace BIDHelpers.BIDUsers
{
    public class BIDUsers
    {
        public static BIDPoNData FetchUserByDID(BIDTenantInfo tenantInfo, string did, bool fetchDevices)
        {
            BIDPoNData ret;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, communityInfo.community.publicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;
                headers["X-TenantTag"] = communityInfo.tenant.tenanttag;

                string url = sd.adminconsole + "/api/r1/community/" + communityInfo.community.name + "/userdid/" + did + "/userinfo";
                if (fetchDevices)
                {
                    url += "?devicelist=true";
                }

                IDictionary<string, object> response = WTM.ExecuteRequest("get", url, headers, null);

                string error = null;
                int statusCode = 0;
                dynamic json = null;
                foreach (var item in response)
                {
                    if (item.Key == "error")
                    {
                        error = JsonConvert.SerializeObject(item.Value);
                    }
                    if (item.Key == "status")
                    {
                        statusCode = (int)(HttpStatusCode)item.Value;
                    }
                    if (item.Key == "json")
                    {
                        json = item.Value;
                    }
                }

                if (json == null && error != null)
                {
                    return new BIDPoNData()
                    {
                        status = false,
                        message = error
                    };
                }
                IDictionary<string, string> map = JsonConvert.DeserializeObject<IDictionary<string, string>>(JsonConvert.SerializeObject(json));

                string dec_data = BIDECDSA.BIDECDSA.Decrypt(map["data"], sharedKey);
                ret = JsonConvert.DeserializeObject<BIDPoNData>(dec_data);

            }
            catch (Exception e)
            {
                return new BIDPoNData()
                {
                    status = false,
                    message = e.Message
                };
            }
            return ret;
        }

    }
}
