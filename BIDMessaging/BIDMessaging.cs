/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

using BIDHelpers.BIDECDSA.Model;
using BIDHelpers.BIDMessaging.Model;
using BIDHelpers.BIDTenant.Model;
using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Net;

namespace BIDHelpers.BIDMessaging
{
    public class BIDMessaging
    {
        public static BIDSendSMSResponse SendSMS(BIDTenantInfo tenantInfo, string smsTo, string smsISDCode, string smsTemplateB64)
        {
            BIDSendSMSResponse ret;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDSendSMSResponse()
                    {
                        status = false,
                        message = communityInfo.message
                    };
                }

                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                string communityPublicKey = communityInfo.community.publicKey;

                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, communityPublicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["tenantId"] = communityInfo.community.tenantid,
                    ["communityId"] = communityInfo.community.id,
                    ["smsTo"] = smsTo,
                    ["smsISDCode"] = smsISDCode,
                    ["smsTemplateB64"] = smsTemplateB64
                };

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.adminconsole + "/api/r2/messaging/schedule", headers, JsonConvert.SerializeObject(body));

                string error = null;
                int statusCode = 0;
                dynamic json = null;
                foreach (var item in response)
                {
                    if (item.Key == "error")
                    {
                        error = Convert.ToString(item.Value);
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

                if (error != null)
                {
                    ret = JsonConvert.DeserializeObject<BIDSendSMSResponse>(error);
                    ret.status = false;
                    return ret;
                }

                ret = JsonConvert.DeserializeObject<BIDSendSMSResponse>(JsonConvert.SerializeObject(json));

            }
            catch (Exception e)
            {
                return new BIDSendSMSResponse() { message = e.Message, status = false };
            }
            return ret;
        }

    }
}
