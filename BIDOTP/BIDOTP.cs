/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Net;
using BIDHelpers.BIDTenant.Model;
using BIDHelpers.BIDECDSA.Model;
using BIDHelpers.BIDOTP.Model;

namespace BIDHelpers.BIDOTP
{

    public class BIDOTP
    {
        public static BIDOtpResponse RequestOTP(BIDTenantInfo tenantInfo, string userName, string emailOrNull, string phoneOrNull, string isdCodeOrNull)
        {
            BIDOtpResponse ret = null;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDOtpResponse()
                    {
                        error_code = 400,
                        message = communityInfo.message
                    };
                }
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["userId"] = userName,
                    ["tenantId"] = communityInfo.tenant.id,
                    ["communityId"] = communityInfo.community.id
                };


                if (emailOrNull != null)
                {
                    body["emailTo"] = emailOrNull;
                }

                if (phoneOrNull != null && isdCodeOrNull != null)
                {
                    body["smsTo"] = phoneOrNull;
                    body["smsISDCode"] = isdCodeOrNull;
                }

                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, communityInfo.community.publicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.adminconsole + "/api/r2/otp/generate", headers, JsonConvert.SerializeObject(body));

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


                if (statusCode == Convert.ToInt32(HttpStatusCode.OK) || statusCode == Convert.ToInt32(HttpStatusCode.Accepted))
                {
                    ret = JsonConvert.DeserializeObject<BIDOtpResponse>(JsonConvert.SerializeObject(json));
                }

                if (ret != null && ret.data != null)
                {
                    string dataStr = BIDECDSA.BIDECDSA.Decrypt(ret.data, sharedKey);

                    ret.response = JsonConvert.DeserializeObject<BIDOtpValue>(JsonConvert.SerializeObject(dataStr));
                }

                if (error != null)
                {
                    return JsonConvert.DeserializeObject<BIDOtpResponse>(error);
                }

            }
            catch (Exception e)
            {
                return new BIDOtpResponse() { error_code = 500, message = e.Message };
            }

            return ret;
        }

        public static BIDOtpVerifyResult VerifyOTP(BIDTenantInfo tenantInfo, string userName, string otpCode)
        {
            BIDOtpVerifyResult ret;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDOtpVerifyResult()
                    {
                        error_code = 400,
                        message = communityInfo.message
                    };
                }
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["userId"] = userName,
                    ["code"] = otpCode,
                    ["tenantId"] = communityInfo.tenant.id,
                    ["communityId"] = communityInfo.community.id
                };


                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, communityInfo.community.publicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.adminconsole + "/api/r2/otp/verify", headers, JsonConvert.SerializeObject(body));

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
                    return JsonConvert.DeserializeObject<BIDOtpVerifyResult>(error);
                }

                ret = JsonConvert.DeserializeObject<BIDOtpVerifyResult>(JsonConvert.SerializeObject(json));
            }
            catch (Exception e)
            {
                return new BIDOtpVerifyResult() { error_code = 500, message = e.Message };
            }

            return ret;

        }


    }
}
