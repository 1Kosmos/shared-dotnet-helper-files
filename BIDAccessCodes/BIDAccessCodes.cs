/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.Caching;
using BIDHelpers.BIDAccessCodes.Model;
using BIDHelpers.BIDECDSA.Model;
using BIDHelpers.BIDTenant.Model;
using Newtonsoft.Json;

namespace BIDHelpers.BIDAccessCodes
{
    public class BIDAccessCodes
    {
        public static BIDRequestEmailVerificationLinkResponse RequestEmailVerificationLink(BIDTenantInfo tenantInfo, string emailTo, string emailTemplateB64OrNull, string emailSubjectOrNull, string createdBy, string ttl_seconds_or_null)
        {
            BIDRequestEmailVerificationLinkResponse ret = null;
            try
            {
                if (emailTo is null || emailTo.Length == 0)
                {
                    return new BIDRequestEmailVerificationLinkResponse
                    {
                        statusCode = 400,
                        message = "emailTo is required parameter"
                    };
                }

                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDRequestEmailVerificationLinkResponse
                    {
                        statusCode = 400,
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
                headers["X-tenantTag"] = communityInfo.tenant.tenanttag;
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["createdBy"] = createdBy,
                    ["version"] = "v0",
                    ["type"] = "verification_link",
                    ["emailTo"] = emailTo
                };

                if (ttl_seconds_or_null != null)
                {
                    body["ttl_seconds"] = ttl_seconds_or_null;
                }

                if (emailTemplateB64OrNull != null)
                {
                    body["emailTemplateB64"] = emailTemplateB64OrNull;
                }

                if (emailSubjectOrNull != null)
                {
                    body["emailSubject"] = emailSubjectOrNull;
                }

                string enc_data = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(body), sharedKey);

                IDictionary<string, object> data = new Dictionary<string, object>
                {
                    ["data"] = enc_data
                };

                IDictionary<string, object> response = WTM.ExecuteRequest("put", sd.adminconsole + "/api/r2/acr/community/" + communityInfo.community.name + "/code", headers, JsonConvert.SerializeObject(data));

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

                if (statusCode != 200)
                {
                    return new BIDRequestEmailVerificationLinkResponse
                    {
                        statusCode = statusCode,
                        message = error
                    };
                }

                ret = JsonConvert.DeserializeObject<BIDRequestEmailVerificationLinkResponse>(JsonConvert.SerializeObject(json));

                ret.statusCode = statusCode;

            }
            catch (Exception e)
            {
                return new BIDRequestEmailVerificationLinkResponse { statusCode = 400, message = e.Message };
            }
            return ret;
        }

        private static BIDAccessCodeResponse FetchAccessCode(BIDTenantInfo tenantInfo, string code)
        {
            BIDAccessCodeResponse ret = new BIDAccessCodeResponse();
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                string communityPublicKey = communityInfo.community.publicKey;

                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, communityPublicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["X-tenantTag"] = communityInfo.tenant.tenanttag;
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> response = WTM.ExecuteRequest("get", sd.adminconsole + "/api/r1/acr/community/" + communityInfo.community.name + "/" + code, headers, null);

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

                if (statusCode != 200)
                {
                    return new BIDAccessCodeResponse
                    {
                        statusCode = statusCode,
                        message = error
                    };
                }

                IDictionary<string, string> map = JsonConvert.DeserializeObject<IDictionary<string, string>>(JsonConvert.SerializeObject(json));
                ret = JsonConvert.DeserializeObject<BIDAccessCodeResponse>(JsonConvert.SerializeObject(map));

                if (map != null && map["data"] != null)
                {
                    string dec_data = BIDECDSA.BIDECDSA.Decrypt(map["data"], sharedKey);
                    ret = JsonConvert.DeserializeObject<BIDAccessCodeResponse>(dec_data);

                }
                ret.statusCode = statusCode;

            }
            catch (Exception e)
            {
                return new BIDAccessCodeResponse { statusCode = 400, message = e.Message };
            }
            return ret;
        }

        public static BIDAccessCodeResponse VerifyAndRedeemEmailVerificationCode(BIDTenantInfo tenantInfo, string code)
        {
            BIDAccessCodeResponse ret;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDAccessCodeResponse
                    {
                        statusCode = 400,
                        message = communityInfo.message
                    };
                }
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                string communityPublicKey = communityInfo.community.publicKey;

                ret = FetchAccessCode(tenantInfo, code);

                if (ret.statusCode != 200)
                {
                    return ret;
                }

                if (!ret.type.Equals("verification_link"))
                {
                    ret.statusCode = 400;
                    ret.message = "Provided verification code is invalid type";
                    return ret;
                }

                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, communityPublicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["X-tenantTag"] = communityInfo.tenant.tenanttag;
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;

                string body = "{}";

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.adminconsole + "/api/r1/acr/community/" + communityInfo.community.name + "/" + code + "/redeem", headers, body);

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

                if (statusCode != 200)
                {
                    return new BIDAccessCodeResponse
                    {
                        statusCode = statusCode,
                        message = error
                    };
                }

                if (json != null && json.message != null && statusCode == 200)
                {
                    var redemCodeResponse = JsonConvert.DeserializeObject<BIDRedeemEmailVerificationCodeResponse>(JsonConvert.SerializeObject(json));
                    ret.message = redemCodeResponse.message;
                    ret.status = "redeemed";
                }

            }
            catch (Exception e)
            {
                return new BIDAccessCodeResponse { statusCode = 400, message = e.Message };
            }
            return ret;
        }


    }
}