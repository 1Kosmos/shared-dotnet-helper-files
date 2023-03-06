/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

using BIDHelpers.BIDECDSA.Model;
using BIDHelpers.BIDTenant.Model;
using BIDHelpers.BIDVerifyDocument.Model;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.Caching;

namespace BIDHelpers.BIDVerifyDocument
{
    public class BIDVerifyDocument
    {
        // Initializer cache
        static readonly ObjectCache cache = MemoryCache.Default;
        // create cache item policy
        static readonly CacheItemPolicy cacheItemPolicy = new CacheItemPolicy
        {
            AbsoluteExpiration = DateTimeOffset.Now.AddSeconds(10 * 60),
        };
        private static string GetPublicKey(BIDTenantInfo tenantInfo)
        {
            string ret = null;
            try
            {
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);
                string url = sd.docuverify + "/publickeys";

                string cache_key = url;
                var cache_str = cache.Get(cache_key);
                if (cache_str != null)
                {
                    IDictionary<string, string> map = JsonConvert.DeserializeObject<IDictionary<string, string>>(JsonConvert.SerializeObject(cache_str));
                    ret = map["publicKey"];
                    return ret;
                }

                //load from services
                IDictionary<string, object> response = WTM.ExecuteRequest("get", url, WTM.DefaultHeaders(), null);

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

                if (statusCode == 200)
                {
                    IDictionary<string, string> map = JsonConvert.DeserializeObject<IDictionary<string, string>>(JsonConvert.SerializeObject(json));
                    ret = map["publicKey"];
                    cache.Set(cache_key, json, cacheItemPolicy);
                }
            }
            catch
            {
                ret = null;
            }

            return ret;
        }

        public static BIDVerifyDocumentResponse VerifyDocument(BIDTenantInfo tenantInfo, string dvcId, string[] verifications, object document)
        {
            BIDVerifyDocumentResponse ret = null;
            try
            {

                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                string docVerifyPublicKey = GetPublicKey(tenantInfo);

                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, docVerifyPublicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["dvcID"] = dvcId,
                    ["verifications"] = verifications,
                    ["document"] = document
                };

                string enc_data = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(body), sharedKey);

                IDictionary<string, object> data = new Dictionary<string, object>
                {
                    ["data"] = enc_data
                };

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.docuverify + "/verify", headers, JsonConvert.SerializeObject(data));

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

                if (json != null && error == null)
                {
                    ret = JsonConvert.DeserializeObject<BIDVerifyDocumentResponse>(JsonConvert.SerializeObject(json));
                    if (ret.data != null)
                    {
                        string dec_data = BIDECDSA.BIDECDSA.Decrypt(ret.data, sharedKey);
                        ret = JsonConvert.DeserializeObject<BIDVerifyDocumentResponse>(dec_data);
                    }
                }
                if (error != null)
                {
                    ret = JsonConvert.DeserializeObject<BIDVerifyDocumentResponse>(error);
                }

            }
            catch (Exception e)
            {
                return new BIDVerifyDocumentResponse() { status = "false", message = e.Message };

            }
            return ret;
        }
        public static BIDCreateDocumentSessionResponse CreateDocumentSession(BIDTenantInfo tenantInfo, string dvcId, string documentType)
        {
            BIDCreateDocumentSessionResponse ret;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDCreateDocumentSessionResponse()
                    {
                        status = false,
                        message = communityInfo.message
                    };
                }
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                string docVerifyPublicKey = GetPublicKey(tenantInfo);

                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, docVerifyPublicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;

                string userUIDAndDid = Guid.NewGuid().ToString();

                IDictionary<string, object> sessionRequest = new Dictionary<string, object>
                {
                    ["tenantDNS"] = tenantInfo.dns,
                    ["communityName"] = communityInfo.community.name,
                    ["documentType"] = documentType,
                    ["userUID"] = userUIDAndDid,
                    ["did"] = userUIDAndDid
                };

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["dvcID"] = dvcId,
                    ["sessionRequest"] = sessionRequest
                };

                string enc_data = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(body), sharedKey);

                IDictionary<string, object> data = new Dictionary<string, object>
                {
                    ["data"] = enc_data
                };

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.docuverify + "/document_share_session/create", headers, JsonConvert.SerializeObject(data));

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

                if (error != null)
                {
                    ret = JsonConvert.DeserializeObject<BIDCreateDocumentSessionResponse>(error);
                    ret.status = false;
                    return ret;
                }

                ret = JsonConvert.DeserializeObject<BIDCreateDocumentSessionResponse>(JsonConvert.SerializeObject(json));
                ret.status = true;
            }
            catch (Exception e)
            {
                return new BIDCreateDocumentSessionResponse()
                {
                    status = false,
                    message = e.Message
                };
            }
            return ret;
        }

        public static BIDPollSessionResponse PollSessionResult(BIDTenantInfo tenantInfo, string dvcId, string sessionId)
        {
            BIDPollSessionResponse ret;
            try
            {
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                string docVerifyPublicKey = GetPublicKey(tenantInfo);

                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, docVerifyPublicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["dvcID"] = dvcId,
                    ["sessionId"] = sessionId
                };

                string enc_data = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(body), sharedKey);

                IDictionary<string, object> data = new Dictionary<string, object>
                {
                    ["data"] = enc_data
                };

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.docuverify + "/document_share_session/result", headers, JsonConvert.SerializeObject(data));

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
                    return JsonConvert.DeserializeObject<BIDPollSessionResponse>(error);
                }

                ret = JsonConvert.DeserializeObject<BIDPollSessionResponse>(JsonConvert.SerializeObject(json));

                if (ret.data != null)
                {
                    string dec_data = BIDECDSA.BIDECDSA.Decrypt(ret.data, sharedKey);
                    ret = JsonConvert.DeserializeObject<BIDPollSessionResponse>(dec_data);
                }

            }
            catch (Exception e)
            {
                ret = new BIDPollSessionResponse()
                {
                    status = false,
                    message = e.Message
                };
            }
            return ret;
        }


    }
}
