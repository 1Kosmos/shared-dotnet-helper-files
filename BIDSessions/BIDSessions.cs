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
using System.Runtime.Caching;
using BIDHelpers.BIDTenant.Model;
using BIDHelpers.BIDSessions.Model;
using BIDHelpers.BIDECDSA.Model;

namespace BIDHelpers.BIDSessions
{
    public class BIDSessions
    {
        // Initializer cache
        static readonly ObjectCache cache = MemoryCache.Default;
        // create cache item policy
        static readonly CacheItemPolicy cacheItemPolicy = new CacheItemPolicy
        {
            AbsoluteExpiration = DateTimeOffset.Now.AddSeconds(10 * 60),
        };

        private static string GetSessionPublicKey(BIDTenantInfo tenantInfo)
        {
            string ret = null;
            try
            {
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);
                if (!sd.status) return sd.message;

                string url = sd.sessions + "/publickeys";
                //check cache
                var sessionsPublicKeyCache = cache.Get(url);

                if (sessionsPublicKeyCache != null)
                {
                    return Convert.ToString(sessionsPublicKeyCache);
                }

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
                if (json != null && error == null)
                {
                    if (json.publicKey != null)
                    {
                        ret = JsonConvert.DeserializeObject(JsonConvert.SerializeObject(json.publicKey));
                        //set cache
                        cache.Set(url, ret, cacheItemPolicy);
                    }
                    if (json.message != null)
                    {
                        ret = JsonConvert.DeserializeObject(JsonConvert.SerializeObject(json.message));
                    }
                }
                else
                {
                    throw new Exception("Unable to load publicKey code " + statusCode + " with message: " + error);
                }
            }
            catch (Exception e)
            {
                ret = e.Message;
            }
            return ret;
        }

        public static BIDSession CreateNewSession(BIDTenantInfo tenantInfo, string authType, string scopes)
        {
            BIDSession ret = null;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDSession()
                    {
                        status = communityInfo.status,
                        message = communityInfo.message
                    };
                }
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                string sessionsPublicKey = GetSessionPublicKey(tenantInfo);

                IDictionary<string, object> origin = new Dictionary<string, object>
                {
                    ["tag"] = communityInfo.tenant.tenanttag,
                    ["url"] = sd.adminconsole,
                    ["communityName"] = communityInfo.community.name,
                    ["communityId"] = communityInfo.community.id,
                    ["authPage"] = "blockid://authenticate"
                };

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["origin"] = origin,
                    ["scopes"] = (scopes != null && scopes != "") ? scopes : "",
                    ["authtype"] = (authType != null && authType != "") ? authType : "none"
                };

                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, sessionsPublicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;


                IDictionary<string, object> response = WTM.ExecuteRequest("put", sd.sessions + "/session/new", headers, JsonConvert.SerializeObject(body));

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

                if (json != null && error == null)
                {
                    if (json.sessionId != null)
                    {
                        ret = JsonConvert.DeserializeObject<BIDSession>(JsonConvert.SerializeObject(json));
                    }
                    if (json.message != null)
                    {
                        ret = JsonConvert.DeserializeObject<BIDSession>(JsonConvert.SerializeObject(json));
                        ret.status = false;
                    }
                }
                else
                {
                    throw new Exception("Unable to createNewSession code " + statusCode + " with message: " + error);
                }

                ret.url = sd.sessions;

            }
            catch (Exception e)
            {
                return new BIDSession() { status = false, message = e.Message };
            }
            return ret;
        }

        public static BIDSessionResponse PollSession(BIDTenantInfo tenantInfo, string sessionId, bool fetchProfile, bool fetchDevices)
        {
            BIDSessionResponse ret;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDSessionResponse()
                    {
                        status = 400,
                        message = communityInfo.message
                    };
                }
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                string sessionsPublicKey = GetSessionPublicKey(tenantInfo);

                string sharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, sessionsPublicKey);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = BIDECDSA.BIDECDSA.Encrypt(licenseKey, sharedKey);
                headers["requestid"] = BIDECDSA.BIDECDSA.Encrypt(JsonConvert.SerializeObject(WTM.MakeRequestId()), sharedKey);
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> response = WTM.ExecuteRequest("get", sd.sessions + "/session/" + sessionId + "/response", headers, null);

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
                    return new BIDSessionResponse
                    {
                        status = statusCode,
                        message = error
                    };
                }

                ret = JsonConvert.DeserializeObject<BIDSessionResponse>(JsonConvert.SerializeObject(json));
                ret.status = statusCode;

                if (ret.data != null)
                {
                    string clientSharedKey = BIDECDSA.BIDECDSA.CreateSharedKey(keySet.prKey, ret.publicKey);
                    string dec_data = BIDECDSA.BIDECDSA.Decrypt(ret.data, clientSharedKey);
                    ret.user_data = JsonConvert.DeserializeObject<IDictionary<string, object>>(dec_data);
                }

                if (ret != null && ret.data != null && ret.user_data.ContainsKey("did") && fetchProfile)
                {
                    ret.account_data = BIDUsers.BIDUsers.FetchUserByDID(tenantInfo, (string)ret.user_data["did"], fetchDevices);
                }

            }
            catch (Exception e)
            {
                return new BIDSessionResponse()
                {
                    status = 0,
                    message = e.Message
                };
            }
            return ret;
        }

    }
}
