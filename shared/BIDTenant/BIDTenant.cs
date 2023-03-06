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
using System.Runtime.Caching;
using BIDHelpers.BIDTenant.Model;
using System.Net;
using BIDHelpers.BIDECDSA.Model;

namespace BIDHelpers.BIDTenant
{

    public class BIDTenant
    {
        // Initializer cache
        static readonly ObjectCache cache = MemoryCache.Default;
        // create cache item policy
        static readonly CacheItemPolicy cacheItemPolicy = new CacheItemPolicy
        {
            AbsoluteExpiration = DateTimeOffset.Now.AddSeconds(10 * 60),

        };

        private static BIDKeyPair keySet;
        public static BIDCommunityInfo GetCommunityInfo(BIDTenantInfo tenantInfo)
        {
            BIDCommunityInfo communityInfo = null;
            try
            {
                IDictionary<string, object> body = new Dictionary<string, object>();
                string communityCacheKey = "communityCache_" + tenantInfo.dns;

                if (tenantInfo.tenantId != null)
                {
                    body["tenantId"] = tenantInfo.tenantId;
                    communityCacheKey = $"{communityCacheKey}_{tenantInfo.tenantId}";
                }
                else
                {
                    body["dns"] = tenantInfo.dns;
                }

                if (tenantInfo.communityId != null)
                {
                    body["communityId"] = tenantInfo.communityId;
                    communityCacheKey = $"{communityCacheKey}_{tenantInfo.communityId}";
                }
                else
                {
                    body["communityName"] = tenantInfo.communityName;
                    communityCacheKey = $"{communityCacheKey}_{tenantInfo.communityName}";
                }

                //check cache
                var communityInfoCache = cache.Get(communityCacheKey);

                if (communityInfoCache != null)
                {
                    return JsonConvert.DeserializeObject<BIDCommunityInfo>(JsonConvert.SerializeObject(communityInfoCache));
                }

                //no cache found.. let's get live data.
                var url = "https://" + tenantInfo.dns + "/api/r1/system/community_info/fetch";
                var response = WTM.ExecuteRequest("post", url, null, JsonConvert.SerializeObject(body));

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
                    if (json.tenant != null && json.community != null)
                    {
                        communityInfo = JsonConvert.DeserializeObject<BIDCommunityInfo>(JsonConvert.SerializeObject(json));
                        //Store in cache on positive response
                        cache.Set(communityCacheKey, communityInfo, cacheItemPolicy);
                    }
                    if (json.message != null)
                    {
                        communityInfo = JsonConvert.DeserializeObject<BIDCommunityInfo>(JsonConvert.SerializeObject(json));
                        communityInfo.status = false;
                    }
                }
                else
                {
                    throw new Exception("Unable to load communityInfo code " + statusCode + " with message: " + error);
                }
            }
            catch (Exception e)
            {
                communityInfo = new BIDCommunityInfo()
                {
                    status = false,
                    message = e.Message
                };
            }
            return communityInfo;
        }

        public static BIDSD GetSD(BIDTenantInfo tenantInfo)
        {
            BIDSD sd;
            try
            {
                IDictionary<string, object> body = new Dictionary<string, object>();
                string cache_key = "sdCache_" + tenantInfo.dns;

                if (tenantInfo.tenantId != null)
                {
                    cache_key = cache_key + "_" + tenantInfo.tenantId;
                }

                if (tenantInfo.communityId != null)
                {
                    cache_key = cache_key + "_" + tenantInfo.communityId;
                }
                else
                {
                    cache_key = (tenantInfo.communityName != null) ? cache_key + "_" + tenantInfo.communityName : cache_key;
                }

                //check cache, if yes.
                var cache_str = cache.Get(cache_key);
                if (cache_str != null)
                {
                    return JsonConvert.DeserializeObject<BIDSD>(JsonConvert.SerializeObject(cache_str));
                }

                //no cache found.. let's get live data.
                string sdUrl = "https://" + tenantInfo.dns + "/caas/sd";
                var response = WTM.ExecuteRequest("get", sdUrl, WTM.DefaultHeaders(), null);

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

                if (statusCode == 200 && json != null && error == null)
                {
                    sd = JsonConvert.DeserializeObject<BIDSD>(JsonConvert.SerializeObject(json));
                    cache.Set(cache_key, sd, cacheItemPolicy);
                }
                else
                {
                    throw new Exception("Unable to load sd code " + statusCode + " with message: " + error);
                }
            }
            catch (Exception e)
            {
                sd = new BIDSD()
                {
                    status = false,
                    message = e.Message
                };
            }
            return sd;
        }

        public static BIDKeyPair GetKeySet()
        {
            if (keySet == null)
            {
                keySet = BIDECDSA.BIDECDSA.GenerateKeyPair();
            }
            return keySet;
        }

        public static void SetKeySet(BIDKeyPair keyPairKeySet)
        {
            keySet = keyPairKeySet;
        }
    }
}