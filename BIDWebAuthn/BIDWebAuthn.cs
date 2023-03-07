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
using Newtonsoft.Json;
using BIDHelpers.BIDECDSA.Model;
using BIDHelpers.BIDTenant.Model;
using BIDHelpers.BIDWebAuthn.Model;

namespace BIDHelpers.BIDWebAuthn
{
    public class BIDWebAuthn
    {
        public static BIDAttestationOptionsResponse FetchAttestationOptions(BIDTenantInfo tenantInfo, BIDAttestationOptionsValue attestationOptionsRequest)
        {
            BIDAttestationOptionsResponse ret;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDAttestationOptionsResponse()
                    {
                        status = "false",
                        errorMessage = communityInfo.message
                    };
                }
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = licenseKey;
                headers["requestid"] = JsonConvert.SerializeObject(WTM.MakeRequestId());
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["dns"] = attestationOptionsRequest.dns,
                    ["username"] = attestationOptionsRequest.username,
                    ["displayName"] = attestationOptionsRequest.displayName,
                    ["attestation"] = attestationOptionsRequest.attestation,
                    ["authenticatorSelection"] = attestationOptionsRequest.authenticatorSelection,
                    ["communityId"] = communityInfo.community.id,
                    ["tenantId"] = communityInfo.tenant.id
                };

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.webauthn + "/u1/attestation/options", headers, JsonConvert.SerializeObject(body));

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
                    return JsonConvert.DeserializeObject<BIDAttestationOptionsResponse>(error);
                }
                var res = JsonConvert.SerializeObject(json);
                ret = JsonConvert.DeserializeObject<BIDAttestationOptionsResponse>(res);

            }
            catch (Exception e)
            {
                ret = new BIDAttestationOptionsResponse() { status = "false", errorMessage = e.Message };
            }
            return ret;
        }

        public static BIDAttestationResultData SubmitAttestationResult(BIDTenantInfo tenantInfo, BIDAttestationResultValue attestationResultRequest)
        {
            BIDAttestationResultData ret;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDAttestationResultData()
                    {
                        status = "false",
                        errorMessage = communityInfo.message
                    };
                }
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = licenseKey;
                headers["requestid"] = JsonConvert.SerializeObject(WTM.MakeRequestId());
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["rawId"] = attestationResultRequest.rawId,
                    ["response"] = attestationResultRequest.response,
                    ["authenticatorAttachment"] = attestationResultRequest.authenticatorAttachment,
                    ["getClientExtensionResults"] = attestationResultRequest.getClientExtensionResults,
                    ["id"] = attestationResultRequest.id,
                    ["type"] = attestationResultRequest.type,
                    ["dns"] = attestationResultRequest.dns,
                    ["communityId"] = communityInfo.community.id,
                    ["tenantId"] = communityInfo.tenant.id
                };

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.webauthn + "/u1/attestation/result", headers, JsonConvert.SerializeObject(body));

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
                    return JsonConvert.DeserializeObject<BIDAttestationResultData>(error);
                }

                ret = JsonConvert.DeserializeObject<BIDAttestationResultData>(JsonConvert.SerializeObject(json));


            }
            catch (Exception e)
            {
                ret = new BIDAttestationResultData() { status = "false", errorMessage = e.Message };
            }
            return ret;
        }
        public static BIDAssertionOptionResponse FetchAssertionOptions(BIDTenantInfo tenantInfo, BIDAssertionOptionValue assertionOptionRequest)
        {
            BIDAssertionOptionResponse ret;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDAssertionOptionResponse()
                    {
                        status = "false",
                        errorMessage = communityInfo.message
                    };
                }
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = licenseKey;
                headers["requestid"] = JsonConvert.SerializeObject(WTM.MakeRequestId());
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["username"] = assertionOptionRequest.username,
                    ["displayName"] = assertionOptionRequest.displayName,
                    ["dns"] = assertionOptionRequest.dns,
                    ["communityId"] = communityInfo.community.id,
                    ["tenantId"] = communityInfo.tenant.id
                };

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.webauthn + "/u1/assertion/options", headers, JsonConvert.SerializeObject(body));

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
                    return JsonConvert.DeserializeObject<BIDAssertionOptionResponse>(error);
                }

                ret = JsonConvert.DeserializeObject<BIDAssertionOptionResponse>(JsonConvert.SerializeObject(json));

            }
            catch (Exception e)
            {
                ret = new BIDAssertionOptionResponse() { status = "false", errorMessage = e.Message };
            }
            return ret;
        }
        public static BIDAssertionResultResponse SubmitAssertionResult(BIDTenantInfo tenantInfo, BIDAssertionResultValue assertionResultRequest)
        {
            BIDAssertionResultResponse ret;
            try
            {
                BIDCommunityInfo communityInfo = BIDTenant.BIDTenant.GetCommunityInfo(tenantInfo);
                if (communityInfo.community == null)
                {
                    return new BIDAssertionResultResponse()
                    {
                        status = "false",
                        errorMessage = communityInfo.message
                    };
                }
                BIDKeyPair keySet = BIDTenant.BIDTenant.GetKeySet();
                string licenseKey = tenantInfo.licenseKey;
                BIDSD sd = BIDTenant.BIDTenant.GetSD(tenantInfo);

                IDictionary<string, string> headers = WTM.DefaultHeaders();
                headers["licensekey"] = licenseKey;
                headers["requestid"] = JsonConvert.SerializeObject(WTM.MakeRequestId());
                headers["publickey"] = keySet.pKey;

                IDictionary<string, object> body = new Dictionary<string, object>
                {
                    ["rawId"] = assertionResultRequest.rawId,
                    ["dns"] = assertionResultRequest.dns,
                    ["response"] = assertionResultRequest.response,
                    ["getClientExtensionResults"] = assertionResultRequest.getClientExtensionResults,
                    ["id"] = assertionResultRequest.id,
                    ["type"] = assertionResultRequest.type,
                    ["communityId"] = communityInfo.community.id,
                    ["tenantId"] = communityInfo.tenant.id
                };

                IDictionary<string, object> response = WTM.ExecuteRequest("post", sd.webauthn + "/u1/assertion/result", headers, JsonConvert.SerializeObject(body));

                string responseStr = (string)response["response"];

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
                    return JsonConvert.DeserializeObject<BIDAssertionResultResponse>(error);
                }

                ret = JsonConvert.DeserializeObject<BIDAssertionResultResponse>(JsonConvert.SerializeObject(json));

            }
            catch (Exception e)
            {
                ret = new BIDAssertionResultResponse() { status = "false", errorMessage = e.Message };
            }
            return ret;
        }


    }
}
