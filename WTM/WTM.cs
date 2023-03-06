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
using System.Net.Http;
using System.Text;
using Newtonsoft.Json;

namespace BIDHelpers
{
    class WTM
    {
        private static HttpClient httpClient;

        public static IDictionary<string, object> MakeRequestId()
        {
            //gets the epoch seconds
            TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
            int secondsSinceEpoch = (int)t.TotalSeconds;
            IDictionary<string, object> ret = new Dictionary<string, object>
            {
                ["ts"] = secondsSinceEpoch,
                ["uuid"] = Guid.NewGuid().ToString(),
                ["appid"] = "fixme"
            };

            return ret;
        }

        public static IDictionary<string, string> DefaultHeaders()
        {
            return new Dictionary<string, string>(){
                { "Content-Type", "application/json" },{"charset", "utf-8" }
            };
        }
        public static IDictionary<string, object> ExecuteRequest(string method, string url, IDictionary<string, string> headers, string body)
        {
            IDictionary<string, object> ret = new Dictionary<string, object>();
            HttpResponseMessage httpResponse;
            try
            {
                httpClient = new HttpClient();
                var httpMethod = new HttpMethod(method);

                var httpRequestMessage = new HttpRequestMessage(httpMethod, url);
                // Add headers
                if (headers != null)
                {
                    foreach (var headerItem in headers)
                    {
                        httpRequestMessage.Headers.TryAddWithoutValidation(headerItem.Key, headerItem.Value);
                    }
                }

                if (httpMethod == HttpMethod.Post || httpMethod == HttpMethod.Put)
                    httpRequestMessage.Content = new StringContent(body, Encoding.UTF8, "application/json");

                httpResponse = httpClient.SendAsync(httpRequestMessage).Result;
                ret["status"] = httpResponse.StatusCode;
                var content = httpResponse.Content.ReadAsStringAsync().Result;
                if (!string.IsNullOrWhiteSpace(content) && (httpResponse.StatusCode == HttpStatusCode.OK || httpResponse.StatusCode == HttpStatusCode.Accepted || httpResponse.StatusCode == HttpStatusCode.Created))
                {
                    var api_response = JsonConvert.DeserializeObject<dynamic>(content);
                    ret["json"] = api_response;
                }
                else
                {
                    ret["error"] = content;
                }
            }
            catch (Exception ex)
            {
                ret["status"] = HttpStatusCode.BadRequest;
                ret["error"] = ex.ToString();
            }

            return ret;

        }
    }
}
