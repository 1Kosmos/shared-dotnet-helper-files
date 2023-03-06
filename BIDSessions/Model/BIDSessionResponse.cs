/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

using System.Collections.Generic;

namespace BIDHelpers.BIDSessions.Model
{
    public class BIDSessionResponse
    {
        public string sessionId;
        public string data;
        public string appid;
        public string ial;
        public string publicKey;
        public long createdTS;
        public string createdDate;
        public int status;
        public string message;
        public IDictionary<string, object> user_data;
        public BIDPoNData account_data;
    }
}
