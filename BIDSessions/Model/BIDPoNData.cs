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
    public class BIDPoNData
    {
        public string id;
        public string personId;
        public List<string> userIdList;
        public string communityId;
        public string publicKey;
        public string poi_ial;
        public string pon_ial;
        public BIDDevice device;
        public string message;
        public bool status;
    }
}
