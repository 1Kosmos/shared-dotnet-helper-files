/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

namespace BIDHelpers.BIDOTP.Model
{
    public class BIDOtpResponse
    {
        public string data;
        public string messageId;
        public string info;
        public BIDOtpValue response;
        public string message;
        public int? error_code;
    }

}
